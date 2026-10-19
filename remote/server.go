package remote

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/openabstractions/abstraction-identity/listen"
)

// Handler receives one complete authenticated frame. It applies capability and
// method authorization before effects. Nil reply means one-way completion.
// Honor ctx for bounded waits; accepted work uses its service-owned lifetime.
type Handler func(context.Context, Peer, []byte) ([]byte, error)

// Server owns accepted connections and uses a caller-supplied TCP listener.
// TLS credentials, trusted client roots and handler policy are explicitly supplied
// by the host. Zero limits select the documented bounded defaults.
type Server struct {
	TLS     *tls.Config
	Handler Handler
	// Admit checks the verified leaf SPKI against the owner's live pin policy.
	// It runs during the TLS handshake, before the request frame is read.
	// New hosts use AdmitContext to retain the handshake's caller deadline.
	Admit func(Peer) error
	// AdmitContext checks the same live pin policy within this connection's
	// handshake context. When both callbacks are set, both must admit the peer.
	AdmitContext func(context.Context, Peer) error
	// ClientRoots, when non-nil, overrides only ClientCAs for each connection.
	// Return an immutable snapshot and honor the remaining handshake context.
	// The server clones the pool. Nil/error/cancellation refuses; fixed roots
	// are used only when this callback is nil. TLS verification remains mandatory.
	ClientRoots func(context.Context) (*x509.CertPool, error)
	Timeout     time.Duration
	MaxFrame    uint32
	// MaxRequestFrame separates the request bound from MaxFrame's reply bound.
	// Zero preserves the legacy MaxFrame bound in both directions.
	MaxRequestFrame uint32
	MaxConnections  int
	// HandshakeTimeout is capped by Timeout's remaining end-to-end budget.
	HandshakeTimeout time.Duration
	// MaxSourceConnections counts pre-authentication TCP connections per IP.
	MaxSourceConnections int
	// Peer limits use the verified SPKI after the live Admit callback succeeds.
	MaxPeerCalls          int
	PeerRequestsPerSecond int
	PeerBurst             int
}

// Validate checks configuration without opening a listener or evaluating a peer.
// The live Admit policy is evaluated again during each TLS handshake.
func (s Server) Validate() error {
	if s.TLS == nil || s.TLS.ClientCAs == nil || s.TLS.GetConfigForClient != nil ||
		(len(s.TLS.Certificates) == 0 && s.TLS.GetCertificate == nil) || s.Handler == nil || (s.Admit == nil && s.AdmitContext == nil) ||
		s.Timeout < 0 || s.MaxConnections < 0 || s.HandshakeTimeout < 0 ||
		s.MaxSourceConnections < 0 || s.MaxPeerCalls < 0 || s.PeerRequestsPerSecond < 0 || s.PeerBurst < 0 {
		return fmt.Errorf("%w: fixed server identity, client roots, handler and valid limits required", ErrTrust)
	}
	if s.TLS.MaxVersion != 0 && s.TLS.MaxVersion < tls.VersionTLS13 {
		return fmt.Errorf("%w: TLS 1.3 required", ErrTrust)
	}
	return nil
}

// Serve closes the listener on return and joins every admitted handler. Handlers
// must honor their context. Per-connection errors close that connection; they
// never retry application requests or stop unrelated connections.
func (s Server) Serve(parent context.Context, listener net.Listener) error {
	if listener == nil {
		return errors.New("remote: listener required")
	}
	defer listener.Close()
	if err := s.Validate(); err != nil {
		return err
	}
	c := s.TLS.Clone()
	c.ClientCAs = s.TLS.ClientCAs.Clone()
	c.ClientAuth = tls.RequireAndVerifyClientCert
	c.MinVersion = tls.VersionTLS13
	c.NextProtos = []string{Protocol}
	c.SessionTicketsDisabled = true
	if s.Admit != nil {
		verifyAdmission(c, s.Admit)
	}
	if s.Timeout == 0 {
		s.Timeout = listen.DefaultFrameTimeout
	}
	if s.MaxConnections == 0 {
		s.MaxConnections = 64
	}
	if s.HandshakeTimeout == 0 {
		s.HandshakeTimeout = 5 * time.Second
	}
	budgets := newServerBudgets(s)
	ctx, cancel := context.WithCancel(parent)
	stop := context.AfterFunc(ctx, func() { listener.Close() })
	var workers sync.WaitGroup
	defer func() { cancel(); stop(); workers.Wait() }()
	capacity := make(chan struct{}, s.MaxConnections)
	for {
		raw, err := listener.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return err
		}
		select {
		case capacity <- struct{}{}:
			releaseSource, ok := budgets.source(raw.RemoteAddr())
			if !ok {
				<-capacity
				raw.Close()
				continue
			}
			accepted := time.Now()
			workers.Add(1)
			go func() {
				defer workers.Done()
				defer func() { <-capacity }()
				s.serveCall(ctx, raw, c, budgets, releaseSource, accepted)
			}()
		default:
			raw.Close()
		}
	}
}

func (s Server) serveCall(parent context.Context, raw net.Conn, config *tls.Config, budgets *serverBudgets, releaseSource func(), accepted time.Time) {
	ctx, cancel := context.WithDeadline(parent, accepted.Add(s.Timeout))
	defer cancel()
	defer releaseSource()
	defer raw.Close()
	handshake, finishHandshake := context.WithDeadline(ctx, accepted.Add(s.HandshakeTimeout))
	defer finishHandshake()
	if s.AdmitContext != nil {
		selected := config.Clone()
		verifyAdmission(selected, func(peer Peer) error { return s.AdmitContext(handshake, peer) })
		config = selected
	}
	if s.ClientRoots != nil {
		roots, err := s.ClientRoots(handshake)
		if err != nil || roots == nil || handshake.Err() != nil {
			return
		}
		selected := config.Clone()
		selected.ClientCAs = roots.Clone()
		config = selected
	}
	conn := tls.Server(raw, config)
	stop := context.AfterFunc(ctx, func() { raw.Close() })
	defer func() { cancel(); stop(); raw.Close(); conn.Close() }()
	deadline, _ := ctx.Deadline()
	handshakeDeadline, _ := handshake.Deadline()
	if conn.SetDeadline(handshakeDeadline) != nil || conn.HandshakeContext(handshake) != nil {
		finishHandshake()
		return
	}
	finishHandshake()
	releaseSource()
	if conn.SetDeadline(deadline) != nil {
		return
	}
	caller, err := peer(conn.ConnectionState())
	if err != nil {
		return
	}
	releasePeer, ok := budgets.peer(caller.Key)
	if !ok {
		return
	}
	defer releasePeer()
	requestLimit := s.MaxRequestFrame
	if requestLimit == 0 {
		requestLimit = s.MaxFrame
	}
	frame, err := listen.ReadFrameFrom(conn, requestLimit)
	if err != nil {
		return
	}
	// TLS permits one reader concurrently with a writer. Detect caller departure
	// during a long handler without consuming any application response bytes.
	ended := make(chan struct{})
	go func() {
		var extra [1]byte
		conn.Read(extra[:])
		close(ended)
		cancel()
	}()
	defer func() { raw.Close(); <-ended }()
	reply, err := s.Handler(ctx, caller, frame)
	if err != nil || ctx.Err() != nil || reply == nil {
		return
	}
	if listen.WriteFrameTo(conn, reply, s.MaxFrame) != nil {
		return
	}
	// The reader observes the client closing after it consumes the response.
	<-ended
}
