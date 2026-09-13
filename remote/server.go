package remote

import (
	"context"
	"crypto/tls"
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
// by the host. Zero limits select five seconds, 1 MiB and 64 concurrent calls.
type Server struct {
	TLS            *tls.Config
	Handler        Handler
	Timeout        time.Duration
	MaxFrame       uint32
	MaxConnections int
}

// Serve closes the listener on return and joins every admitted handler. Handlers
// must honor their context. Per-connection errors close that connection; they
// never retry application requests or stop unrelated connections.
func (s Server) Serve(parent context.Context, listener net.Listener) error {
	if listener == nil {
		return errors.New("remote: listener required")
	}
	defer listener.Close()
	if s.TLS == nil || s.TLS.ClientCAs == nil || s.TLS.GetConfigForClient != nil ||
		(len(s.TLS.Certificates) == 0 && s.TLS.GetCertificate == nil) || s.Handler == nil ||
		s.Timeout < 0 || s.MaxConnections < 0 {
		return fmt.Errorf("%w: fixed server identity, client roots, handler and valid limits required", ErrTrust)
	}
	c := s.TLS.Clone()
	c.ClientCAs = s.TLS.ClientCAs.Clone()
	c.ClientAuth = tls.RequireAndVerifyClientCert
	c.MinVersion = tls.VersionTLS13
	c.NextProtos = []string{Protocol}
	c.SessionTicketsDisabled = true
	if c.MaxVersion != 0 && c.MaxVersion < c.MinVersion {
		return fmt.Errorf("%w: TLS 1.3 required", ErrTrust)
	}
	if s.Timeout == 0 {
		s.Timeout = listen.DefaultFrameTimeout
	}
	if s.MaxConnections == 0 {
		s.MaxConnections = 64
	}
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
			workers.Add(1)
			go func() {
				defer workers.Done()
				defer func() { <-capacity }()
				s.serveCall(ctx, raw, c)
			}()
		default:
			raw.Close()
		}
	}
}

func (s Server) serveCall(parent context.Context, raw net.Conn, config *tls.Config) {
	ctx, cancel := context.WithTimeout(parent, s.Timeout)
	conn := tls.Server(raw, config)
	stop := context.AfterFunc(ctx, func() { raw.Close() })
	defer func() { cancel(); stop(); conn.Close() }()
	deadline, _ := ctx.Deadline()
	if conn.SetDeadline(deadline) != nil || conn.HandshakeContext(ctx) != nil {
		return
	}
	caller, err := peer(conn.ConnectionState())
	if err != nil {
		return
	}
	frame, err := listen.ReadFrameFrom(conn, s.MaxFrame)
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
