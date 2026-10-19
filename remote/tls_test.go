package remote

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"net"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/openabstractions/abstraction-identity/listen"
)

func credentials(t *testing.T) (*tls.Config, *tls.Config) {
	server, client, _ := credentialsWithRenewal(t)
	return server, client
}

func credentialsWithRenewal(t *testing.T) (*tls.Config, *tls.Config, tls.Certificate) {
	t.Helper()
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "isolated test CA"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true,
		BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, ca, ca, pub, key)
	if err != nil {
		t.Fatal(err)
	}
	ca, err = x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	makeCert := func(id int64, usage x509.ExtKeyUsage) tls.Certificate {
		p, k, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		c := &x509.Certificate{SerialNumber: big.NewInt(id), DNSNames: []string{"runtime.test"},
			NotBefore: ca.NotBefore, NotAfter: ca.NotAfter, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{usage}}
		b, err := x509.CreateCertificate(rand.Reader, c, ca, p, key)
		if err != nil {
			t.Fatal(err)
		}
		return tls.Certificate{Certificate: [][]byte{b}, PrivateKey: k}
	}
	server := makeCert(2, x509.ExtKeyUsageServerAuth)
	renewed := server
	template := &x509.Certificate{SerialNumber: big.NewInt(4), DNSNames: []string{"runtime.test"}, NotBefore: ca.NotBefore, NotAfter: ca.NotAfter, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	renewedDER, err := x509.CreateCertificate(rand.Reader, template, ca, server.PrivateKey.(ed25519.PrivateKey).Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	renewed.Certificate = [][]byte{renewedDER}
	return &tls.Config{Certificates: []tls.Certificate{server}, ClientCAs: roots},
		&tls.Config{Certificates: []tls.Certificate{makeCert(3, x509.ExtKeyUsageClientAuth)}, RootCAs: roots, ServerName: "runtime.test"}, renewed
}

func TestLiveCertificateRenewalKeepsLeafPin(t *testing.T) {
	server, client, renewed := credentialsWithRenewal(t)
	pin := remoteTestPin(t, server)
	var current atomic.Pointer[tls.Certificate]
	current.Store(&server.Certificates[0])
	server.GetCertificate = func(*tls.ClientHelloInfo) (*tls.Certificate, error) { return current.Load(), nil }
	server.Certificates = nil
	address := start(t, server, remoteTestPin(t, client), func(_ context.Context, _ Peer, frame []byte) ([]byte, error) { return frame, nil })
	c, err := Client(address, client, time.Second, 0, pin)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.ExchangeFrame([]byte("original")); err != nil {
		t.Fatal(err)
	}
	current.Store(&renewed)
	if got, err := c.ExchangeFrame([]byte("renewed")); err != nil || string(got) != "renewed" {
		t.Fatalf("same-key renewal: %q %v", got, err)
	}
}

func TestExistingPeerCertificateVerifiersRemainEffective(t *testing.T) {
	for _, receivingServer := range []bool{false, true} {
		t.Run(map[bool]string{false: "client", true: "server"}[receivingServer], func(t *testing.T) {
			server, client := credentials(t)
			var reached atomic.Bool
			refusal := errors.New("existing peer certificate verifier")
			verify := func([][]byte, [][]*x509.Certificate) error { reached.Store(true); return refusal }
			if receivingServer {
				server.VerifyPeerCertificate = verify
			} else {
				client.VerifyPeerCertificate = verify
			}
			address := start(t, server, remoteTestPin(t, client), func(context.Context, Peer, []byte) ([]byte, error) {
				t.Error("frame after verifier refusal")
				return nil, nil
			})
			c, err := Client(address, client, time.Second, 0, remoteTestPin(t, server))
			if err != nil {
				t.Fatal(err)
			}
			if _, err := c.ExchangeFrame(nil); err == nil {
				t.Fatal("verifier refusal lost")
			}
			if !reached.Load() {
				t.Fatal("existing verifier not reached")
			}
		})
	}
}

func TestSameRootNamedServerCannotReplacePinnedLeaf(t *testing.T) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	root := &x509.Certificate{SerialNumber: big.NewInt(100), IsCA: true, BasicConstraintsValid: true,
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, root, root, public, private)
	if err != nil {
		t.Fatal(err)
	}
	root, err = x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(root)
	leaf := func(serial int64, usage x509.ExtKeyUsage) tls.Certificate {
		t.Helper()
		pub, key, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		certificate := &x509.Certificate{SerialNumber: big.NewInt(serial), DNSNames: []string{"runtime.test"},
			Subject: pkix.Name{CommonName: "same display name"}, NotBefore: root.NotBefore, NotAfter: root.NotAfter,
			KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{usage}}
		b, err := x509.CreateCertificate(rand.Reader, certificate, root, pub, private)
		if err != nil {
			t.Fatal(err)
		}
		return tls.Certificate{Certificate: [][]byte{b}, PrivateKey: key}
	}
	expected, impostor := leaf(101, x509.ExtKeyUsageServerAuth), leaf(102, x509.ExtKeyUsageServerAuth)
	client := &tls.Config{Certificates: []tls.Certificate{leaf(103, x509.ExtKeyUsageClientAuth)}, RootCAs: roots, ServerName: "runtime.test"}
	var calls atomic.Int32
	handler := func(_ context.Context, _ Peer, frame []byte) ([]byte, error) { calls.Add(1); return frame, nil }
	pin := remoteTestPin(t, &tls.Config{Certificates: []tls.Certificate{expected}})
	var admitted atomic.Int32
	admit := func(peer Peer) error { admitted.Add(1); return pin(peer) }
	legitimate := start(t, &tls.Config{Certificates: []tls.Certificate{expected}, ClientCAs: roots}, remoteTestPin(t, client), handler)
	transport, err := Client(legitimate, client, time.Second, 0, admit)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := transport.ExchangeFrame([]byte("positive")); err != nil {
		t.Fatal(err)
	}
	other := start(t, &tls.Config{Certificates: []tls.Certificate{impostor}, ClientCAs: roots}, remoteTestPin(t, client), handler)
	transport, err = Client(other, client, time.Second, 0, admit)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := transport.ExchangeFrame([]byte("must not reach handler")); !errors.Is(err, ErrTrust) {
		t.Fatalf("same-root, same-name replacement: %v", err)
	}
	// Reaching admission proves normal TLS chain/name/usage validation passed.
	if admitted.Load() != 2 || calls.Load() != 1 {
		t.Fatalf("admissions=%d frames=%d", admitted.Load(), calls.Load())
	}
}

func TestExistingServerConnectionVerifierRejectsBeforeFrame(t *testing.T) {
	server, client := credentials(t)
	var verified, frames, pins atomic.Int32
	refusal := errors.New("existing server connection verifier")
	server.VerifyConnection = func(state tls.ConnectionState) error {
		if len(state.VerifiedChains) == 0 || state.NegotiatedProtocol != Protocol {
			t.Error("ordinary TLS verification missing")
		}
		verified.Add(1)
		return refusal
	}
	pin := remoteTestPin(t, client)
	address := start(t, server, func(peer Peer) error { pins.Add(1); return pin(peer) },
		func(context.Context, Peer, []byte) ([]byte, error) { frames.Add(1); return nil, nil })
	transport, err := Client(address, client, time.Second, 0, remoteTestPin(t, server))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := transport.ExchangeFrame([]byte("must not dispatch")); err == nil {
		t.Fatal("server verifier refusal lost")
	}
	if verified.Load() != 1 || pins.Load() != 0 || frames.Load() != 0 {
		t.Fatalf("existing verifier=%d later pin=%d frames=%d", verified.Load(), pins.Load(), frames.Load())
	}
}

func start(t *testing.T, config *tls.Config, admit func(Peer) error, handler Handler) string {
	t.Helper()
	return startServer(t, Server{TLS: config, Admit: admit, Handler: handler, Timeout: 2 * time.Second})
}

func startServer(t *testing.T, server Server) string {
	t.Helper()
	if err := server.Validate(); err != nil {
		t.Fatal(err)
	}
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- server.Serve(ctx, l)
	}()
	t.Cleanup(func() {
		cancel()
		select {
		case err := <-done:
			if !errors.Is(err, context.Canceled) {
				t.Errorf("Serve: %v", err)
			}
		case <-time.After(3 * time.Second):
			t.Error("server did not drain")
		}
	})
	return l.Addr().String()
}

func TestServerValidateHasNoPeerEffects(t *testing.T) {
	config, _ := credentials(t)
	server := Server{TLS: config,
		Admit:   func(Peer) error { t.Fatal("validation evaluated a peer"); return nil },
		Handler: func(context.Context, Peer, []byte) ([]byte, error) { t.Fatal("validation dispatched"); return nil, nil }}
	if err := server.Validate(); err != nil {
		t.Fatal(err)
	}
	for _, change := range []func(*Server){
		func(s *Server) { s.TLS = nil },
		func(s *Server) { s.TLS = s.TLS.Clone(); s.TLS.ClientCAs = nil },
		func(s *Server) { s.TLS = s.TLS.Clone(); s.TLS.MaxVersion = tls.VersionTLS12 },
		func(s *Server) { s.Admit = nil },
		func(s *Server) { s.Handler = nil },
		func(s *Server) { s.Timeout = -1 },
		func(s *Server) { s.MaxConnections = -1 },
		func(s *Server) { s.HandshakeTimeout = -1 },
		func(s *Server) { s.MaxSourceConnections = -1 },
		func(s *Server) { s.MaxPeerCalls = -1 },
		func(s *Server) { s.PeerRequestsPerSecond = -1 },
		func(s *Server) { s.PeerBurst = -1 },
	} {
		invalid := server
		change(&invalid)
		if err := invalid.Validate(); !errors.Is(err, ErrTrust) {
			t.Fatalf("invalid configuration accepted: %v", err)
		}
	}
}

func TestSilentConnectionsCannotStarvePairedPeer(t *testing.T) {
	// Some systems configure only 127.0.0.1 on loopback. This control needs
	// two actual TCP source addresses and never configures a host alias.
	probe, err := net.Listen("tcp4", "127.0.0.2:0")
	if errors.Is(err, syscall.EADDRNOTAVAIL) {
		t.Skip("second loopback source 127.0.0.2 is unavailable")
	}
	if err != nil {
		t.Fatal(err)
	}
	if err := probe.Close(); err != nil {
		t.Fatal(err)
	}
	server, client := credentials(t)
	address := startServer(t, Server{TLS: server, Admit: remoteTestPin(t, client),
		Timeout: 2 * time.Second, HandshakeTimeout: time.Second, MaxConnections: 2, MaxSourceConnections: 1,
		Handler: func(_ context.Context, _ Peer, frame []byte) ([]byte, error) { return frame, nil }})
	silent, err := net.Dial("tcp", address)
	if err != nil {
		t.Fatal(err)
	}
	defer silent.Close()
	// Accept order ensures the silent connection has claimed its source slot.
	excess, err := net.Dial("tcp", address)
	if err != nil {
		t.Fatal(err)
	}
	defer excess.Close()
	excess.SetReadDeadline(time.Now().Add(time.Second))
	var one [1]byte
	if _, err := excess.Read(one[:]); err == nil {
		t.Fatal("excess source connection retained")
	} else if e, ok := err.(net.Error); ok && e.Timeout() {
		t.Fatal("excess source consumed a global slot")
	}
	config := client.Clone()
	config.NextProtos = []string{Protocol}
	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: time.Second,
		LocalAddr: &net.TCPAddr{IP: net.ParseIP("127.0.0.2")}}, "tcp", address, config)
	if err != nil {
		t.Fatalf("another permitted source could not progress: %v", err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(time.Second))
	if err := listen.WriteFrameTo(conn, []byte("permitted"), 0); err != nil {
		t.Fatal(err)
	}
	frame, err := listen.ReadFrameFrom(conn, 0)
	if err != nil || string(frame) != "permitted" {
		t.Fatalf("other source: %q %v", frame, err)
	}
}

func TestHandshakeBudgetExpiresAndReleasesSource(t *testing.T) {
	server, client := credentials(t)
	var calls atomic.Int32
	address := startServer(t, Server{TLS: server, Admit: remoteTestPin(t, client), Timeout: 2 * time.Second,
		HandshakeTimeout: 50 * time.Millisecond, MaxSourceConnections: 1,
		Handler: func(_ context.Context, _ Peer, frame []byte) ([]byte, error) { calls.Add(1); return frame, nil }})
	silent, err := net.Dial("tcp", address)
	if err != nil {
		t.Fatal(err)
	}
	defer silent.Close()
	silent.SetReadDeadline(time.Now().Add(time.Second))
	var one [1]byte
	if _, err := silent.Read(one[:]); err == nil {
		t.Fatal("silent handshake retained")
	} else if e, ok := err.(net.Error); ok && e.Timeout() {
		t.Fatal("handshake used the longer total budget")
	}
	if calls.Load() != 0 {
		t.Fatal("unauthenticated handler")
	}
	c, err := Client(address, client, time.Second, 0, remoteTestPin(t, server))
	if err != nil {
		t.Fatal(err)
	}
	if got, err := c.ExchangeFrame([]byte("after expiry")); err != nil || string(got) != "after expiry" {
		t.Fatalf("source did not recover: %q %v", got, err)
	}
}

func TestPerPeerConcurrencyCapBeforeDispatch(t *testing.T) {
	server, client := credentials(t)
	entered, release := make(chan struct{}), make(chan struct{})
	var calls atomic.Int32
	address := startServer(t, Server{TLS: server, Admit: remoteTestPin(t, client), MaxPeerCalls: 1,
		Handler: func(ctx context.Context, _ Peer, frame []byte) ([]byte, error) {
			if calls.Add(1) == 1 {
				close(entered)
			}
			select {
			case <-release:
				return frame, nil
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		}})
	c, err := Client(address, client, 2*time.Second, 0, remoteTestPin(t, server))
	if err != nil {
		t.Fatal(err)
	}
	first := make(chan error, 1)
	go func() { _, err := c.ExchangeFrame([]byte("held")); first <- err }()
	select {
	case <-entered:
	case <-time.After(time.Second):
		close(release)
		t.Fatal("first handler absent")
	}
	_, refused := c.ExchangeFrame([]byte("must not dispatch"))
	close(release)
	if err := <-first; err != nil {
		t.Fatal(err)
	}
	if refused == nil || calls.Load() != 1 {
		t.Fatalf("peer cap: err=%v calls=%d", refused, calls.Load())
	}
}

func TestHandshakeDeadlineRestoresRemainingTotalBudget(t *testing.T) {
	server, client := credentials(t)
	address := startServer(t, Server{TLS: server, Admit: remoteTestPin(t, client),
		Timeout: 2 * time.Second, HandshakeTimeout: 50 * time.Millisecond,
		Handler: func(ctx context.Context, _ Peer, frame []byte) ([]byte, error) {
			deadline, ok := ctx.Deadline()
			if !ok || time.Until(deadline) > 2*time.Second {
				t.Error("total budget extended")
			}
			select {
			case <-time.After(100 * time.Millisecond):
				return frame, nil
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		}})
	c, err := Client(address, client, time.Second, 0, remoteTestPin(t, server))
	if err != nil {
		t.Fatal(err)
	}
	if got, err := c.ExchangeFrame([]byte("remaining total")); err != nil || string(got) != "remaining total" {
		t.Fatalf("handshake deadline retained after TLS: %q %v", got, err)
	}
}

func TestServerSeparateRequestAndReplyBounds(t *testing.T) {
	for _, test := range []struct {
		name                     string
		requestLimit, replyLimit uint32
		request, reply           int
		accepted                 bool
	}{
		{"split reply", 1024, 4096, 16, 2048, true},
		{"split request refused", 1024, 4096, 2048, 16, false},
		{"reply refused", 4096, 1024, 16, 2048, false},
		{"legacy request", 0, 1024, 2048, 16, false},
		{"legacy reply", 0, 4096, 2048, 2048, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			server, client := credentials(t)
			var calls atomic.Int32
			address := startServer(t, Server{TLS: server, Admit: remoteTestPin(t, client), Timeout: time.Second,
				MaxRequestFrame: test.requestLimit, MaxFrame: test.replyLimit,
				Handler: func(context.Context, Peer, []byte) ([]byte, error) {
					calls.Add(1)
					return bytes.Repeat([]byte{7}, test.reply), nil
				}})
			transport, err := Client(address, client, time.Second, 8192, remoteTestPin(t, server))
			if err != nil {
				t.Fatal(err)
			}
			reply, err := transport.ExchangeFrame(bytes.Repeat([]byte{3}, test.request))
			if test.accepted {
				if err != nil || len(reply) != test.reply {
					t.Fatalf("reply=%d err=%v", len(reply), err)
				}
			} else if err == nil {
				t.Fatal("oversized frame accepted")
			}
			limit := test.requestLimit
			if limit == 0 {
				limit = test.replyLimit
			}
			if uint32(test.request) > limit && calls.Load() != 0 {
				t.Fatal("oversized request dispatched")
			}
		})
	}
}

func TestMutualTrustBeforeHandlerAndSharedFrames(t *testing.T) {
	server, client := credentials(t)
	var calls atomic.Int32
	address := start(t, server, remoteTestPin(t, client), func(ctx context.Context, p Peer, frame []byte) ([]byte, error) {
		calls.Add(1)
		if p.Certificate.SerialNumber.Int64() != 3 || p.Key == [32]byte{} {
			t.Error("missing authenticated certificate")
		}
		return frame, nil
	})
	c, err := Client(address, client, time.Second, 1024*1024, remoteTestPin(t, server))
	if err != nil {
		t.Fatal(err)
	}
	want := bytes.Repeat([]byte{0, 255, 13, 10, 1}, 30000)
	got, err := c.ExchangeFrame(want)
	if err != nil || !bytes.Equal(got, want) {
		t.Fatalf("roundtrip: %d %v", len(got), err)
	}
	for _, mutate := range []func(*tls.Config){
		func(c *tls.Config) { c.ServerName = "wrong.test" },
		func(c *tls.Config) { c.RootCAs = x509.NewCertPool() },
		func(c *tls.Config) { _, bad := credentials(t); c.Certificates = bad.Certificates },
	} {
		bad := client.Clone()
		mutate(bad)
		b, err := Client(address, bad, time.Second, 0, remoteTestPin(t, server))
		if err != nil {
			t.Fatal(err)
		}
		if _, err = b.ExchangeFrame([]byte("must not reach handler")); err == nil {
			t.Fatal("untrusted peer accepted")
		}
	}
	if calls.Load() != 1 {
		t.Fatalf("untrusted payload reached handler: %d", calls.Load())
	}
	if _, err = c.ExchangeFrame(make([]byte, 1024*1024+1)); !errors.Is(err, listen.ErrFrameTooLarge) {
		t.Fatal(err)
	}
	if calls.Load() != 1 {
		t.Fatal("oversized outgoing request reached handler")
	}
	c.Endpoint = "127.0.0.1:1"
	if _, err = c.ExchangeFrame(nil); !errors.Is(err, ErrTrust) {
		t.Fatalf("changed endpoint: %v", err)
	}
}

func TestClientTrustConfigurationRefusesWeakening(t *testing.T) {
	_, config := credentials(t)
	for _, mutate := range []func(*tls.Config){
		func(c *tls.Config) { c.InsecureSkipVerify = true },
		func(c *tls.Config) { c.RootCAs = nil },
		func(c *tls.Config) { c.ServerName = "" },
		func(c *tls.Config) { c.Certificates = nil },
		func(c *tls.Config) { c.MaxVersion = tls.VersionTLS12 },
	} {
		bad := config.Clone()
		mutate(bad)
		if _, err := Client("127.0.0.1:1", bad, time.Second, 0, remoteTestPin(t, config)); !errors.Is(err, ErrTrust) {
			t.Fatalf("weak config: %v", err)
		}
	}
}

// A retained transport reevaluates the owner's current key set on every TLS
// handshake. Neither endpoint may deliver an application frame after removal.
func TestLiveLeafAdmissionBeforeFrames(t *testing.T) {
	server, client := credentials(t)
	var serverAllowed, clientAllowed atomic.Bool
	serverAllowed.Store(true)
	clientAllowed.Store(true)
	var calls atomic.Int32
	serverPin, clientPin := remoteTestPin(t, client), remoteTestPin(t, server)
	address := start(t, server, func(p Peer) error {
		if !serverAllowed.Load() {
			return ErrTrust
		}
		return serverPin(p)
	}, func(_ context.Context, _ Peer, frame []byte) ([]byte, error) {
		calls.Add(1)
		return frame, nil
	})
	c, err := Client(address, client, time.Second, 1024, func(p Peer) error {
		if !clientAllowed.Load() {
			return ErrTrust
		}
		return clientPin(p)
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.ExchangeFrame([]byte("paired")); err != nil {
		t.Fatal(err)
	}
	clientAllowed.Store(false)
	if _, err := c.ExchangeFrame([]byte("removed server")); !errors.Is(err, ErrTrust) {
		t.Fatalf("client admission: %v", err)
	}
	clientAllowed.Store(true)
	serverAllowed.Store(false)
	if _, err := c.ExchangeFrame([]byte("removed client")); err == nil {
		t.Fatal("server admitted removed leaf")
	}
	if calls.Load() != 1 {
		t.Fatalf("refused frame reached handler: %d", calls.Load())
	}
	serverAllowed.Store(true)
	if _, err := c.ExchangeFrame([]byte("restored")); err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 2 {
		t.Fatalf("restored frame count: %d", calls.Load())
	}
}

func TestAdmissionPreservesVerifierAndRequiresPolicy(t *testing.T) {
	server, client := credentials(t)
	if _, err := Client("127.0.0.1:1", client, time.Second, 0, nil); !errors.Is(err, ErrTrust) {
		t.Fatalf("nil policy: %v", err)
	}
	sentinel := errors.New("existing connection verifier")
	client.VerifyConnection = func(tls.ConnectionState) error { return sentinel }
	address := start(t, server, remoteTestPin(t, client), func(context.Context, Peer, []byte) ([]byte, error) {
		t.Error("frame after verifier refusal")
		return nil, nil
	})
	c, err := Client(address, client, time.Second, 0, remoteTestPin(t, server))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.ExchangeFrame(nil); !errors.Is(err, sentinel) {
		t.Fatalf("existing verifier: %v", err)
	}
	if client.MinVersion != 0 || len(client.NextProtos) != 0 {
		t.Fatal("constructor mutated caller config")
	}
}

// No application write occurs in this test: refusal must finish as part of
// the handshake itself. Each leaf has a valid chain and name under these roots.
func TestUnpairedLeafFailsHandshakeWithoutFrame(t *testing.T) {
	for _, refuseServer := range []bool{false, true} {
		t.Run(map[bool]string{false: "client-leaf", true: "server-leaf"}[refuseServer], func(t *testing.T) {
			server, client := credentials(t)
			server.ClientAuth = tls.RequireAndVerifyClientCert
			server.MinVersion, client.MinVersion = tls.VersionTLS13, tls.VersionTLS13
			server.NextProtos, client.NextProtos = []string{Protocol}, []string{Protocol}
			serverAdmit, clientAdmit := remoteTestPin(t, client), remoteTestPin(t, server)
			refused := make(chan struct{}, 1)
			reject := func(Peer) error { refused <- struct{}{}; return ErrTrust }
			if refuseServer {
				clientAdmit = reject
			} else {
				serverAdmit = reject
			}
			verifyAdmission(server, serverAdmit)
			verifyAdmission(client, clientAdmit)
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			left, err := net.Dial("tcp", listener.Addr().String())
			if err != nil {
				t.Fatal(err)
			}
			right, err := listener.Accept()
			if err != nil {
				left.Close()
				t.Fatal(err)
			}
			defer left.Close()
			defer right.Close()
			deadline := time.Now().Add(time.Second)
			left.SetDeadline(deadline)
			right.SetDeadline(deadline)
			serverResult := make(chan error, 1)
			go func() { serverResult <- tls.Server(right, server).Handshake() }()
			clientErr := tls.Client(left, client).Handshake()
			serverErr := <-serverResult
			select {
			case <-refused:
			default:
				t.Fatal("leaf admission was not reached")
			}
			if refuseServer && !errors.Is(clientErr, ErrTrust) {
				t.Fatalf("client handshake: %v", clientErr)
			}
			if !refuseServer && !errors.Is(serverErr, ErrTrust) {
				t.Fatalf("server handshake: %v", serverErr)
			}
		})
	}
}

func TestDisconnectCancelsWaitAndClientReusesBudget(t *testing.T) {
	server, client := credentials(t)
	entered := make(chan struct{}, 1)
	stopped := make(chan struct{}, 1)
	address := start(t, server, remoteTestPin(t, client), func(ctx context.Context, _ Peer, frame []byte) ([]byte, error) {
		if string(frame) == "wait" {
			entered <- struct{}{}
			<-ctx.Done()
			stopped <- struct{}{}
			return nil, ctx.Err()
		}
		return frame, nil
	})
	c, err := Client(address, client, time.Second, 0, remoteTestPin(t, server))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { _, err := c.ExchangeFrameContext(ctx, []byte("wait")); done <- err }()
	select {
	case <-entered:
	case <-time.After(2 * time.Second):
		t.Fatal("handler never entered")
	}
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	select {
	case <-stopped:
	case <-time.After(time.Second):
		t.Fatal("disconnected wait retained")
	}
	got, err := c.ExchangeFrame([]byte("fresh"))
	if err != nil || string(got) != "fresh" {
		t.Fatalf("reuse: %q %v", got, err)
	}
	short, stop := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer stop()
	_, err = c.ExchangeFrameContext(short, []byte("wait"))
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("deadline: %v", err)
	}
}

func TestLocalExpectationCannotAuthenticateCustomTransport(t *testing.T) {
	c := listen.FrameClient{Endpoint: "custom", Server: &listen.ServerExpectation{}, Dialer: func(context.Context, string) (net.Conn, error) {
		t.Fatal("dialed ambiguous identity transport")
		return nil, nil
	}}
	if _, err := c.ExchangeFrame(nil); !errors.Is(err, listen.ErrServerUntrusted) {
		t.Fatal(err)
	}
}

func TestOwnedStreamCloseDoesNotWaitForTLSCloseNotify(t *testing.T) {
	serverConfig, clientConfig := credentials(t)
	clientRaw, serverRaw := net.Pipe()
	defer clientRaw.Close()
	defer serverRaw.Close()
	server := tls.Server(serverRaw, serverConfig)
	client := tls.Client(clientRaw, clientConfig)
	deadline := time.Now().Add(time.Second)
	clientRaw.SetDeadline(deadline)
	serverRaw.SetDeadline(deadline)
	handshake := make(chan error, 1)
	go func() { handshake <- server.Handshake() }()
	if err := client.Handshake(); err != nil {
		t.Fatal(err)
	}
	if err := <-handshake; err != nil {
		t.Fatal(err)
	}
	clientRaw.SetDeadline(time.Time{})
	serverRaw.SetDeadline(time.Time{})
	// The peer stops reading after handshake. A TLS Close would write close_notify
	// and wait on net.Pipe under a new five-second budget.
	done := make(chan error, 1)
	go func() { done <- (&ownedStream{Conn: client, raw: clientRaw}).Close() }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(200 * time.Millisecond):
		clientRaw.Close()
		<-done
		t.Fatal("cleanup waited for TLS close_notify")
	}
}

// remoteTestPin admits exactly the isolated fixture certificate's leaf key.
func remoteTestPin(t *testing.T, config *tls.Config) func(Peer) error {
	t.Helper()
	cert, err := x509.ParseCertificate(config.Certificates[0].Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	key := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	return func(peer Peer) error {
		if peer.Key != key {
			return ErrTrust
		}
		return nil
	}
}
