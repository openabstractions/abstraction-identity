package remote

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/openabstractions/abstraction-identity/listen"
)

func credentials(t *testing.T) (*tls.Config, *tls.Config) {
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
	return &tls.Config{Certificates: []tls.Certificate{makeCert(2, x509.ExtKeyUsageServerAuth)}, ClientCAs: roots},
		&tls.Config{Certificates: []tls.Certificate{makeCert(3, x509.ExtKeyUsageClientAuth)}, RootCAs: roots, ServerName: "runtime.test"}
}

func start(t *testing.T, config *tls.Config, handler Handler) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- (Server{TLS: config, Handler: handler, Timeout: 2 * time.Second}).Serve(ctx, l) }()
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

func TestMutualTrustBeforeHandlerAndSharedFrames(t *testing.T) {
	server, client := credentials(t)
	var calls atomic.Int32
	address := start(t, server, func(ctx context.Context, p Peer, frame []byte) ([]byte, error) {
		calls.Add(1)
		if p.Certificate.SerialNumber.Int64() != 3 || p.Key == [32]byte{} {
			t.Error("missing authenticated certificate")
		}
		return frame, nil
	})
	c, err := Client(address, client, time.Second, 1024*1024)
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
		b, err := Client(address, bad, time.Second, 0)
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
		if _, err := Client("127.0.0.1:1", bad, time.Second, 0); !errors.Is(err, ErrTrust) {
			t.Fatalf("weak config: %v", err)
		}
	}
}

func TestDisconnectCancelsWaitAndClientReusesBudget(t *testing.T) {
	server, client := credentials(t)
	entered := make(chan struct{}, 1)
	stopped := make(chan struct{}, 1)
	address := start(t, server, func(ctx context.Context, _ Peer, frame []byte) ([]byte, error) {
		if string(frame) == "wait" {
			entered <- struct{}{}
			<-ctx.Done()
			stopped <- struct{}{}
			return nil, ctx.Err()
		}
		return frame, nil
	})
	c, err := Client(address, client, time.Second, 0)
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
