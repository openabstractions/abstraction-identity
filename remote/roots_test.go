package remote

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestClientRootsRefreshPreservesAcceptedCall(t *testing.T) {
	server, a := credentials(t)
	other, b := credentials(t)
	_, unknown := credentials(t)
	b.RootCAs = a.RootCAs
	unknown.RootCAs = a.RootCAs
	leafA, err := x509.ParseCertificate(a.Certificates[0].Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	leafB, err := x509.ParseCertificate(b.Certificates[0].Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	keyA, keyB := sha256.Sum256(leafA.RawSubjectPublicKeyInfo), sha256.Sum256(leafB.RawSubjectPublicKeyInfo)
	var mu sync.Mutex
	roots := server.ClientCAs.Clone()
	admitted := map[[32]byte]bool{keyA: true}
	entered, release, ended := make(chan struct{}), make(chan struct{}), make(chan error, 1)
	var frames atomic.Int32
	address := startServer(t, Server{TLS: server, Timeout: 5 * time.Second, ClientRoots: func(ctx context.Context) (*x509.CertPool, error) {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		mu.Lock()
		defer mu.Unlock()
		return roots.Clone(), nil
	}, Admit: func(p Peer) error {
		mu.Lock()
		defer mu.Unlock()
		if !admitted[p.Key] {
			return ErrTrust
		}
		return nil
	}, Handler: func(ctx context.Context, p Peer, frame []byte) ([]byte, error) {
		frames.Add(1)
		if string(frame) == "held-a" {
			close(entered)
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-release:
			}
		}
		return frame, nil
	}})
	clientA, err := Client(address, a, 5*time.Second, 0, remoteTestPin(t, server))
	if err != nil {
		t.Fatal(err)
	}
	go func() { _, err := clientA.ExchangeFrame([]byte("held-a")); ended <- err }()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("A did not enter")
	}
	defer func() {
		select {
		case <-release:
		default:
			close(release)
		}
		select {
		case <-ended:
		case <-time.After(5 * time.Second):
			t.Error("accepted A not joined")
		}
	}()
	mu.Lock()
	roots = other.ClientCAs.Clone()
	admitted[keyB] = true
	mu.Unlock()
	clientB, err := Client(address, b, time.Second, 0, remoteTestPin(t, server))
	if err != nil {
		t.Fatal(err)
	}
	if got, err := clientB.ExchangeFrame([]byte("new-b")); err != nil || string(got) != "new-b" {
		t.Fatalf("fresh B roots: %q %v", got, err)
	}
	select {
	case err := <-ended:
		t.Fatalf("roots refresh ended accepted A: %v", err)
	default:
	}
	before := frames.Load()
	for _, cfg := range []*tls.Config{a, unknown} {
		c, err := Client(address, cfg, time.Second, 0, remoteTestPin(t, server))
		if err != nil {
			t.Fatal(err)
		}
		if _, err = c.ExchangeFrame([]byte("refused")); err == nil {
			t.Fatal("absent/stale root admitted")
		}
	}
	mu.Lock()
	delete(admitted, keyB)
	mu.Unlock()
	if _, err = clientB.ExchangeFrame([]byte("removed")); err == nil {
		t.Fatal("removed live pin admitted")
	}
	if frames.Load() != before {
		t.Fatal("refused peer reached application frame")
	}
	close(release)
	if err := <-ended; err != nil {
		t.Fatal(err)
	}
	ended <- nil
}

func TestClientRootsRefusesWithoutFixedFallback(t *testing.T) {
	for _, mode := range []string{"nil", "error", "cancel"} {
		t.Run(mode, func(t *testing.T) {
			server, client := credentials(t)
			var frames atomic.Int32
			address := startServer(t, Server{TLS: server, HandshakeTimeout: 40 * time.Millisecond, ClientRoots: func(ctx context.Context) (*x509.CertPool, error) {
				switch mode {
				case "nil":
					return nil, nil
				case "error":
					return nil, errors.New("unavailable")
				default:
					<-ctx.Done()
					return nil, ctx.Err()
				}
			}, Admit: remoteTestPin(t, client), Handler: func(context.Context, Peer, []byte) ([]byte, error) { frames.Add(1); return []byte("unexpected"), nil }})
			c, err := Client(address, client, time.Second, 0, remoteTestPin(t, server))
			if err != nil {
				t.Fatal(err)
			}
			if _, err = c.ExchangeFrame(nil); err == nil {
				t.Fatal("dynamic roots refusal fell back to fixed roots")
			}
			if frames.Load() != 0 {
				t.Fatal("frame after roots refusal")
			}
		})
	}
}

func TestClientRootsCannotSupplyTLSConfiguration(t *testing.T) {
	config, client := credentials(t)
	server := Server{TLS: config, ClientRoots: func(context.Context) (*x509.CertPool, error) {
		t.Fatal("validation invoked roots owner")
		return nil, nil
	}, Admit: remoteTestPin(t, client), Handler: func(context.Context, Peer, []byte) ([]byte, error) { t.Fatal("validation dispatched"); return nil, nil }}
	for _, kind := range []string{"arbitrary-config", "old-tls"} {
		bad := server
		bad.TLS = config.Clone()
		if kind == "arbitrary-config" {
			bad.TLS.GetConfigForClient = func(*tls.ClientHelloInfo) (*tls.Config, error) { return config, nil }
		} else {
			bad.TLS.MaxVersion = tls.VersionTLS12
		}
		if err := bad.Validate(); !errors.Is(err, ErrTrust) {
			t.Fatalf("%s accepted: %v", kind, err)
		}
	}
}
