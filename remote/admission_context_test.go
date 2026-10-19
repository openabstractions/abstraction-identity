package remote

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"
)

func TestAdmissionContextDeadline(t *testing.T) {
	for _, receiving := range []bool{false, true} {
		t.Run(map[bool]string{false: "dial", true: "receive"}[receiving], func(t *testing.T) {
			serverTLS, clientTLS := credentials(t)
			refused := make(chan error, 1)
			wait := func(ctx context.Context, _ Peer) error {
				<-ctx.Done()
				refused <- ctx.Err()
				return ctx.Err()
			}
			var frames atomic.Int32
			s := Server{TLS: serverTLS, Admit: remoteTestPin(t, clientTLS), Timeout: 5 * time.Second,
				Handler: func(context.Context, Peer, []byte) ([]byte, error) { frames.Add(1); return nil, nil }}
			d := Dialer{TLS: clientTLS, Timeout: 5 * time.Second, Admit: remoteTestPin(t, serverTLS)}
			if receiving {
				s.Admit, s.AdmitContext, s.HandshakeTimeout = nil, wait, 500*time.Millisecond
			} else {
				d.Admit, d.AdmitContext = nil, wait
			}
			// Context alone is a valid admission owner on either side.
			address := startServer(t, s)
			client, err := d.Client(address)
			if err != nil {
				t.Fatal(err)
			}
			ctx := t.Context()
			if !receiving {
				var cancel context.CancelFunc
				ctx, cancel = context.WithTimeout(ctx, 500*time.Millisecond)
				defer cancel()
			}
			_, err = client.WithContext(ctx).ExchangeFrame([]byte("must not dispatch"))
			if err == nil || !errors.Is(err, ErrTrust) && !receiving {
				t.Fatalf("expired admission did not refuse trust: %v", err)
			}
			select {
			case err := <-refused:
				if !errors.Is(err, context.DeadlineExceeded) {
					t.Fatal(err)
				}
			case <-t.Context().Done():
				t.Fatal(t.Context().Err())
			}
			if frames.Load() != 0 {
				t.Fatal("expired admission dispatched a frame")
			}
		})
	}
}

func TestAdmissionCallbacksBothMustAccept(t *testing.T) {
	for _, receiving := range []bool{false, true} {
		for _, legacyRefuses := range []bool{false, true} {
			name := map[bool]string{false: "dial", true: "receive"}[receiving] + map[bool]string{false: "/context", true: "/legacy"}[legacyRefuses]
			t.Run(name, func(t *testing.T) {
				serverTLS, clientTLS := credentials(t)
				var legacy, contextual, frames atomic.Int32
				refusal := errors.New("admission fixture refusal")
				old := func(Peer) error {
					legacy.Add(1)
					if legacyRefuses {
						return refusal
					}
					return nil
				}
				current := func(context.Context, Peer) error { contextual.Add(1); return refusal }
				s := Server{TLS: serverTLS, Admit: remoteTestPin(t, clientTLS), Timeout: 5 * time.Second,
					Handler: func(context.Context, Peer, []byte) ([]byte, error) { frames.Add(1); return nil, nil }}
				d := Dialer{TLS: clientTLS, Timeout: 5 * time.Second, Admit: remoteTestPin(t, serverTLS)}
				if receiving {
					s.Admit, s.AdmitContext = old, current
				} else {
					d.Admit, d.AdmitContext = old, current
				}
				client, err := d.Client(startServer(t, s))
				if err != nil {
					t.Fatal(err)
				}
				if _, err = client.ExchangeFrame([]byte("must not dispatch")); err == nil {
					t.Fatal("refused callback admitted")
				}
				want := int32(1)
				if legacyRefuses {
					want = 0
				}
				if legacy.Load() != 1 || contextual.Load() != want || frames.Load() != 0 {
					t.Fatalf("legacy=%d contextual=%d frames=%d", legacy.Load(), contextual.Load(), frames.Load())
				}
			})
		}
	}
}
