package listen

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestContextAdapterCancellationAndFreshReuse(t *testing.T) {
	for _, exchange := range []bool{false, true} {
		name := "write"
		if exchange {
			name = "exchange"
		}
		t.Run(name, func(t *testing.T) {
			endpoint := framedEndpoint(t)
			l, err := Listen(endpoint)
			if err != nil {
				t.Fatal(err)
			}
			defer l.Close()
			client := FrameClient{Endpoint: endpoint, Timeout: 5 * time.Second}
			invoke := func(ctx context.Context) error {
				adapter := client.WithContext(ctx)
				if exchange {
					_, err := adapter.ExchangeFrame([]byte("request"))
					return err
				}
				return adapter.WriteFrame([]byte("request"))
			}
			expired, finish := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
			defer finish()
			if err := invoke(expired); !errors.Is(err, context.DeadlineExceeded) {
				t.Fatalf("expired: %v", err)
			}
			// Exactly two receives: expired waiting opens no connection. The first
			// live call cancels after receive; a fresh call on the same client succeeds.
			entered := make(chan struct{})
			release := make(chan struct{})
			defer close(release)
			served := make(chan error, 1)
			go func() {
				for i := 0; i < 2; i++ {
					c, err := l.Accept()
					if err != nil {
						served <- err
						return
					}
					ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
					call, err := ReceiveFramed(ctx, c, framingNeed, 0)
					if err != nil {
						cancel()
						served <- err
						return
					}
					if i == 0 {
						close(entered)
						<-release
					} else if exchange {
						err = call.Reply([]byte("reply"))
					}
					call.Close()
					cancel()
					if err != nil {
						served <- err
						return
					}
				}
				served <- nil
			}()
			ctx, cancel := context.WithCancel(context.Background())
			result := make(chan error, 1)
			go func() { result <- invoke(ctx) }()
			select {
			case <-entered:
			case <-time.After(2 * time.Second):
				cancel()
				t.Fatal("request not received")
			}
			cancel()
			select {
			case err := <-result:
				if !errors.Is(err, context.Canceled) {
					t.Fatalf("cancellation: %v", err)
				}
			case <-time.After(time.Second):
				t.Fatal("canceled call still waiting")
			}
			release <- struct{}{}
			fresh, done := context.WithTimeout(context.Background(), 2*time.Second)
			defer done()
			if err := invoke(fresh); err != nil {
				t.Fatalf("fresh reuse: %v", err)
			}
			if err := <-served; err != nil {
				t.Fatal(err)
			}
		})
	}
}
