package listen

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestFramedBusyDialCancellation(t *testing.T) {
	endpoint := framedEndpoint(t)
	l, err := Listen(endpoint)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	held, err := Dial(endpoint)
	if err != nil {
		t.Fatal(err)
	}
	defer held.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, err = dialFramed(ctx, endpoint)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal(err)
	}
	if time.Since(start) > time.Second {
		t.Fatal("busy dial used legacy five-second wait")
	}
}
