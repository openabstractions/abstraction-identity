package listen

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"golang.org/x/sys/windows"
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

func TestWindowsSessionWriteDisconnectCodesPermitRefusalProbe(t *testing.T) {
	for _, err := range []error{
		windows.ERROR_BROKEN_PIPE,
		windows.ERROR_NO_DATA,
		windows.ERROR_PIPE_NOT_CONNECTED,
	} {
		wrapped := &os.PathError{Op: "write", Path: "pipe", Err: err}
		if !writeSignalsClosedPeer(wrapped) {
			t.Fatalf("write disconnect %v did not permit refusal probe", wrapped)
		}
	}
	if writeSignalsClosedPeer(errors.New("injected short write")) {
		t.Fatal("live-peer short write permits blocking refusal probe")
	}
}
