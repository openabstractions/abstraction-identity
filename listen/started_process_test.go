package listen

import (
	"context"
	"errors"
	"net"
	"testing"

	identity "github.com/openabstractions/abstraction-identity"
)

func TestFramedStartedMatchMessageLifetime(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	k := &FramedCall{ctx: ctx, message: &receivedMessage{done: done, matchStarted: func(*identity.Binding, *identity.SealedResourceEvidence) (identity.Code, identity.Proof, error) {
		return identity.Code{Trusted: true}, identity.ProofBound, nil
	}}}
	if code, proof, err := k.MatchStartedProcess(nil, nil); err != nil || !code.Trusted || proof != identity.ProofBound {
		t.Fatalf("message operation: %+v %v %v", code, proof, err)
	}
	close(done)
	if _, _, err := k.MatchStartedProcess(nil, nil); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("ended message: %v", err)
	}
	k.message = &receivedMessage{}
	if _, _, err := k.MatchStartedProcess(nil, nil); !errors.Is(err, identity.ErrNoBinding) {
		t.Fatalf("stream transport: %v", err)
	}
	k.closed = true
	if _, _, err := k.MatchStartedProcess(nil, nil); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("closed call: %v", err)
	}
}
func TestFramedStartedMatchCancellationAfterNative(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	k := &FramedCall{ctx: ctx, message: &receivedMessage{done: make(chan struct{}), matchStarted: func(*identity.Binding, *identity.SealedResourceEvidence) (identity.Code, identity.Proof, error) {
		cancel()
		return identity.Code{Trusted: true}, identity.ProofBound, nil
	}}}
	if _, proof, err := k.MatchStartedProcess(nil, nil); !errors.Is(err, context.Canceled) || proof != identity.ProofUnmet {
		t.Fatalf("late cancellation: %v %v", proof, err)
	}
}
