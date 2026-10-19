package identity

import (
	"errors"
	"net"
	"sync/atomic"
	"testing"
	"time"
)

type startedFixtureMatcher struct {
	entered      chan struct{}
	releaseMatch chan struct{}
	closed       atomic.Bool
}

func (*startedFixtureMatcher) recheck() error       { return nil }
func (*startedFixtureMatcher) alive() (bool, error) { return true, nil }
func (p *startedFixtureMatcher) release() error     { p.closed.Store(true); return nil }
func (p *startedFixtureMatcher) matchStarted(sealedResourceNative, *XPCRequest) (Code, Proof, error) {
	close(p.entered)
	<-p.releaseMatch
	if p.closed.Load() {
		return Code{}, ProofUnmet, net.ErrClosed
	}
	return Code{Trusted: true}, ProofBound, nil
}
func TestStartedResourceCompositionLifetime(t *testing.T) {
	native := &startedFixtureMatcher{entered: make(chan struct{}), releaseMatch: make(chan struct{})}
	state := &bindingState{inner: native}
	pin := &Binding{inner: state}
	e := &SealedResourceEvidence{state: &sealedResourceState{native: &sealedResourceTestNative{}}}
	done := make(chan error, 1)
	go func() { _, _, err := e.MatchStartedProcess(pin.Shared()); done <- err }()
	<-native.entered
	closed := make(chan struct{})
	go func() { pin.Close(); close(closed) }()
	select {
	case <-closed:
		t.Fatal("close crossed active native match")
	case <-time.After(10 * time.Millisecond):
	}
	close(native.releaseMatch)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	<-closed
	if _, _, err := e.MatchStartedProcess(pin); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("closed started binding: %v", err)
	}
	if _, _, err := e.MatchStartedXPCRequest(pin, nil); !errors.Is(err, ErrNoBinding) {
		t.Fatalf("nil request: %v", err)
	}
	e.Close()
	if _, _, err := e.MatchStartedProcess(pin); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("closed evidence: %v", err)
	}
}
