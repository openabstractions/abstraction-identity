package identity

import (
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type retainFixture struct {
	live   atomic.Bool
	moved  atomic.Bool
	closed atomic.Int32
}
type retainFixturePin struct{ process *retainFixture }

type unsupportedRetainFixture struct{}

func (unsupportedRetainFixture) recheck() error       { return nil }
func (unsupportedRetainFixture) alive() (bool, error) { return true, nil }
func (unsupportedRetainFixture) release() error       { return nil }

func (p *retainFixturePin) recheck() error {
	if p.process.moved.Load() {
		return ErrPeerMoved
	}
	return nil
}
func (p *retainFixturePin) alive() (bool, error)           { return p.process.live.Load(), nil }
func (p *retainFixturePin) release() error                 { p.process.closed.Add(1); return nil }
func (p *retainFixturePin) retainProcess() (binder, error) { return &retainFixturePin{p.process}, nil }

func TestRetainProcessIndependentLifetimeAndEvidence(t *testing.T) {
	p := &retainFixture{}
	p.live.Store(true)
	at, deadline := time.Now(), time.Now().Add(time.Minute)
	peer := &Peer{evidenceValidUntil: deadline}
	owner := &Binding{peer: peer, boundAt: at, inner: &bindingState{inner: &retainFixturePin{p}}}
	retained, err := owner.Shared().RetainProcess()
	if err != nil {
		t.Fatal(err)
	}
	if retained.BoundAt() != at || retained.EvidenceValidUntil() != deadline {
		t.Fatal("retention changed evidence times")
	}
	if err = owner.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err = owner.Shared().Peer(); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("closed owner: %v", err)
	}
	if got, err := retained.Peer(); err != nil || got != peer {
		t.Fatalf("retained peer: %v %v", got, err)
	}
	p.live.Store(false)
	if live, err := retained.Alive(); live || err != nil {
		t.Fatalf("exited: %v %v", live, err)
	}
	if _, err = retained.Peer(); err != nil {
		t.Fatalf("historical peer: %v", err)
	}
	if _, err = retained.RetainProcess(); !errors.Is(err, ErrPeerGone) {
		t.Fatalf("retain exited: %v", err)
	}
	retained.Close()
	retained.Close()
	if p.closed.Load() != 2 {
		t.Fatalf("releases=%d", p.closed.Load())
	}
}

func TestRetainProcessRefusesMovedUnsupportedAndClosed(t *testing.T) {
	if _, err := (*Binding)(nil).RetainProcess(); !errors.Is(err, ErrNoBinding) {
		t.Fatal(err)
	}
	unsupported := &Binding{inner: &bindingState{inner: unsupportedRetainFixture{}}}
	if _, err := unsupported.RetainProcess(); !errors.Is(err, ErrNoBinding) {
		t.Fatal(err)
	}
	p := &retainFixture{}
	p.live.Store(true)
	p.moved.Store(true)
	b := &Binding{inner: &bindingState{inner: &retainFixturePin{p}}}
	if _, err := b.RetainProcess(); !errors.Is(err, ErrPeerMoved) {
		t.Fatal(err)
	}
	b.Close()
	if _, err := b.RetainProcess(); !errors.Is(err, net.ErrClosed) {
		t.Fatal(err)
	}
}

func TestRetainProcessConcurrentClose(t *testing.T) {
	p := &retainFixture{}
	p.live.Store(true)
	b := &Binding{peer: &Peer{}, inner: &bindingState{inner: &retainFixturePin{p}}}
	ready, use := make(chan struct{}, 32), make(chan struct{})
	var wg sync.WaitGroup
	for range 32 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			pin, err := b.Shared().RetainProcess()
			ready <- struct{}{}
			if err != nil {
				t.Error(err)
				return
			}
			defer pin.Close()
			<-use
			if _, err = pin.Peer(); err != nil {
				t.Error(err)
			}
			if live, err := pin.Alive(); !live || err != nil {
				t.Errorf("live=%v err=%v", live, err)
			}
		}()
	}
	for range 32 {
		<-ready
	}
	b.Close()
	close(use)
	wg.Wait()
	if p.closed.Load() != 33 {
		t.Fatalf("released %d pins, want 33", p.closed.Load())
	}
}
