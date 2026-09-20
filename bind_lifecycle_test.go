package identity

import (
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"testing"
)

type blockingBinder struct {
	recheckEntered chan struct{}
	recheckDone    chan struct{}
	releaseEntered chan struct{}
	active         atomic.Int32
	overlapped     atomic.Bool
	releases       atomic.Int32
}

func (b *blockingBinder) enter() {
	if b.active.Add(1) != 1 {
		b.overlapped.Store(true)
	}
}

func (b *blockingBinder) leave() { b.active.Add(-1) }

func (b *blockingBinder) recheck() error {
	b.enter()
	defer b.leave()
	close(b.recheckEntered)
	<-b.recheckDone
	return nil
}

func (b *blockingBinder) alive() (bool, error) {
	b.enter()
	defer b.leave()
	return true, nil
}

func (b *blockingBinder) release() error {
	b.enter()
	defer b.leave()
	b.releases.Add(1)
	close(b.releaseEntered)
	return nil
}

func TestBindingCloseSerializesSharedChecksAndReleasesOnce(t *testing.T) {
	platform := &blockingBinder{
		recheckEntered: make(chan struct{}),
		recheckDone:    make(chan struct{}),
		releaseEntered: make(chan struct{}),
	}
	state := &bindingState{inner: platform}
	owner := &Binding{inner: state}
	view := owner.Shared()

	checked := make(chan error, 1)
	go func() {
		_, err := view.Peer()
		checked <- err
	}()
	<-platform.recheckEntered

	const closers = 16
	closed := make(chan error, closers)
	var wg sync.WaitGroup
	for range closers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			closed <- owner.Close()
		}()
	}

	close(platform.recheckDone)
	if err := <-checked; err != nil {
		t.Fatalf("shared check: %v", err)
	}
	wg.Wait()
	close(closed)
	for err := range closed {
		if err != nil {
			t.Fatalf("close: %v", err)
		}
	}
	<-platform.releaseEntered
	if got := platform.releases.Load(); got != 1 {
		t.Fatalf("platform release called %d times, want 1", got)
	}
	if platform.overlapped.Load() {
		t.Fatal("platform handle was checked and released concurrently")
	}
	if err := view.Close(); err != nil {
		t.Fatalf("close shared view: %v", err)
	}
	if _, err := owner.Peer(); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("Peer after Close = %v, want net.ErrClosed", err)
	}
	if alive, err := view.Alive(); alive || !errors.Is(err, net.ErrClosed) {
		t.Fatalf("Alive after Close = %v, %v; want false, net.ErrClosed", alive, err)
	}
}
