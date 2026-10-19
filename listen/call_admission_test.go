package listen

import (
	"sync"
	"sync/atomic"
	"testing"
)

type closedConnection struct{ closed atomic.Bool }

func (c *closedConnection) Close() error { c.closed.Store(true); return nil }

func TestAdmissionEarlyCloseDoesNotReleaseHandlerAndReleaseIsReusable(t *testing.T) {
	gate := NewCallAdmission(1)
	first := &closedConnection{}
	release, admitted := gate.Take(first)
	if !admitted {
		t.Fatal("initial admission refused")
	}
	first.Close() // A failed handshake closes transport before its handler returns.
	excess := &closedConnection{}
	if _, admitted := gate.Take(excess); admitted || !excess.closed.Load() {
		t.Fatal("early close freed a running handler")
	}
	var joins sync.WaitGroup
	for range 10 {
		joins.Add(1)
		go func() { defer joins.Done(); release() }()
	}
	joins.Wait()
	next := &closedConnection{}
	finish, admitted := gate.Take(next)
	if !admitted || next.closed.Load() {
		t.Fatal("completed handler slot not reusable")
	}
	finish()
}

func TestAdmissionSaturationBoundsConcurrentHandlers(t *testing.T) {
	const limit = 4
	gate := NewCallAdmission(limit)
	var releases []func()
	for range limit {
		release, admitted := gate.Take(&closedConnection{})
		if !admitted {
			t.Fatal("capacity lost")
		}
		releases = append(releases, release)
	}
	var calls sync.WaitGroup
	for range 1000 {
		calls.Add(1)
		go func() {
			defer calls.Done()
			c := &closedConnection{}
			if _, admitted := gate.Take(c); admitted || !c.closed.Load() {
				t.Error("saturation admitted an excess handler")
			}
		}()
	}
	calls.Wait()
	for _, release := range releases {
		release()
	}
}
