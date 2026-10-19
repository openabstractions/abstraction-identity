package listen

import (
	"errors"
	"net"
	"sync"
	"testing"

	identity "github.com/openabstractions/abstraction-identity"
)

func TestCallPeerRefusesMissingAndClosedEvidence(t *testing.T) {
	for _, call := range []*Call{nil, {}, {closed: true}} {
		if peer, err := call.Peer(); peer != nil || !errors.Is(err, net.ErrClosed) {
			t.Fatalf("peer=%v err=%v", peer, err)
		}
		if err := call.Recheck(); !errors.Is(err, net.ErrClosed) {
			t.Fatalf("recheck=%v", err)
		}
	}
}

func TestCallPeerUsesRetainedBindingAndSerializesClose(t *testing.T) {
	if err := identity.CanEver(Program); err != nil {
		t.Skip(err)
	}
	endpoint := framedEndpoint(t)
	listener, err := Listen(endpoint)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	client, err := Dial(endpoint)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	accepted, err := listener.Accept()
	if err != nil {
		t.Fatal(err)
	}
	if _, err = client.Write([]byte("request\n")); err != nil {
		accepted.Close()
		t.Fatal(err)
	}
	call, err := Receive(accepted, Program, 1024)
	if err != nil {
		call.Close()
		t.Fatal(err)
	}
	defer call.Close()
	captured := call.b.Captured()
	call.Caller = Seen{Bound: true, User: "serialized claim", Path: "serialized claim"}
	if peer, err := call.Peer(); err != nil || peer != captured {
		t.Fatalf("peer=%p captured=%p err=%v", peer, captured, err)
	}
	var workers sync.WaitGroup
	workers.Add(2)
	go func() {
		defer workers.Done()
		for i := 0; i < 20; i++ {
			_, err := call.Peer()
			if err != nil && !errors.Is(err, net.ErrClosed) {
				t.Errorf("peer during close: %v", err)
			}
		}
	}()
	go func() { defer workers.Done(); _ = call.Close() }()
	workers.Wait()
	if peer, err := call.Peer(); peer != nil || !errors.Is(err, net.ErrClosed) {
		t.Fatalf("closed peer=%v err=%v", peer, err)
	}
	if err := call.Recheck(); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("closed recheck=%v", err)
	}
}
