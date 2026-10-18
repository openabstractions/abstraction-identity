//go:build windows

package identity

import (
	"errors"
	"net"
	"net/netip"
	"os"
	"testing"
	"time"
)

// thisProcess is a tree of one: the test process, proved by id and creation
// time the way a supervised job's Contains proves membership.
func thisProcess(t *testing.T) TreeContains {
	t.Helper()
	started, err := processCreation(os.Getpid())
	if err != nil {
		t.Fatal(err)
	}
	return func(pid int, at time.Time) (bool, error) {
		return pid == os.Getpid() && at.Equal(started), nil
	}
}

// TestCheckTreeLoopbackReadsTheOwnerTables asserts ID-T7 on the real
// Windows owner tables, with membership proved by id and creation time.
func TestCheckTreeLoopbackReadsTheOwnerTables(t *testing.T) {
	l, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	listener := netip.MustParseAddrPort(l.Addr().String())
	if err := CheckTreeLoopback(listener, thisProcess(t)); err != nil {
		t.Fatalf("loopback-only test process refused: %v", err)
	}
	stranger := func(int, time.Time) (bool, error) { return false, nil }
	if err := CheckTreeLoopback(listener, stranger); !errors.Is(err, ErrBeyondLoopback) {
		t.Fatalf("listener credited to a tree that does not own it: %v", err)
	}
	stale := func(pid int, at time.Time) (bool, error) { return pid == os.Getpid() && at.IsZero(), nil }
	if err := CheckTreeLoopback(listener, stale); !errors.Is(err, ErrBeyondLoopback) {
		t.Fatalf("membership without the creation time accepted: %v", err)
	}
}

// A wildcard socket of the tree, injected into the real table, refuses. The
// test process itself never binds beyond loopback.
func TestCheckLoopbackOnlyRefusesInjectedWildcard(t *testing.T) {
	l, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	sockets, err := Sockets()
	if err != nil {
		t.Fatal(err)
	}
	wide := append(sockets, Socket{Proto: "tcp", Addr: netip.MustParseAddr("0.0.0.0"), Port: 13305, PID: os.Getpid()})
	listener := netip.MustParseAddrPort(l.Addr().String())
	if err := CheckLoopbackOnly(wide, OwnedByTree(thisProcess(t)), listener); !errors.Is(err, ErrBeyondLoopback) {
		t.Fatalf("tree socket on 0.0.0.0 accepted: %v", err)
	}
	if err := CheckLoopbackOnly(sockets, OwnedByTree(thisProcess(t)), listener); err != nil {
		t.Fatalf("real table refused: %v", err)
	}
}
