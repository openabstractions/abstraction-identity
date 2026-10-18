//go:build windows

package identity

import (
	"net"
	"net/netip"
	"os"
	"testing"
)

// ID-T7: AllSockets reads TCP sockets in every state, so the client end of
// an outbound connection is in it with its owner, where the listener table
// that Sockets reads has only listeners. Loopback only.
func TestAllSocketsHoldsAnOutboundConnection(t *testing.T) {
	l, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	go func() {
		if c, err := l.Accept(); err == nil {
			defer c.Close()
			buf := make([]byte, 1)
			_, _ = c.Read(buf)
		}
	}()
	c, err := net.Dial("tcp4", l.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	local := netip.MustParseAddrPort(c.LocalAddr().String())
	holds := func(sockets []Socket) bool {
		for _, s := range sockets {
			if s.Proto == "tcp" && s.PID == os.Getpid() && s.Addr.Unmap() == local.Addr() && s.Port == int(local.Port()) {
				return true
			}
		}
		return false
	}
	all, err := AllSockets()
	if err != nil {
		t.Fatal(err)
	}
	if !holds(all) {
		t.Fatalf("AllSockets has no row for this process's outbound socket %s", local)
	}
	listeners, err := Sockets()
	if err != nil {
		t.Fatal(err)
	}
	if holds(listeners) {
		t.Fatalf("Sockets lists the outbound socket %s as a listener", local)
	}
}
