//go:build !windows

package listen

import (
	"context"
	"net"
	"syscall"
)

func dialFramed(ctx context.Context, path string) (net.Conn, error) {
	return (&net.Dialer{}).DialContext(ctx, "unix", path)
}

// idleIntact reports whether a pooled connection has nothing to read and has
// not been ended: a byte waiting is the server's closing marker, and end of
// stream is a server that closed.
func idleIntact(c net.Conn) bool {
	sc, ok := c.(syscall.Conn)
	if !ok {
		return false
	}
	raw, err := sc.SyscallConn()
	if err != nil {
		return false
	}
	intact := false
	err = raw.Control(func(fd uintptr) {
		var b [1]byte
		_, _, err := syscall.Recvfrom(int(fd), b[:], syscall.MSG_PEEK|syscall.MSG_DONTWAIT)
		intact = err == syscall.EAGAIN || err == syscall.EWOULDBLOCK
	})
	return err == nil && intact
}
