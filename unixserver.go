package identity

import (
	"fmt"
	"net"
	"syscall"
	"time"
)

// BindUnixServer binds the listening process at the far end of a dialed
// AF_UNIX stream connection (ID-T8). A provider that started an engine on a
// socket path calls it on the line after the dial, before sending a byte,
// checks the captured process against the engine it started, and rechecks
// with Binding.Peer before trusting a reply.
//
//   - Windows: SIO_AF_UNIX_GETPEERPID on the client socket returns the
//     process id the kernel recorded for the server end. The binding opens
//     that process, requires its creation time to predate the connection,
//     and reads user, path and package through the pinned handle.
//   - Linux: SO_PEERCRED on a connected client socket names the process that
//     called listen(2); SO_PEERPIDFD pins it, as Bind does for an accepted
//     socket.
//   - macOS: ErrNoBinding. The client socket's LOCAL_PEERPID and audit
//     token follow the server socket's most recent writer (ID-M1), so no
//     primitive pins the listening process.
//
// The returned Binding keeps the socket's handle and must be closed before c.
func BindUnixServer(c net.Conn, opts *Options) (*Binding, error) {
	if _, ok := c.(*net.UnixConn); !ok {
		return nil, fmt.Errorf("%w: not an AF_UNIX connection", ErrUnsupportedConn)
	}
	sc, ok := c.(syscall.Conn)
	if !ok {
		return nil, ErrUnsupportedConn
	}
	raw, err := sc.SyscallConn()
	if err != nil {
		return nil, ErrUnsupportedConn
	}
	var (
		inner binder
		peer  *Peer
		ierr  error
	)
	if err := raw.Control(func(fd uintptr) { inner, peer, ierr = bindUnixServer(Handle(fd), opts) }); err != nil {
		return nil, ErrUnsupportedConn
	}
	if ierr != nil {
		return nil, ierr
	}
	return &Binding{peer: peer, boundAt: time.Now(), inner: &bindingState{inner: inner}}, nil
}
