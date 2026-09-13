package identity

import (
	"net"
	"syscall"
	"time"
)

// BindServer captures the server of an already connected local CLIENT handle,
// before application bytes are sent. The caller must establish that the handle
// belongs to the local transport namespace; this raw-handle primitive does not
// validate the path used to open it. The caller owns the connection and closes
// the returned binding before that connection. ConnectedAt must describe the
// successful dial, when supplied. This identifies a process; the caller still
// needs independent trust evidence to authorize that process as its server.
func BindServer(h Handle, opts *Options) (*Binding, error) {
	inner, peer, err := bindServerHandle(h, opts)
	if err != nil {
		return nil, err
	}
	return &Binding{peer: peer, boundAt: time.Now(), inner: inner}, nil
}

// BindServerConn is BindServer for a connection exposing syscall.Conn.
func BindServerConn(c net.Conn, opts *Options) (*Binding, error) {
	sc, ok := c.(syscall.Conn)
	if !ok {
		return nil, ErrUnsupportedConn
	}
	raw, err := sc.SyscallConn()
	if err != nil {
		return nil, err
	}
	var b *Binding
	var captureErr error
	if err := raw.Control(func(fd uintptr) { b, captureErr = BindServer(Handle(fd), opts) }); err != nil {
		return nil, err
	}
	return b, captureErr
}
