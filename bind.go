package identity

import (
	"errors"
	"net"
	"syscall"
	"time"
)

// Errors a binding returns instead of an identity.
var (
	// ErrNoBinding means this machine has no primitive that ties an
	// identity to the process that opened the connection. It is not a
	// weaker answer; it is the absence of one, and a service that needs a
	// peer bound must refuse the connection. Ceiling().Binding says what is
	// missing.
	ErrNoBinding = errors.New("identity: this machine cannot bind a peer to a connection")

	// ErrPeerGone means there was no live process to bind to. It comes from
	// [Bind] only. A peer that exits after it has been bound does not
	// invalidate the binding: "the process that opened this connection was
	// X" stays true after X exits, and every primitive here pins the process
	// so that no successor can take its place. Ask [Binding.Alive] when
	// liveness is what matters.
	ErrPeerGone = errors.New("identity: there is no live peer to bind to")

	// ErrPeerMoved means the connection no longer answers for the process
	// that was captured when it was accepted.
	ErrPeerMoved = errors.New("identity: the connection has moved to a different program since it was accepted")
)

// A Binding is a peer identity captured when the connection was accepted,
// together with whatever handle the platform offers for asking, later, whether
// that capture is still true.
//
// It exists because [OfHandle] answers by looking the peer up at the moment it
// is called, and a lookup is a race by construction: every platform here
// resolves a program from a number, and the thing that number refers to can
// change. A Binding takes the answer once, at the only instant the caller
// controls, and refuses afterwards rather than re-deriving.
//
// When to call it differs by platform, and the difference is not cosmetic:
//
//   - Linux and macOS: at accept, before the service reads a single byte. On
//     macOS this is load-bearing. LOCAL_PEERTOKEN follows the socket's most
//     recent writer, so a byte written by another process before this call is
//     a byte this call believes.
//   - Windows: after the first read, the same precondition [OfHandle] has.
//     Nothing is lost by waiting: the client process id is written onto the
//     pipe instance by the kernel when the client opens it and never moves,
//     and a Windows process cannot replace its own image.
type Binding struct {
	peer    *Peer
	boundAt time.Time
	inner   binder
}

type binder interface {
	recheck() error
	alive() (bool, error)
	release() error
}

// Bind captures the peer identity of an accepted local connection and keeps
// the platform handle needed to re-check it.
//
// The returned Binding must be closed. See the type documentation for when to
// call this, which is not the same on all three platforms.
func Bind(h Handle, opts *Options) (*Binding, error) {
	inner, peer, err := bindHandle(h, opts)
	if err != nil {
		return nil, err
	}
	return &Binding{peer: peer, boundAt: time.Now(), inner: inner}, nil
}

// BindConn is [Bind] for a net.Conn that is willing to give up its handle.
//
// The returned Binding keeps a reference to that handle and is only valid
// while c is open: close the Binding before closing c. This is the one place
// this package holds a descriptor outside raw.Control, and it is unavoidable -
// a binding that has to be re-checked later cannot re-derive the handle it was
// taken from.
func BindConn(c net.Conn, opts *Options) (*Binding, error) {
	sc, ok := c.(syscall.Conn)
	if !ok {
		return nil, ErrUnsupportedConn
	}
	raw, err := sc.SyscallConn()
	if err != nil {
		return nil, ErrUnsupportedConn
	}
	var (
		b    *Binding
		ierr error
	)
	if err := raw.Control(func(fd uintptr) { b, ierr = Bind(Handle(fd), opts) }); err != nil {
		return nil, ErrUnsupportedConn
	}
	return b, ierr
}

// Peer returns the captured identity, having first confirmed that nothing has
// contradicted it. It returns [ErrPeerMoved] instead of a stale answer.
//
// A peer that has merely exited is not a contradiction and is answered
// normally; see [Binding.Alive].
func (b *Binding) Peer() (*Peer, error) {
	if err := b.inner.recheck(); err != nil {
		return nil, err
	}
	return b.peer, nil
}

// Alive reports whether the bound process still exists. It is a separate
// question from whether the identity is still trustworthy, and services that
// conflate the two end up refusing honest callers that happened to exit.
func (b *Binding) Alive() (bool, error) { return b.inner.alive() }

// Captured returns the identity as it was at bind time without re-checking it.
// It is for log lines and for tests that need to compare the two answers. A
// permission decision uses [Binding.Peer].
func (b *Binding) Captured() *Peer { return b.peer }

// BoundAt is when the capture was taken.
func (b *Binding) BoundAt() time.Time { return b.boundAt }

// Check is [Peer.Check] against the re-checked capture.
func (b *Binding) Check(n Need) error {
	p, err := b.Peer()
	if err != nil {
		return err
	}
	return p.Check(n)
}

// Close releases the platform handle. A Binding that is not closed leaks a
// pidfd on Linux and a process handle on Windows, and on Linux a leaked pidfd
// holds the peer's pid reserved for as long as the service runs.
func (b *Binding) Close() error { return b.inner.release() }
