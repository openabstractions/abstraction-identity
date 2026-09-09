//go:build linux

package identity

import (
	"fmt"

	"golang.org/x/sys/unix"
)

// What SO_PEERPIDFD closes, and what it does not.
//
// A pidfd names a process instance. While one is open the kernel will not
// reassign that pid, so every /proc read behind it answers about the peer or
// fails; the reuse race that makes a bare pid unusable for a permission
// decision is gone. The kernel derives the pidfd from the connection itself,
// so unlike LOCAL_PEERTOKEN on macOS it cannot follow a later writer: a
// process handed this socket by the peer never becomes its answer.
//
// What a pidfd does not close is execve. It follows the process across an
// exec, so a peer that connects as one program and becomes another keeps the
// same pidfd, and /proc/<pid>/exe read afterwards names the second program.
// That is the attack this file exists to refuse: the image path is captured at
// bind and compared on every recheck, and a change is ErrPeerMoved rather than
// a new answer. The residual race is between the peer's execve and the
// service's Bind, and it is the reason Bind belongs on the line after accept.

type linuxBinding struct {
	pidfd int
	pid   int
	exe   string
}

func bindHandle(h Handle, opts *Options) (binder, *Peer, error) {
	fd := int(h)
	if err := requireAcceptedUnixSocket(fd); err != nil {
		return nil, nil, err
	}
	if ok, why := pidfdSupport(); !ok {
		return nil, nil, fmt.Errorf("%w: %s", ErrNoBinding, why)
	}

	pidfd, err := unix.GetsockoptInt(fd, unix.SOL_SOCKET, soPeerPIDFD)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: SO_PEERPIDFD: %v", ErrNoBinding, err)
	}

	b := &linuxBinding{pidfd: pidfd, pid: -1}
	ucred, err := unix.GetsockoptUcred(fd, unix.SOL_SOCKET, unix.SO_PEERCRED)
	if err != nil {
		b.release()
		return nil, nil, fmt.Errorf("%w: SO_PEERCRED: %v", ErrUnsupportedConn, err)
	}
	b.pid = int(ucred.Pid)

	live, err := pidfdAlive(pidfd, b.pid)
	switch {
	case err != nil:
		b.release()
		return nil, nil, fmt.Errorf("%w: the pidfd for this connection could not be checked: %v", ErrNoBinding, err)
	case !live:
		b.release()
		return nil, nil, ErrPeerGone
	}

	exe, _, err := processExe(b.pid)
	if err != nil {
		b.release()
		// The pidfd held the pid across the read, so a failure here is the
		// peer having exited under it, not a lookup that went astray.
		return nil, nil, fmt.Errorf("%w: /proc/%d/exe: %v", ErrPeerGone, b.pid, err)
	}
	b.exe = exe

	// The pidfd was open across both reads above, so the pid could not have
	// been reassigned between them, and ofHandle's own reads are pinned by
	// it for the same reason.
	peer, err := ofHandle(h, opts)
	if err != nil {
		b.release()
		return nil, nil, err
	}
	return b, peer, nil
}

func (b *linuxBinding) recheck() error {
	// The pidfd is open, so the pid cannot have been reassigned. An exited
	// peer leaves nothing behind that could contradict the capture, and a
	// /proc read that fails is that exit rather than a wrong answer.
	if live, err := b.alive(); err != nil || !live {
		return nil
	}
	exe, _, err := processExe(b.pid)
	if err != nil {
		return nil
	}
	if exe != b.exe {
		return fmt.Errorf("%w: it was %s when this connection was accepted and is %s now",
			ErrPeerMoved, strconvQuote(b.exe), strconvQuote(exe))
	}
	return nil
}

func (b *linuxBinding) alive() (bool, error) { return pidfdAlive(b.pidfd, b.pid) }

func (b *linuxBinding) release() error {
	if b.pidfd < 0 {
		return nil
	}
	err := unix.Close(b.pidfd)
	b.pidfd = -1
	return err
}
