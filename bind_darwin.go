//go:build darwin

package identity

import (
	"fmt"

	"golang.org/x/sys/unix"
)

// The audit token is the right primitive and AF_UNIX is the wrong place to get
// it from.
//
// An audit token obtained from a mach message trailer - which is what an XPC
// peer has - was stamped by the kernel on the sending task for that message.
// Nothing the sender does afterwards changes it, and the pidversion inside it
// makes an execve visible. That is a binding.
//
// LOCAL_PEERTOKEN is not that token. XNU resolves it when asked, from the peer
// socket's so_last_pid, which is the process that most recently wrote to the
// socket. Measured on 15.7.4: a helper forked 405ms before the connection,
// exec'ing /bin/cat after it, is reported by LOCAL_PEERTOKEN as the peer, and
// the Security framework then validates /bin/cat's Apple signature honestly.
// See research/darwin-verification/probe-evidence.txt, experiments 1, 2 and 7.
//
// So this binding does the one thing a socket allows: it takes the token on
// the line after accept, before the service has read anything, and refuses any
// later disagreement instead of re-deriving. That converts a defeat the
// attacker wins every time into a race the attacker must win against the
// service's next syscall - and a race is not a proof. Ceiling reports this
// transport at ProofPID with XPC named as the one that does better, and Bind
// does not promote anything it captured.

type darwinBinding struct {
	fd    int
	token auditToken
}

func bindHandle(h Handle, opts *Options) (binder, *Peer, error) {
	fd := int(h)
	if err := requireAcceptedUnixSocket(fd); err != nil {
		return nil, nil, err
	}

	token, err := peerAuditToken(fd)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: LOCAL_PEERTOKEN: %v", ErrNoBinding, err)
	}

	xu, err := unix.GetsockoptXucred(fd, unix.SOL_LOCAL, unix.LOCAL_PEERCRED)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: LOCAL_PEERCRED: %v", ErrUnsupportedConn, err)
	}
	if xu.Version != xucredVersion {
		return nil, nil, fmt.Errorf("%w: LOCAL_PEERCRED returned struct version %d, not %d", ErrUnsupportedConn, xu.Version, xucredVersion)
	}
	// The xucred is the one thing on this transport the kernel really did
	// stamp at connect(2). If the token names a different principal, the
	// socket had already changed hands before this call.
	if token.euid() != xu.Uid {
		return nil, nil, fmt.Errorf("%w: the socket already pointed at uid %d when it was accepted, but the peer that connected was uid %d",
			ErrPeerMoved, token.euid(), xu.Uid)
	}

	b := &darwinBinding{fd: fd, token: token}
	peer, err := ofHandle(h, opts)
	if err != nil {
		return nil, nil, err
	}
	if err := b.recheck(); err != nil {
		return nil, nil, err
	}
	return b, peer, nil
}

func (b *darwinBinding) recheck() error {
	now, err := peerAuditToken(b.fd)
	if err != nil {
		// XNU reports EINVAL once the socket has no process behind it. That
		// is the peer having gone, which contradicts nothing: the capture is
		// a statement about who opened the connection, not about who is
		// running now.
		return nil
	}
	if now.pid() != b.token.pid() {
		return fmt.Errorf("%w: pid %d wrote to this socket last; pid %d opened it",
			ErrPeerMoved, now.pid(), b.token.pid())
	}
	if now.pidversion() != b.token.pidversion() {
		return fmt.Errorf("%w: pid %d has exec'd since this connection was accepted (pidversion %d, was %d)",
			ErrPeerMoved, now.pid(), now.pidversion(), b.token.pidversion())
	}
	return nil
}

// alive asks the socket, not the pid. A bare proc lookup would answer about
// whatever holds the number now, which is the mistake this whole file is
// about; the pidversion is what makes the answer specific to the instance that
// was captured.
func (b *darwinBinding) alive() (bool, error) {
	now, err := peerAuditToken(b.fd)
	if err != nil {
		return false, nil
	}
	return now.pid() == b.token.pid() && now.pidversion() == b.token.pidversion(), nil
}

func (b *darwinBinding) release() error { return nil }
