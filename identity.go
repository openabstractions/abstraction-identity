// Package identity answers one question for a local service: which program is
// on the other end of this connection, and how strongly is that proven.
//
// The second half is the point. A privileged service that grants narrow
// permissions to named applications - "allow LogViewer to read the System log"
// - is only as good as its ability to tell that the caller really is
// LogViewer. When it cannot, the honest outcome is a refusal, not a weaker
// grant made silently. So every attribute of a [Peer] arrives welded to a
// [Proof], there is no way to read the value without the proof, and a service
// can ask [CanEver] at startup whether the policy it intends to enforce is
// achievable on this operating system at all.
//
// Nothing here ever reads an identity out of a message. There is no API that
// accepts one. [ProofClaimed] exists only to name what is being refused.
//
// # Usage
//
//	// Once, at startup: refuse to run a policy this machine cannot enforce.
//	if err := identity.CanEver(policy); err != nil {
//	    return fmt.Errorf("this build cannot enforce its own permission model: %w", err)
//	}
//
//	for {
//	    h := acceptPipeInstance()
//	    at := time.Now() // the line after accept; see Options.ConnectedAt
//
//	    // Windows will not identify the peer until the server has read.
//	    frame := readOneBoundedFrame(h) // do not parse it yet
//
//	    peer, err := identity.OfHandle(identity.Handle(h), &identity.Options{ConnectedAt: at})
//	    if err != nil { reject(h); continue }
//	    if err := peer.Check(policy); err != nil { reject(h); continue }
//
//	    handle(peer, frame) // now the bytes may be interpreted, as a request
//	}                       // and never as a claim about who is making it
//
// # Platforms
//
// Windows named pipes, Linux AF_UNIX and macOS AF_UNIX are implemented. Every
// other GOOS is a seam that returns [ErrUnimplemented] rather than a weaker
// answer from a portable fallback.
//
// The three do not answer the same question equally well, and the differences
// are not details:
//
//   - Windows names the process that opened the pipe and cannot verify the code
//     it is running.
//   - Linux names the user unforgeably and has no general answer to what a
//     program is; without SO_PEERPIDFD (Linux 6.5) it cannot even bind a path
//     to the peer, and reports that at [ProofPID] rather than hiding it.
//   - macOS can verify a running program's signature, which neither of the
//     others can, but over a plain socket the audit token that selects which
//     program is resolved from the socket's current owner rather than stamped
//     at connect - so the strong answer is bound to a weak binding.
//
// Read CONTRACT.md before building a permission prompt on any of it. It is the
// document this package exists to make possible.
package identity

import (
	"net"
	"syscall"
)

// Handle is an operating-system handle for one accepted local connection: on
// Windows the server end of a named pipe instance, on Unix the file descriptor
// of a connected socket.
//
// The handle must still be open, and must be the end the service accepted, not
// the end the client opened. Ownership stays with the caller: nothing in this
// package closes it.
type Handle uintptr

// OfHandle identifies the program on the other end of an accepted local
// connection.
//
// It never blocks on the peer and never reads from the connection itself.
//
// On Windows there is a precondition that is easy to miss and impossible to
// work around: the server must already have completed a read on the pipe.
// Windows refuses to impersonate the client of a pipe nothing has been read
// from, and it is the read that matters, not the client's write. So the
// sequence is accept, read one bounded frame, identify, and only then decide
// what that frame was allowed to ask for. Calling OfHandle before the first
// read returns [ErrMustReadFirst].
//
// A returned error means the channel could not answer the question at all - a
// remote peer, the wrong end of the pipe, a refused impersonation. An answer
// that is merely weak comes back as a *Peer with low [Proof] values and a
// populated Notes, not as an error, because only the caller's policy knows
// whether weak is fatal.
func OfHandle(h Handle, opts *Options) (*Peer, error) { return ofHandle(h, opts) }

// OfConn is OfHandle for a net.Conn that is willing to give up its handle.
//
// Most named-pipe libraries on Windows are not: they wrap the handle in an
// unexported struct with no accessor. When that is the case OfConn returns
// [ErrUnsupportedConn] and the caller must keep hold of the handle it created
// the pipe instance with and use [OfHandle]. This is not a workaround to be
// embarrassed about - the handle is the object the identity belongs to.
func OfConn(c net.Conn, opts *Options) (*Peer, error) {
	switch v := c.(type) {
	case syscall.Conn:
		raw, err := v.SyscallConn()
		if err != nil {
			return nil, ErrUnsupportedConn
		}
		// Resolve inside Control, not after it. On Unix the descriptor is
		// only guaranteed to be open and to still mean this connection
		// while Control holds it; a descriptor read out and used later can
		// be closed and reissued in between, and would then answer about
		// something else entirely.
		var (
			p    *Peer
			ierr error
		)
		if err := raw.Control(func(fd uintptr) { p, ierr = ofHandle(Handle(fd), opts) }); err != nil {
			return nil, ErrUnsupportedConn
		}
		return p, ierr
	case interface{ Fd() uintptr }:
		return ofHandle(Handle(v.Fd()), opts)
	}
	return nil, ErrUnsupportedConn
}

// Ceiling reports what this platform can prove at best, and why it stops
// there. It does not depend on any connection.
func Ceiling() Limits { return ceiling() }
