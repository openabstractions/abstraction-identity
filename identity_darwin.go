//go:build darwin

package identity

// macOS, over AF_UNIX.
//
// This platform has the best code identity of the three and the worst peer
// binding, and the two facts are easy to confuse because the same API carries
// both. Read this before believing anything below.
//
// # What the kernel stamps onto the socket
//
// One thing: LOCAL_PEERCRED. unp_connect copies the connecting thread's
// credentials into the socket at connect(2), and LOCAL_PEERCRED hands back that
// copy. The uid is therefore ProofKernel, exactly as SO_PEERCRED is on Linux.
//
// # What the kernel does *not* stamp onto the socket
//
// Everything else. LOCAL_PEERPID and LOCAL_PEERTOKEN are not connect-time
// records: XNU resolves them at the moment of the call, from the peer socket's
// last_pid - the pid of the process that most recently performed a socket
// operation on that fd - and LOCAL_PEERTOKEN then does proc_find(last_pid) and
// asks that task for its audit token. So the audit token obtained from a unix
// socket is a lookup by number wearing an audit token's clothes. It is not the
// unforgeable, kernel-stamped token that arrives in a mach message trailer, and
// the pidversion inside it proves only that the token is self-consistent, not
// that it describes the process that connected.
//
// The consequence is concrete rather than theoretical. A caller can connect and
// then hand the connected socket to another program as its stdout; the first
// write from that program moves last_pid, and every question this package asks
// afterwards is answered about the other program - including the code signature.
// So a service on a plain unix socket can be shown any program the caller can
// get to write one byte.
//
// This package narrows that as far as a socket allows:
//
//   - Options.ConnectedAt, compared against the process start time from
//     sysctl, excludes every process created after the connection existed -
//     which is the whole spawn-a-signed-program-and-hand-it-the-socket family.
//   - The audit token's euid is required to match the connect-time xucred, so
//     a drift to a process running as somebody else is caught.
//   - LOCAL_PEERPID is read separately and required to agree with the pid
//     inside the token, and the token is read again after resolution and
//     required not to have moved. Drift during identification is refused
//     rather than reported.
//
// What remains is a process that already existed when the connection was made
// and can be induced to touch the socket. Measured on 15.7.4: a helper forked
// 405ms before the connection and exec'ing /bin/cat after it defeats all three
// checks, because p_starttime survives exec. So nothing derived from the peer's
// pid is reported above ProofPID on this transport - including the code
// signature, however good the signature is. See
// research/darwin-verification/probe-evidence.txt, experiments 2 and 7.
//
// [Bind] narrows it further, by taking the token before the service reads and
// refusing every later change, and bind_darwin.go states exactly how much that
// is worth. It is not enough to promote anything.
//
// # XPC is where the strong answer lives
//
// An XPC message carries an audit token the kernel put in the mach message
// trailer for that message, on the sending task. That is the stamped-at-send
// token this transport does not have, and it is what makes ProofSigned
// achievable on macOS. This package speaks sockets, so it does not reach it,
// and Ceiling() says so rather than implying otherwise. See CONTRACT.md.

import (
	"fmt"
	"time"

	"golang.org/x/sys/unix"
)

const (
	whyPeerCredDarwin = "uid and gid are the credentials the kernel copied into the socket at connect(2) (LOCAL_PEERCRED); the peer never spoke them and cannot influence them"

	// The single most important sentence in this file.
	whySocketBinding = "resolved from the peer socket's current owner (LOCAL_PEERPID / LOCAL_PEERTOKEN are looked up when asked, not stamped at connect), cross-checked against the connect-time credentials and refused if the process started after the connection; that excludes pid reuse and any program spawned after the connection, but not a process that already existed and was handed the socket, which is measured and defeats it - see CONTRACT.md and Bind"

	whyNoXPC = "ProofSigned needs an audit token the kernel stamped on the message itself, which exists on XPC and not on a unix socket; over a socket the signature is verified against a process the socket only points at - see CONTRACT.md"

	whyNoSocketBinding = "none. LOCAL_PEERTOKEN is resolved from the peer socket's most recent writer, not stamped at connect, so no primitive on this transport names the process that opened the connection. Bind takes the token on the line after accept and refuses every later change, which narrows the measured defeat (a pre-forked helper exec'ing /bin/cat, believed every time) to a race the attacker must win against the service's next syscall - a narrowing, not a binding"

	whyXPCIsStronger = "XPC: xpc_connection_get_audit_token returns the token the kernel stamped on the sending task in the mach message trailer. It cannot follow a later writer and its pidversion changes on execve, which makes Code reach ProofSigned. This package speaks sockets and does not reach it"
)

func ceiling() Limits {
	codeBest, codeWhy := codeCeiling()

	pkg := codeBest
	pkgWhy := "the bundle identifier comes out of the same validated signature as Code and is worth exactly as much"
	if codeBest == ProofNone {
		pkgWhy = codeWhy
	}

	// The signature is verified honestly and against the wrong process, so
	// it is worth what the binding under it is worth and no more. Capping
	// here rather than in codeCeiling keeps the cgo file's answer about the
	// Security framework and this file's answer about the transport.
	if codeBest > ProofPID {
		codeBest = ProofPID
	}
	if pkg > ProofPID {
		pkg = ProofPID
	}

	return Limits{
		Platform:  "darwin",
		Transport: "unix",
		Bindable:  false,
		Binding:   whyNoSocketBinding,
		Stronger:  whyXPCIsStronger,
		Best: Need{
			User:    ProofKernel,
			Process: ProofPID,
			Path:    ProofPID,
			Package: pkg,
			Code:    codeBest,
		},
		Why: map[string]string{
			"user":    whyPeerCredDarwin,
			"process": whySocketBinding,
			"path":    whySocketBinding,
			"package": pkgWhy + "; " + whySocketBinding,
			// whyNoXPC belongs here in both builds. A cgo build stops short
			// of ProofSigned because of the transport, a no-cgo build
			// because of the build - and a service told only the second
			// would rebuild with cgo and still not get there.
			"code": codeWhy + "; " + whyNoXPC,
		},
	}
}

func ofHandle(h Handle, opts *Options) (*Peer, error) {
	fd := int(h)
	connectedAt := opts.connectedAt()

	p := &Peer{
		Platform:   "darwin",
		Transport:  "unix",
		ObservedAt: time.Now(),
		User:       unknown[User]("user", "not resolved"),
		Process:    unknown[Process]("process", "not resolved"),
		Path:       unknown[string]("path", "not resolved"),
		Package:    unknown[string]("package", "not resolved"),
		Code:       unknown[Code]("code", "not resolved"),
	}

	if err := requireAcceptedUnixSocket(fd); err != nil {
		return nil, err
	}

	// 1. The one connect-time fact on this transport.
	xu, err := unix.GetsockoptXucred(fd, unix.SOL_LOCAL, unix.LOCAL_PEERCRED)
	if err != nil {
		return nil, fmt.Errorf("%w: LOCAL_PEERCRED: %v", ErrUnsupportedConn, err)
	}
	if xu.Version != xucredVersion {
		return nil, fmt.Errorf("%w: LOCAL_PEERCRED returned struct version %d, not %d; refusing to parse a layout this package does not know", ErrUnsupportedConn, xu.Version, xucredVersion)
	}
	user := User{Kind: "posix", UID: int(xu.Uid), GID: -1}
	if xu.Ngroups > 0 {
		user.GID = int(xu.Groups[0])
	}

	// 2. The audit token, and the two cross-checks that make it worth
	// anything at all on this transport.
	token, err := peerAuditToken(fd)
	if err != nil {
		// The peer is gone (proc_find failed, and XNU reports EINVAL), or
		// this is not a unix socket after all. Either way the connection
		// carries a principal and nothing else.
		p.User = attr("user", user, ProofKernel, whyPeerCredDarwin)
		why := "the peer socket has no process behind it any more (LOCAL_PEERTOKEN: " + err.Error() + ")"
		p.Process = unknown[Process]("process", why)
		p.Path = unknown[string]("path", why)
		p.Package = unknown[string]("package", why)
		p.Code = unknown[Code]("code", why)
		p.note("process: %s", why)
		return p, nil
	}

	user.AuditSessionID = token.asid()
	p.User = attr("user", user, ProofKernel, whyPeerCredDarwin)

	pid, gen := int(token.pid()), token.pidversion()
	proc := Process{PID: pid, Generation: gen}

	// The token names a process running as somebody other than the peer
	// that connected. That is the socket's owner having moved, and it is a
	// refusal, not a weaker answer.
	if token.euid() != xu.Uid {
		why := fmt.Sprintf("the process the socket now points at runs as uid %d, but the peer that connected was uid %d; the socket has changed hands and nothing about the process can be reported",
			token.euid(), xu.Uid)
		p.Process = unknown[Process]("process", why)
		p.Path = unknown[string]("path", why)
		p.Package = unknown[string]("package", why)
		p.Code = unknown[Code]("code", why)
		p.note("process: %s", why)
		return p, nil
	}

	// LOCAL_PEERPID is a second, independent read of the same mutable
	// field. Disagreement means it moved between the two calls.
	if peerpid, err := unix.GetsockoptInt(fd, unix.SOL_LOCAL, unix.LOCAL_PEERPID); err == nil && peerpid != pid {
		why := fmt.Sprintf("the socket's owner changed while it was being identified: LOCAL_PEERPID says %d, the audit token says %d", peerpid, pid)
		p.Process = unknown[Process]("process", why)
		p.Path = unknown[string]("path", why)
		p.Package = unknown[string]("package", why)
		p.Code = unknown[Code]("code", why)
		p.note("process: %s", why)
		return p, nil
	}

	// 3. The start-time bound, which is the same argument the Windows
	// implementation makes and is worth more here: it excludes every
	// process created after the connection existed, and so excludes both
	// pid reuse and the trick of spawning a signed program and handing it
	// the socket.
	started, startErr := processStartTime(pid)
	switch {
	case startErr != nil:
		why := "the peer's start time could not be read (" + startErr.Error() + "), so it could not be shown to predate the connection"
		p.Process = attr("process", proc, ProofPID, why)
		p.Path = unknown[string]("path", why)
		p.Package = unknown[string]("package", why)
		p.Code = unknown[Code]("code", why)
		p.note("process: %s", why)
		return p, nil
	case started.After(connectedAt):
		proc.StartTime, proc.Recycled = started, true
		why := fmt.Sprintf("the socket now points at a process that started at %s, after this connection existed at %s; it is not the peer that connected",
			started.Format(time.RFC3339Nano), connectedAt.Format(time.RFC3339Nano))
		p.Process = attr("process", proc, ProofPID, why)
		p.Path = unknown[string]("path", why)
		p.Package = unknown[string]("package", why)
		p.Code = unknown[Code]("code", why)
		p.note("process: %s", why)
		return p, nil
	}
	proc.StartTime = started
	p.Process = attr("process", proc, ProofPID, whySocketBinding)

	// 4. The code signature, and the bundle identity that comes out of it.
	// This is the part macOS does better than anything on Windows: the
	// Security framework is asked about running code, not about a file.
	var signedPath string
	switch {
	case opts.skipCodeSignature():
		p.Code = unknown[Code]("code", "signature verification was skipped by the caller")
	default:
		code, verdict, ident, path, err := verifyAuditToken(token, opts)
		// Accepted code is worth the socket binding and no more, which is
		// the same cap ceiling() applies; a verdict below it is untouched.
		verdict = min(verdict, ProofPID)
		switch {
		case err != nil:
			p.Code = unknown[Code]("code", "verification could not be performed: "+err.Error())
			p.note("code: %v", err)
		case verdict < ProofPID:
			p.recordCode(code, verdict, "")
			p.Package = unknown[string]("package", "nothing is read out of a signature the platform did not accept ("+code.Status+")")
		default:
			signedPath = path
			p.recordCode(code, verdict, whySocketBinding+"; "+whyNoXPC)
			if ident != "" {
				p.Package = attr("package", ident, ProofPID,
					"the signing identifier out of the signature the OS validated; "+whySocketBinding)
			} else {
				p.Package = unknown[string]("package", "the peer's code has no signing identifier")
			}
		}
	}

	// 5. The path. Prefer the one the Security framework resolved from the
	// code object it verified; fall back to the kernel's exec record.
	switch {
	case signedPath != "":
		p.Path = attr("path", signedPath, ProofPID,
			"the path of the code object the signature was verified against; "+whySocketBinding)
	default:
		path, err := processExecPath(pid)
		if err != nil {
			p.Path = unknown[string]("path", "the executable path could not be read (kern.procargs2: "+err.Error()+")")
		} else {
			p.Path = attr("path", path, ProofPID,
				"the path the kernel recorded at exec; a path is a name, not an identity - see CONTRACT.md; "+whySocketBinding)
		}
	}

	// 6. Re-read the audit token. If the socket's owner moved while all of
	// the above was happening, everything above describes a process that is
	// no longer the one the socket points at, and none of it may stand.
	if again, err := peerAuditToken(fd); err != nil || again.pid() != token.pid() || again.pidversion() != token.pidversion() {
		why := "the socket's owner changed while it was being identified; every answer derived from it has been withdrawn"
		p.Process = unknown[Process]("process", why)
		p.Path = unknown[string]("path", why)
		p.Package = unknown[string]("package", why)
		p.Code = unknown[Code]("code", why)
		p.note("process: %s", why)
	}

	return p, nil
}

// requireAcceptedUnixSocket refuses anything that is not a connected AF_UNIX
// socket this process accepted.
//
// SO_ACCEPTCONN cannot be used for this on macOS. Measured on 15.7.4, it fails
// with ENOPROTOOPT on every AF_UNIX socket - listening, accepted and client
// alike - so a check written against it never fires. The discrimination is done
// with the two names instead, which were measured on the same machine:
//
//	                      getsockname      getpeername
//	listening socket      the bound path   ENOTCONN
//	accepted (peer live)  the bound path   unix:"" (empty)
//	accepted (peer gone)  the bound path   EINVAL
//	client end            unix:"" (empty)  the server's path
//
// Both halves matter. A listening socket has to be refused because answering
// about it authorises everything; the client end has to be refused because
// LOCAL_PEERCRED succeeds on it too - it describes the service, not a caller -
// and the previous check let it through.
func requireAcceptedUnixSocket(fd int) error {
	sa, err := unix.Getsockname(fd)
	if err != nil {
		return fmt.Errorf("%w: not a socket (getsockname: %v)", ErrUnsupportedConn, err)
	}
	local, ok := sa.(*unix.SockaddrUnix)
	if !ok {
		return fmt.Errorf("%w: this is not an AF_UNIX socket; peer credentials do not exist on it, and a loopback TCP peer has no verifiable identity at all", ErrUnsupportedConn)
	}
	peer, perr := unix.Getpeername(fd)
	switch {
	case perr == unix.ENOTCONN:
		// Never connected: a listening socket, or one that has not been
		// connected yet. Not something with a peer to describe.
		return fmt.Errorf("%w: this socket has no peer (getpeername: ENOTCONN); it is the listening socket or an unconnected one, and LOCAL_PEERCRED on it does not describe a caller", ErrNotServerEnd)
	case perr == nil:
		// The end that named nothing is the accepting end. If this fd's
		// own name is empty and the peer's is a path, this is the
		// client end of a connection this process made.
		if pu, ok := peer.(*unix.SockaddrUnix); ok && local.Name == "" && pu.Name != "" {
			return fmt.Errorf("%w: this is the client end of a connection this process made, not an accepted one; LOCAL_PEERCRED on it describes the listening service", ErrNotServerEnd)
		}
	}
	// perr == EINVAL is an accepted connection whose peer has gone. That is
	// a real case with a real answer (the connect-time credentials survive),
	// and it must not be refused here.
	return nil
}
