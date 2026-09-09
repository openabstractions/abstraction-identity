//go:build linux

package identity

// Linux, over AF_UNIX.
//
// The kernel stamps three things onto a unix socket when the peer connects, and
// they are the only unforgeable answers on this platform:
//
//   - SO_PEERCRED - uid, gid and pid, as they were at connect(2). ProofKernel.
//   - SO_PEERSEC  - the LSM label the peer had at connect: an SELinux context or
//     an AppArmor profile. Also ProofKernel, and reported as part of the
//     principal rather than as a separate attribute, because that is what it
//     is: a label the kernel applies to a subject.
//   - SO_PEERPIDFD (Linux 6.5) - a pidfd for the peer, obtained by the kernel
//     rather than by looking a number up afterwards.
//
// Everything else - the image path, the sandbox application id - is read out of
// /proc after the fact and is therefore a question asked about a *number*. That
// is racy by construction: the peer may be gone and its pid reused. The pidfd
// is what closes it, so this file has two modes, and the difference is visible
// in the Proof rather than hidden:
//
//	with SO_PEERPIDFD:    path ProofBound,  package ProofBound
//	without SO_PEERPIDFD: path ProofPID,    package ProofPID
//
// There is no per-connection code signature verification for ordinary ELF
// binaries anywhere in this picture, so Code is ProofNone on Linux, always. See
// CONTRACT.md.

import (
	"fmt"
	"sync"
	"time"

	"golang.org/x/sys/unix"
)

const (
	whyPeerCred = "uid and gid are the credentials the kernel recorded for the peer at connect(2); the peer never spoke them and cannot influence them"

	whyPidKernel = "the pid is the one the kernel recorded at connect(2); the number is a fact about the connection, but what it refers to now is a separate question - see path"

	whyPidfdBound = "read from /proc through a pid held open by the pidfd the kernel handed out for this connection, so the number cannot have been reassigned to a different process"

	whyNoPidfd = "read from /proc by pid, after the fact: this kernel has no SO_PEERPIDFD (Linux 6.5) to pin the process, so a pid reused between connect and now would answer instead"

	whyNoCode = "Linux has no per-connection code signature verification for ordinary ELF binaries; IMA and dm-verity are not queryable this way, and this is not expected to change"

	whyPackageAdvisory = "a sandbox application id is advisory: it is read from the peer's own mount namespace (Flatpak) or from a cgroup name (Snap), and neither is beyond the reach of a hostile process running as the same user - see CONTRACT.md"
)

// pidfdSupport probes, once, whether this kernel implements SO_PEERPIDFD. The
// probe is a socketpair rather than a version string: a kernel that claims 6.5
// but has the option compiled out, or a seccomp filter in the way, would make a
// version comparison lie in the dangerous direction.
var pidfdSupport = sync.OnceValues(func() (bool, string) {
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return false, "could not probe for SO_PEERPIDFD (socketpair: " + err.Error() + ")"
	}
	defer unix.Close(fds[0])
	defer unix.Close(fds[1])

	fd, err := unix.GetsockoptInt(fds[0], unix.SOL_SOCKET, unix.SO_PEERPIDFD)
	if err != nil {
		return false, "SO_PEERPIDFD is unavailable on this kernel (" + err.Error() + "); it needs Linux 6.5, and without it nothing read from /proc can be pinned to the process that connected"
	}
	unix.Close(fd)
	return true, ""
})

// lsmSupport probes, once, whether SO_PEERSEC returns a label worth reporting.
// A kernel with no LSM loaded answers "unlabeled"; AppArmor with no profile
// answers "unconfined". Both are the absence of an answer, not an answer.
var lsmSupport = sync.OnceValues(func() (bool, string) {
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return false, "could not probe for SO_PEERSEC (socketpair: " + err.Error() + ")"
	}
	defer unix.Close(fds[0])
	defer unix.Close(fds[1])

	ctx, err := unix.GetsockoptString(fds[0], unix.SOL_SOCKET, unix.SO_PEERSEC)
	if err != nil {
		return false, "SO_PEERSEC is unavailable on this kernel (" + err.Error() + ")"
	}
	if !meaningfulLSMLabel(ctx) {
		return false, "no LSM is labelling processes on this system (SO_PEERSEC answers " + strconvQuote(ctx) + ")"
	}
	return true, ""
})

func ceiling() Limits {
	pidfd, pidfdWhy := pidfdSupport()
	lsm, lsmWhy := lsmSupport()

	derived := ProofPID
	derivedWhy := whyNoPidfd + " (" + pidfdWhy + ")"
	if pidfd {
		derived = ProofBound
		derivedWhy = whyPidfdBound
	}

	userWhy := whyPeerCred
	if lsm {
		userWhy += "; SO_PEERSEC also carries the peer's LSM label, which is the closest Linux comes to naming a program rather than a file"
	} else {
		userWhy += "; " + lsmWhy + ", so User.SecurityContext will be empty"
	}

	binding := whyNoPidfd + " (" + pidfdWhy + "), so this machine cannot bind a peer: Bind refuses rather than answering from a number"
	if pidfd {
		binding = "SO_PEERPIDFD: the kernel derives a pidfd from the connection itself, so it names a process instance that cannot be reassigned and cannot follow a later writer. It does follow execve, which Bind captures the image path to refuse"
	}

	return Limits{
		Platform:  "linux",
		Transport: "unix",
		Bindable:  pidfd,
		Binding:   binding,
		Stronger:  "",
		Best: Need{
			User:    ProofKernel,
			Process: ProofKernel,
			Path:    derived,
			Package: derived,
			Code:    ProofNone,
		},
		Why: map[string]string{
			"user":    userWhy,
			"process": whyPidKernel,
			"path":    derivedWhy,
			"package": derivedWhy + "; " + whyPackageAdvisory,
			"code":    whyNoCode,
		},
	}
}

func ofHandle(h Handle, opts *Options) (*Peer, error) {
	fd := int(h)
	connectedAt := opts.connectedAt()

	p := &Peer{
		Platform:   "linux",
		Transport:  "unix",
		ObservedAt: time.Now(),
		User:       unknown[User]("user", "not resolved"),
		Process:    unknown[Process]("process", "not resolved"),
		Path:       unknown[string]("path", "not resolved"),
		Package:    unknown[string]("package", "not resolved"),
		Code:       unknown[Code]("code", whyNoCode),
	}

	// 1. The handle must be a connected AF_UNIX socket, and must be the
	// accepted end. SO_PEERCRED on a listening socket returns the
	// credentials captured at listen(2) - which are the service's own. A
	// service that identified itself and believed it had identified a caller
	// would authorise everything, so this is refused rather than answered.
	if err := requireAcceptedUnixSocket(fd); err != nil {
		return nil, err
	}

	// 2. SO_PEERCRED: the kernel's record of who connected. Not a lookup;
	// the credentials were copied into the socket at connect(2).
	ucred, err := unix.GetsockoptUcred(fd, unix.SOL_SOCKET, unix.SO_PEERCRED)
	if err != nil {
		return nil, fmt.Errorf("%w: SO_PEERCRED: %v", ErrUnsupportedConn, err)
	}
	if ucred.Pid == 0 {
		// Either the socket is not connected, or the peer lives in a pid
		// namespace this process cannot see into. In the second case uid
		// and gid may still be translated, but a peer whose pid is
		// invisible cannot be resolved any further, and reporting a
		// principal with no process attached invites exactly the mistake
		// this package exists to prevent.
		return nil, fmt.Errorf("%w: SO_PEERCRED reports pid 0: the socket is not connected, or the peer is in a pid namespace this process cannot see", ErrUnsupportedConn)
	}

	user := User{Kind: "posix", UID: int(ucred.Uid), GID: int(ucred.Gid)}
	userWhy := whyPeerCred

	// 3. SO_PEERSEC: the LSM label, also stamped at connect. It belongs to
	// the principal, so it rides on User at the same strength as uid.
	switch ctx, err := unix.GetsockoptString(fd, unix.SOL_SOCKET, unix.SO_PEERSEC); {
	case err != nil:
		userWhy += "; no LSM label (SO_PEERSEC: " + err.Error() + ")"
	case !meaningfulLSMLabel(ctx):
		userWhy += "; no LSM label (SO_PEERSEC answers " + strconvQuote(ctx) + ", which is the absence of a label)"
	default:
		user.SecurityContext = ctx
		userWhy += "; SecurityContext is the peer's LSM label as of connect(2), assigned by policy at exec and not by the peer"
	}
	p.User = attr("user", user, ProofKernel, userWhy)

	// 4. The pid, at ProofKernel, because the kernel wrote it down at
	// connect. What that number refers to now is decided next, and nothing
	// derived from it is reported at this strength.
	pid := int(ucred.Pid)
	proc := Process{PID: pid}

	// 5. Pin the process, if this kernel can. SO_PEERPIDFD returns a pidfd
	// the kernel derived from the connection itself, so there is no window
	// in which a number could be looked up wrongly. While the pidfd is open
	// the pid cannot be reassigned, which is what makes anything read out of
	// /proc/<pid> afterwards refer to the peer and not to a successor.
	var (
		bound      bool   // the pid is pinned by a pidfd: reads are ProofBound
		readable   = true // there is a live process worth reading /proc for
		derivedWhy string // why path and package come out at the strength they do
	)
	pidfd, pidfdErr := unix.GetsockoptInt(fd, unix.SOL_SOCKET, soPeerPIDFD)
	switch {
	case pidfdErr == nil:
		defer unix.Close(pidfd)
		live, err := pidfdAlive(pidfd, pid)
		switch {
		case err != nil:
			readable = false
			derivedWhy = "the pidfd the kernel gave for this connection could not be checked (" + err.Error() + "), so nothing was read out of the pid"
		case !live:
			readable = false
			derivedWhy = "the peer has exited: the pidfd for this connection no longer names a running process, so /proc has nothing left to say about it"
		default:
			bound = true
			derivedWhy = whyPidfdBound
		}
	default:
		derivedWhy = whyNoPidfd + " (SO_PEERPIDFD: " + pidfdErr.Error() + ")"
	}
	if !bound {
		p.note("process: %s", derivedWhy)
	}

	// 6. Start time, best effort, for the log line and for one refusal.
	//
	// This is NOT the Windows bound. There, a process handle yields a
	// creation FILETIME and the comparison against ConnectedAt is exact.
	// Here the start time comes out of /proc/<pid>/stat in USER_HZ ticks
	// since boot and has to be turned into a wall clock through /proc/uptime,
	// which is accurate to tens of milliseconds at the very best. A bound
	// that is approximately right is not a bound, so this never promotes a
	// proof. It is only ever allowed to refuse: a process that demonstrably
	// started well after the connection is not the peer, whatever the clock's
	// precision.
	//
	// And it is skipped entirely when a pidfd is holding the pid, because
	// there the reuse question is already answered exactly. Letting a fuzzy
	// clock conversion overrule a kernel-held pin could only ever produce a
	// false refusal.
	if started, err := processStartTime(pid); err == nil {
		proc.StartTime = started
		if !bound && started.After(connectedAt.Add(startTimeSlop)) {
			reused := fmt.Sprintf("pid %d now belongs to a process that started at %s, after this connection existed at %s; it is not the peer",
				pid, started.Format(time.RFC3339Nano), connectedAt.Format(time.RFC3339Nano))
			proc.Recycled = true
			p.Process = attr("process", proc, ProofKernel, reused)
			p.note("process: %s", reused)
			p.Path = unknown[string]("path", reused)
			p.Package = unknown[string]("package", reused)
			return p, nil
		}
	}

	processWhy := whyPidKernel
	if !bound {
		processWhy += "; " + derivedWhy
	}
	p.Process = attr("process", proc, ProofKernel, processWhy)

	if !readable {
		// The peer is gone, or the pidfd could not be checked. The pid
		// stays at ProofKernel - it is a fact about the connection - but
		// nothing is read out of it.
		p.Path = unknown[string]("path", derivedWhy)
		p.Package = unknown[string]("package", derivedWhy)
		return p, nil
	}

	derived := ProofPID
	if bound {
		derived = ProofBound
	}

	// 7. The image path. /proc/<pid>/exe is a link the kernel maintains, so
	// its content is not the peer's to choose - but the file it points at is.
	// A path is a name; see CONTRACT.md before writing a rule against one.
	switch link, deleted, err := processExe(pid); {
	case err != nil:
		p.Path = unknown[string]("path", "/proc/"+itoa(pid)+"/exe could not be read: "+err.Error())
		p.note("path: %v", err)
	case deleted:
		// The kernel appends " (deleted)" when the executable has been
		// unlinked since exec. Reporting the name without the marker
		// would be reporting a path that no longer refers to the file
		// the peer is running - which is the whole trick.
		why := "the peer's executable has been unlinked since it started, so this path no longer refers to the file it is running"
		p.Path = attr("path", link, ProofPID, why)
		p.note("path: %s", why)
	default:
		p.Path = attr("path", link, derived, derivedWhy+"; a path is a name, not an identity - see CONTRACT.md")
	}

	// 8. Sandbox application id, where there is one. This is the closest
	// Linux gets to "which program", and it is not close.
	name, why := sandboxPackage(pid)
	if name == "" {
		p.Package = unknown[string]("package", why)
	} else {
		p.Package = attr("package", name, derived, why+"; "+derivedWhy+"; "+whyPackageAdvisory)
		p.note("package: %s", whyPackageAdvisory)
	}

	// 9. Code. There is nothing to verify against.
	p.Code = unknown[Code]("code", whyNoCode)

	if bound {
		// The pidfd has been open across every read above, so the pid
		// could not have been reassigned under them. Confirm the process
		// did not exit mid-way, which would mean the later reads failed
		// rather than lied, and say so in the notes.
		if live, err := pidfdAlive(pidfd, pid); err == nil && !live {
			p.note("process: the peer exited while it was being identified; what was read before that is still about the right process")
		}
	}

	return p, nil
}

// startTimeSlop is the width of the /proc start-time conversion, and the reason
// that conversion may only ever refuse. See the comment at its use.
const startTimeSlop = 2 * time.Second

// requireAcceptedUnixSocket refuses anything that is not a connected AF_UNIX
// socket this process accepted.
func requireAcceptedUnixSocket(fd int) error {
	domain, err := unix.GetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_DOMAIN)
	if err != nil {
		return fmt.Errorf("%w: not a socket (SO_DOMAIN: %v)", ErrUnsupportedConn, err)
	}
	if domain != unix.AF_UNIX {
		return fmt.Errorf("%w: this is an AF_%s socket; peer credentials exist only on AF_UNIX, and a loopback TCP peer has no verifiable identity at all", ErrUnsupportedConn, domainName(domain))
	}
	if listening, err := unix.GetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_ACCEPTCONN); err == nil && listening != 0 {
		return fmt.Errorf("%w: this is the listening socket, not an accepted connection; SO_PEERCRED on it returns the credentials this service had at listen(2) - its own", ErrNotServerEnd)
	}
	return nil
}

func domainName(d int) string {
	switch d {
	case unix.AF_INET:
		return "INET"
	case unix.AF_INET6:
		return "INET6"
	case unix.AF_NETLINK:
		return "NETLINK"
	case unix.AF_VSOCK:
		return "VSOCK"
	}
	return itoa(d)
}

// meaningfulLSMLabel rejects the strings kernels use to say "no label".
//
// "kernel" is on the list because it is not a profile: it is the label tasks
// carry when AppArmor is compiled in but not enforcing policy, and it was
// observed on a stock WSL2 Ubuntu with apparmor disabled. A label that means
// "nothing is confining this process" must not be reported as if a policy had
// named the peer.
func meaningfulLSMLabel(s string) bool {
	switch s {
	case "", "kernel", "unlabeled", "unlabeled_t", "unconfined", "unconfined (enforce)", "unconfined (complain)":
		return false
	}
	return true
}

// soPeerPIDFD is the socket option asked for the peer's pidfd. It is a variable
// only so that a test can point it at an option this kernel does not have, and
// exercise the pre-6.5 path on a kernel that has it. Nothing else may write it.
var soPeerPIDFD = unix.SO_PEERPIDFD
