//go:build windows

package identity

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"golang.org/x/sys/windows"
)

func ceiling() Limits {
	return Limits{
		Platform:  "windows",
		Transport: "npipe",
		Bindable:  true,
		Binding:   "an open process handle. The kernel writes the client's process id onto the pipe instance when the client opens it, so it never follows a later writer; a Windows process cannot replace its own image, so the program behind that id is fixed for its whole life; and while a handle to the process object is open the id cannot be reassigned. Bind holds one from accept, which leaves no window",
		Stronger:  "",
		Best: Need{
			User:    ProofKernel,
			Process: ProofKernel,
			Path:    ProofBound,
			Package: ProofSigned,
			Code:    ProofBound,
		},
		Why: map[string]string{
			"user":    "the token behind ImpersonateNamedPipeClient is the kernel's own record of the connecting thread's principal",
			"process": "the kernel records the client's process id on the pipe instance when the client opens it",
			"path":    "the image path is read through a process handle whose creation time predates the connection, which excludes pid reuse; it is still only a name the kernel keeps, not a statement about the code that is running",
			"package": "an MSIX package full name encodes the publisher identity from the certificate Windows validated when it installed the package, and no unpackaged process can be given one",
			"code":    "Authenticode verifies a file, and Windows exposes no way to verify the image mapping a running process is actually executing; see CONTRACT.md",
		},
	}
}

func ofHandle(h Handle, opts *Options) (*Peer, error) {
	pipe := windows.Handle(h)
	connectedAt := opts.connectedAt()

	p := &Peer{
		Platform:   "windows",
		Transport:  "npipe",
		ObservedAt: time.Now(),
		User:       unknown[User]("user", "not resolved"),
		Process:    unknown[Process]("process", "not resolved"),
		Path:       unknown[string]("path", "not resolved"),
		Package:    unknown[string]("package", "not resolved"),
		Code:       unknown[Code]("code", "not resolved"),
	}

	// 1. This must be the server end of a named pipe. On the client end
	// every question below has an answer, and every answer is about the
	// service itself.
	var flags, out, in, maxInst uint32
	if err := windows.GetNamedPipeInfo(pipe, &flags, &out, &in, &maxInst); err != nil {
		return nil, fmt.Errorf("%w: GetNamedPipeInfo: %v", ErrUnsupportedConn, err)
	}
	if flags&windows.PIPE_SERVER_END == 0 {
		return nil, ErrNotServerEnd
	}

	// 2. A named pipe is reachable over SMB unless the server passed
	// PIPE_REJECT_REMOTE_CLIENTS. A remote peer has no pid on this machine,
	// and its token is a network logon that says nothing about which program
	// is running. Refuse before any of that can be mistaken for an answer.
	if err := requireLocalPeer(pipe); err != nil {
		return nil, err
	}

	// 3. The user, from the kernel, via a token that is dropped immediately.
	user, why, err := peerUser(pipe)
	switch {
	case err == nil:
		p.User = attr("user", user, ProofKernel, why)
		if why != "" {
			p.note("user: %s", why)
		}
	case errors.Is(err, errAnonymousClient):
		p.User = unknown[User]("user", errAnonymousClient.Error())
		p.note("user: %s", errAnonymousClient.Error())
	case errors.Is(err, ErrImpersonationStuck):
		// Never report an identity when the token could not be dropped.
		return nil, err
	default:
		return nil, err
	}

	// 4. The pid, from the kernel. The number is not a guess: Windows wrote
	// it onto the pipe instance when the client opened it. What the number
	// refers to *now* is a different question, handled next.
	var pid uint32
	if err := windows.GetNamedPipeClientProcessId(pipe, &pid); err != nil {
		p.Process = unknown[Process]("process", "GetNamedPipeClientProcessId failed: "+err.Error())
		p.note("process: the kernel would not name the client process (%v)", err)
		return p, nil
	}

	// 5. Pin the process, and refuse to read anything out of the pid unless
	// the process behind it was already running when the connection was
	// made. A process that inherited a recycled pid must have been created
	// after the connection existed, so this excludes all of them. The handle
	// stays open for the rest of the function: while it is held the pid
	// cannot be reassigned, so every later question is asked of the same
	// process.
	proc, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		// Most often the peer has already exited. The pid is still a fact
		// about the connection; nothing may be read out of it.
		p.Process = attr("process", Process{PID: int(pid)}, ProofKernel,
			"the process could not be opened ("+err.Error()+"), so it could not be checked for pid reuse and nothing was read out of the pid")
		p.note("process: pid %d could not be opened (%v); path, package and code are unavailable", pid, err)
		p.Path = unknown[string]("path", "the peer process was gone before it could be pinned")
		p.Package = unknown[string]("package", "the peer process was gone before it could be pinned")
		p.Code = unknown[Code]("code", "the peer process was gone before it could be pinned")
		return p, nil
	}
	defer windows.CloseHandle(proc)

	started, err := processStartTime(proc)
	if err != nil {
		p.Process = attr("process", Process{PID: int(pid)}, ProofKernel,
			"the process start time could not be read ("+err.Error()+"), so pid reuse could not be excluded")
		p.note("process: could not read the start time of pid %d (%v); path, package and code are unavailable", pid, err)
		p.Path = unknown[string]("path", "pid reuse could not be excluded")
		p.Package = unknown[string]("package", "pid reuse could not be excluded")
		p.Code = unknown[Code]("code", "pid reuse could not be excluded")
		return p, nil
	}

	if started.After(connectedAt) {
		reused := fmt.Sprintf("pid %d now belongs to a process created at %s, after this connection existed at %s; it is not the peer",
			pid, started.Format(time.RFC3339Nano), connectedAt.Format(time.RFC3339Nano))
		p.Process = attr("process", Process{PID: int(pid), StartTime: started, Recycled: true}, ProofKernel, reused)
		p.note("process: %s", reused)
		p.Path = unknown[string]("path", reused)
		p.Package = unknown[string]("package", reused)
		p.Code = unknown[Code]("code", reused)
		return p, nil
	}

	p.Process = attr("process", Process{PID: int(pid), StartTime: started}, ProofKernel,
		"the pid came from the kernel's record of this pipe instance; the start time predates the connection, so it is not a recycled pid")

	// 6. Everything from here is read through the pinned handle: bound to
	// the right process, but still only the operating system's bookkeeping.
	imagePath, err := processImagePath(proc)
	if err != nil {
		p.Path = unknown[string]("path", "QueryFullProcessImageName failed: "+err.Error())
		p.note("path: %v", err)
	} else {
		p.Path = attr("path", imagePath, ProofBound,
			"read through a process handle that cannot be a recycled pid; a path is not an identity - see CONTRACT.md")
	}

	// 7. Package identity, where there is one. This is the only Windows
	// answer that comes out of a signature the OS itself validated.
	if name, err := packageFullName(proc); err != nil {
		p.Package = unknown[string]("package", "GetPackageFullName failed: "+err.Error())
	} else if name == "" {
		p.Package = unknown[string]("package", "the peer is an ordinary executable, not an MSIX package; Windows has no package identity to give")
	} else {
		p.Package = attr("package", name, ProofSigned,
			"an MSIX package full name; its publisher hash comes from the certificate Windows validated when the package was installed")
	}

	// 8. Authenticode. Deliberately last, because it is the slowest and the
	// weakest of the strong-looking answers.
	switch {
	case opts.skipCodeSignature():
		p.Code = unknown[Code]("code", "signature verification was skipped by the caller")
	case !p.Path.Known():
		p.Code = unknown[Code]("code", "there is no image path to verify")
	default:
		code, why, err := verifyImage(proc, imagePath, opts)
		if err != nil {
			p.Code = unknown[Code]("code", "verification failed: "+err.Error())
			p.note("code: %v", err)
			break
		}
		bound := "Authenticode verified the file at the peer's image path, not the image the peer is executing; Windows cannot verify the latter"
		p.Code = attr("code", code, ProofBound, joinWhy(why, bound))
		if !code.Trusted {
			p.note("code: %s", code.Status)
		}
	}

	return p, nil
}

// requireLocalPeer refuses a client that is not on this machine.
func requireLocalPeer(pipe windows.Handle) error {
	client, err := namedPipeClientComputerName(pipe)
	if err != nil {
		// Old builds and some pipe configurations will not answer. The
		// pid check that follows is the backstop: a remote client has no
		// local pid and OpenProcess will fail or name a different
		// process, which is caught by the start-time check.
		return nil
	}
	local, err := windows.ComputerName()
	if err != nil {
		return nil
	}
	if !strings.EqualFold(client, local) {
		return fmt.Errorf("%w: the client is on %q, not %q", ErrRemotePeer, client, local)
	}
	return nil
}

func processStartTime(proc windows.Handle) (time.Time, error) {
	var creation, exit, kernel, user windows.Filetime
	if err := windows.GetProcessTimes(proc, &creation, &exit, &kernel, &user); err != nil {
		return time.Time{}, err
	}
	return time.Unix(0, creation.Nanoseconds()), nil
}

func processImagePath(proc windows.Handle) (string, error) {
	buf := make([]uint16, windows.MAX_LONG_PATH)
	n := uint32(len(buf))
	if err := windows.QueryFullProcessImageName(proc, 0, &buf[0], &n); err != nil {
		return "", err
	}
	return windows.UTF16ToString(buf[:n]), nil
}
