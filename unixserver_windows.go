//go:build windows

package identity

import (
	"errors"
	"fmt"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// sioAFUnixGetPeerPID is SIO_AF_UNIX_GETPEERPID, _WSAIOR(IOC_VENDOR, 256)
// in afunix.h of the Windows SDK 10.0.26100.0: it returns the ULONG process
// id the kernel recorded for the other end of a connected AF_UNIX socket.
const sioAFUnixGetPeerPID = 0x40000000 | 0x18000000 | 256

// unixPeerPID asks the kernel for the process id of the other end of a
// connected AF_UNIX socket.
func unixPeerPID(s windows.Handle) (uint32, error) {
	var pid, returned uint32
	if err := windows.WSAIoctl(s, sioAFUnixGetPeerPID, nil, 0, (*byte)(unsafe.Pointer(&pid)), uint32(unsafe.Sizeof(pid)), &returned, nil, 0); err != nil {
		return 0, err
	}
	// afunix.sys fills the ULONG and reports zero bytes returned, measured on
	// Windows 11 26200; a process id of zero is no answer.
	if pid == 0 {
		return 0, fmt.Errorf("SIO_AF_UNIX_GETPEERPID named no process (%d bytes returned)", returned)
	}
	return pid, nil
}

// unixServerWindowsBinding pins the process the kernel names for the server
// end of a dialed AF_UNIX socket.
type unixServerWindowsBinding struct {
	socket  windows.Handle
	proc    windows.Handle
	pid     uint32
	started time.Time
}

func bindUnixServer(h Handle, opts *Options) (binder, *Peer, error) {
	socket := windows.Handle(h)
	pid, err := unixPeerPID(socket)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: SIO_AF_UNIX_GETPEERPID: %v", ErrUnsupportedConn, err)
	}
	if pid == 0 {
		return nil, nil, fmt.Errorf("%w: the kernel names no process for the socket's server", ErrNoBinding)
	}
	proc, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: pid %d could not be opened (%v)", ErrPeerGone, pid, err)
	}
	b := &unixServerWindowsBinding{socket: socket, proc: proc, pid: pid}
	if b.started, err = processStartTime(proc); err != nil {
		//unchecked: best-effort handle release on an error path that already returns the processStartTime failure
		b.release()
		return nil, nil, fmt.Errorf("%w: the server's start time could not be read: %v", ErrNoBinding, err)
	}
	if connectedAt := opts.connectedAt(); b.started.After(connectedAt) {
		//unchecked: best-effort handle release on an error path that already returns the start-time mismatch
		b.release()
		return nil, nil, fmt.Errorf("%w: pid %d belongs to a process created at %s, after this connection existed at %s",
			ErrPeerMoved, pid, b.started.Format(time.RFC3339Nano), connectedAt.Format(time.RFC3339Nano))
	}
	// The kernel is asked again with the process pinned, so the pid it named
	// cannot have been reassigned between the two reads.
	if err := b.recheck(); err != nil {
		//unchecked: best-effort handle release on an error path that already returns the recheck failure
		b.release()
		return nil, nil, err
	}
	peer, err := pinnedProcessPeer(proc, pid, b.started, string(TransportUnix),
		"read from the access token of the socket server's process, through a handle that cannot be a recycled pid",
		"SIO_AF_UNIX_GETPEERPID names the process the kernel recorded for the socket's server end; its handle is pinned and its creation time predates the connection",
		"transport: a dialed AF_UNIX socket; the server's process id came from SIO_AF_UNIX_GETPEERPID", opts)
	if err != nil {
		//unchecked: best-effort handle release on an error path that already returns the peer lookup failure
		b.release()
		return nil, nil, err
	}
	return b, peer, nil
}

// disconnected reports an error of a socket that is closed or no longer
// connected. The kernel keeps naming the server's process id after the
// server exits (measured on Windows 11 26200); the ioctl fails only once
// the socket itself is gone.
func disconnected(err error) bool {
	return errors.Is(err, windows.WSAENOTSOCK) || errors.Is(err, windows.WSAENOTCONN) ||
		errors.Is(err, windows.WSAECONNRESET) || errors.Is(err, windows.WSAECONNABORTED) ||
		errors.Is(err, windows.WSAESHUTDOWN)
}

func (b *unixServerWindowsBinding) recheck() error {
	// A socket that is closed or disconnected contradicts nothing about who
	// served it. Any other failure to ask is no answer, and refuses.
	pid, err := unixPeerPID(b.socket)
	if err != nil {
		if disconnected(err) {
			return nil
		}
		return fmt.Errorf("%w: SIO_AF_UNIX_GETPEERPID: %v", ErrNoBinding, err)
	}
	if pid != b.pid {
		return fmt.Errorf("%w: the kernel now names pid %d for the socket's server; it named pid %d at the dial", ErrPeerMoved, pid, b.pid)
	}
	if started, err := processStartTime(b.proc); err == nil && !started.Equal(b.started) {
		return fmt.Errorf("%w: pid %d was created at %s and is now reported as created at %s", ErrPeerMoved, b.pid, b.started.Format(time.RFC3339Nano), started.Format(time.RFC3339Nano))
	}
	return nil
}

func (b *unixServerWindowsBinding) alive() (bool, error) {
	var code uint32
	if err := windows.GetExitCodeProcess(b.proc, &code); err != nil {
		return false, err
	}
	return code == stillActive, nil
}

func (b *unixServerWindowsBinding) release() error {
	if b.proc == 0 {
		return nil
	}
	err := windows.CloseHandle(b.proc)
	b.proc = 0
	return err
}

// pinnedProcessPeer reads a peer through a pinned process handle whose
// creation time the caller already compared with the connection: user from
// the primary token, path and package through the handle, and code from the
// image file unless the caller skipped it. Each reaches ProofBound at most.
func pinnedProcessPeer(proc windows.Handle, pid uint32, started time.Time, transport, userWhy, processWhy, note string, opts *Options) (*Peer, error) {
	p := &Peer{
		Platform:   "windows",
		Transport:  transport,
		ObservedAt: time.Now(),
		Package:    unknown[string]("package", "not resolved"),
		Code:       unknown[Code]("code", "not resolved"),
	}
	user, why, err := processUser(proc)
	if err != nil {
		return nil, fmt.Errorf("%w: the process token could not be read: %v", ErrNoBinding, err)
	}
	p.User = attr("user", user, ProofBound, joinWhy(userWhy, why))
	p.Process = attr("process", Process{PID: int(pid), StartTime: started}, ProofBound, processWhy)
	imagePath, err := processImagePath(proc)
	if err != nil {
		return nil, fmt.Errorf("%w: QueryFullProcessImageName: %v", ErrNoBinding, err)
	}
	p.Path = attr("path", imagePath, ProofBound, "read through the pinned process handle; a path is not an identity - see CONTRACT.md")
	if name, err := packageFullName(proc); err == nil && name != "" {
		p.Package = attr("package", name, ProofSigned, "an MSIX package full name read through the pinned process handle")
	} else {
		p.Package = unknown[string]("package", "the peer is an ordinary executable, not an MSIX package")
	}
	if opts.skipCodeSignature() {
		p.Code = unknown[Code]("code", "signature verification was skipped by the caller")
	} else if code, verdict, verifiedAt, err := verifyProcessImageAt(proc, pid, started, imagePath, opts); err != nil {
		p.Code = unknown[Code]("code", "verification could not be performed: "+err.Error())
	} else {
		p.recordCode(code, verdict, "Authenticode verified the file at the peer's image path, not the image the peer is executing")
		p.evidenceValidUntil = verifiedAt.Add(codeVerdictLifetime)
	}
	p.note("%s", note)
	return p, nil
}
