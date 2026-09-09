//go:build windows

package identity

import (
	"fmt"
	"time"

	"golang.org/x/sys/windows"
)

// Windows is the platform where this actually works, and it is worth saying
// why rather than only that.
//
// Two facts combine. The kernel writes the client's process id onto the pipe
// instance when the client opens it, so the number never follows a later
// writer the way macOS's so_last_pid does - handing the pipe handle to another
// process does not change the answer. And a Windows process cannot replace its
// own image: there is no execve, so the program behind that number is fixed for
// the process's whole life. The only remaining question is pid reuse, and an
// open process handle settles it: the kernel will not reassign a pid while a
// handle to the process object exists. Hold the handle from accept and there is
// no window left.
//
// That is why the attack in bind_attack_windows_test.go cannot be built here
// rather than merely failing. The test asserts the two facts it rests on, so a
// future Windows that breaks either one breaks the test rather than the
// service.

type windowsBinding struct {
	pipe    windows.Handle
	proc    windows.Handle
	pid     uint32
	started time.Time
}

func bindHandle(h Handle, opts *Options) (binder, *Peer, error) {
	pipe := windows.Handle(h)

	var flags, out, in, maxInst uint32
	if err := windows.GetNamedPipeInfo(pipe, &flags, &out, &in, &maxInst); err != nil {
		return nil, nil, fmt.Errorf("%w: GetNamedPipeInfo: %v", ErrUnsupportedConn, err)
	}
	if flags&windows.PIPE_SERVER_END == 0 {
		return nil, nil, ErrNotServerEnd
	}
	if err := requireLocalPeer(pipe); err != nil {
		return nil, nil, err
	}

	var pid uint32
	if err := windows.GetNamedPipeClientProcessId(pipe, &pid); err != nil {
		return nil, nil, fmt.Errorf("%w: GetNamedPipeClientProcessId: %v", ErrNoBinding, err)
	}

	proc, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: pid %d could not be opened (%v); it exited before it could be pinned", ErrPeerGone, pid, err)
	}

	b := &windowsBinding{pipe: pipe, proc: proc, pid: pid}
	if b.started, err = processStartTime(proc); err != nil {
		b.release()
		return nil, nil, fmt.Errorf("%w: the peer's creation time could not be read: %v", ErrNoBinding, err)
	}
	if connectedAt := opts.connectedAt(); b.started.After(connectedAt) {
		b.release()
		return nil, nil, fmt.Errorf("%w: pid %d belongs to a process created at %s, after this connection existed at %s",
			ErrPeerMoved, pid, b.started.Format(time.RFC3339Nano), connectedAt.Format(time.RFC3339Nano))
	}

	// The handle is open across this call, so ofHandle's own OpenProcess
	// cannot reach a different process than the one pinned above.
	peer, err := ofHandle(h, opts)
	if err != nil {
		b.release()
		return nil, nil, err
	}
	return b, peer, nil
}

func (b *windowsBinding) recheck() error {
	// Only a contradiction may refuse. A call that simply fails - the client
	// has closed its end, so the pipe no longer answers - leaves the capture
	// standing, because nothing has disputed it.
	var pid uint32
	if err := windows.GetNamedPipeClientProcessId(b.pipe, &pid); err == nil && pid != b.pid {
		return fmt.Errorf("%w: the pipe now names pid %d; it named pid %d when it was accepted", ErrPeerMoved, pid, b.pid)
	}
	// Asked of the held handle, not of the pid. It answers about the pinned
	// process even after that process exits, which is the point of holding
	// it: a pid lookup here could reach a successor.
	if started, err := processStartTime(b.proc); err == nil && !started.Equal(b.started) {
		return fmt.Errorf("%w: pid %d was created at %s and is now reported as created at %s",
			ErrPeerMoved, b.pid, b.started.Format(time.RFC3339Nano), started.Format(time.RFC3339Nano))
	}
	return nil
}

func (b *windowsBinding) alive() (bool, error) {
	var code uint32
	if err := windows.GetExitCodeProcess(b.proc, &code); err != nil {
		return false, err
	}
	return code == stillActive, nil
}

func (b *windowsBinding) release() error {
	if b.proc == 0 {
		return nil
	}
	err := windows.CloseHandle(b.proc)
	b.proc = 0
	return err
}

const stillActive = 259
