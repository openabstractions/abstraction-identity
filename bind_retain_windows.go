package identity

import (
	"fmt"
	"time"

	"golang.org/x/sys/windows"
)

// windowsProcessPin owns only a process handle. A retired pipe/socket handle
// can be reused without becoming evidence for this pin.
type windowsProcessPin struct {
	proc    windows.Handle
	started time.Time
	sid     string
}

func retainWindowsProcess(proc windows.Handle, started time.Time, sid string) (binder, error) {
	var duplicate windows.Handle
	current := windows.CurrentProcess()
	if err := windows.DuplicateHandle(current, proc, current, &duplicate, 0, false, windows.DUPLICATE_SAME_ACCESS); err != nil {
		return nil, err
	}
	return &windowsProcessPin{proc: duplicate, started: started, sid: sid}, nil
}

func (b *windowsProcessPin) recheck() error {
	started, err := processStartTime(b.proc)
	if err != nil {
		return err
	}
	if !started.Equal(b.started) {
		return ErrPeerMoved
	}
	if b.sid != "" {
		u, err := serverPrincipal(b.proc)
		if err != nil {
			return err
		}
		if u.SID != b.sid {
			return ErrPeerMoved
		}
	}
	return nil
}

func (b *windowsProcessPin) alive() (bool, error) {
	return windowsProcessAlive(b.proc)
}

// Process objects become signaled at exit, including exit code STILL_ACTIVE
// (259). An exit-code comparison cannot answer liveness. Every capturing
// adapter opens SYNCHRONIZE and duplicates preserve that held-handle right.
func windowsProcessAlive(proc windows.Handle) (bool, error) {
	state, err := windows.WaitForSingleObject(proc, 0)
	if err != nil {
		return false, err
	}
	switch state {
	case windows.WAIT_OBJECT_0:
		return false, nil
	case uint32(windows.WAIT_TIMEOUT):
		return true, nil
	default:
		return false, fmt.Errorf("%w: unexpected process wait state %d", ErrNoBinding, state)
	}
}

func (b *windowsProcessPin) release() error { return windows.CloseHandle(b.proc) }
func (b *windowsProcessPin) retainProcess() (binder, error) {
	return retainWindowsProcess(b.proc, b.started, b.sid)
}
func (b *windowsBinding) retainProcess() (binder, error) {
	return retainWindowsProcess(b.proc, b.started, "")
}
func (b *windowsServerBinding) retainProcess() (binder, error) {
	return retainWindowsProcess(b.proc, b.started, b.sid)
}
func (b *loopbackWindowsBinding) retainProcess() (binder, error) {
	return retainWindowsProcess(b.proc, b.started, "")
}
func (b *unixServerWindowsBinding) retainProcess() (binder, error) {
	return retainWindowsProcess(b.proc, b.started, "")
}
