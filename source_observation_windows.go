//go:build windows && oa_source_probe

package identity

import (
	"context"
	"errors"
	"net"
	"sync"

	"golang.org/x/sys/windows"
)

// SourceProcessObservation is diagnostic process data for source-owned probes.
// It is absent from ordinary builds and supplies no Peer, caller binding,
// transport provenance, signature verdict or authorization evidence.
type SourceProcessObservation struct {
	Process   Process
	ImagePath string
	Account   string
	mu        sync.Mutex
	ctx       context.Context
	pin       binder
}

// OpenSourceProcessObservation uses expected only to locate a kernel process handle.
// The held handle must match the independently selected birth and account.
// The caller owns Close and separately proves the image file's full identity
// and bytes; this observation never treats a path as file or caller identity.
func OpenSourceProcessObservation(ctx context.Context, expected Process, expectedAccount string) (*SourceProcessObservation, error) {
	if ctx == nil || expected.PID <= 0 || uint64(expected.PID) > 1<<32-1 || expected.StartTime.IsZero() || expected.Recycled || expectedAccount == "" {
		return nil, errors.New("identity source observation: exact process birth and account required")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	proc, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION|windows.SYNCHRONIZE, false, uint32(expected.PID))
	if err != nil {
		return nil, err
	}
	defer windows.CloseHandle(proc)
	started, err := processStartTime(proc)
	if err != nil {
		return nil, err
	}
	if !started.Equal(expected.StartTime) {
		return nil, ErrPeerMoved
	}
	u, err := serverPrincipal(proc)
	if err != nil {
		return nil, err
	}
	if u.SID != expectedAccount {
		return nil, ErrPeerMoved
	}
	image, err := processImagePath(proc)
	if err != nil {
		return nil, err
	}
	pin, err := retainWindowsProcess(proc, started, u.SID)
	if err != nil {
		return nil, err
	}
	observation := &SourceProcessObservation{Process: Process{PID: expected.PID, StartTime: started}, ImagePath: image, Account: u.SID, ctx: ctx, pin: pin}
	if err := observation.Recheck(); err != nil {
		observation.Close()
		return nil, err
	}
	return observation, nil
}

func (o *SourceProcessObservation) checkLocked() error {
	if o.pin == nil {
		return net.ErrClosed
	}
	if err := o.ctx.Err(); err != nil {
		return err
	}
	return o.pin.recheck()
}

// Recheck reuses the retained kernel handle, including its account and birth.
func (o *SourceProcessObservation) Recheck() error {
	if o == nil {
		return net.ErrClosed
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	if err := o.checkLocked(); err != nil {
		return err
	}
	live, err := o.pin.alive()
	if err != nil {
		return err
	}
	if !live {
		return ErrPeerGone
	}
	return nil
}

// Alive queries the existing process-handle liveness owner, including exit259.
func (o *SourceProcessObservation) Alive() (bool, error) {
	if o == nil {
		return false, net.ErrClosed
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	if err := o.checkLocked(); err != nil {
		return false, err
	}
	return o.pin.alive()
}

// Close joins no worker and releases exactly this observation's retained handle.
func (o *SourceProcessObservation) Close() error {
	if o == nil {
		return nil
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.pin == nil {
		return nil
	}
	err := o.pin.release()
	o.pin = nil
	return err
}
