//go:build darwin && cgo

package identity

/*
#cgo LDFLAGS: -framework CoreFoundation -framework Security -lbsm
#include "started_process_native.h"
*/
import "C"

import (
	"fmt"
	"net"
	"os"
	"runtime"
	"syscall"
	"time"
)

type startedDarwinBinding struct{ native *C.oa_started_process }

func startedProcessError(status C.oa_xpc_status, detail C.int32_t) error {
	if status == C.OA_XPC_OK {
		return nil
	}
	if status == C.OA_XPC_OCCURRENCE_ENDED {
		return ErrPeerGone
	}
	if status == C.OA_XPC_SYSTEM {
		return fmt.Errorf("%w: started occurrence native status %d", ErrNotProven, int32(detail))
	}
	return xpcError(status)
}

func bindStartedProcess(process *os.Process) (binder, *Peer, error) {
	if process == nil || process.Pid <= 0 || uint64(process.Pid) > uint64(1<<31-1) {
		return nil, nil, ErrNoBinding
	}
	if err := process.Signal(syscall.Signal(0)); err != nil {
		return nil, nil, fmt.Errorf("%w: %v", ErrPeerGone, err)
	}
	var native *C.oa_started_process
	var info C.oa_started_identity
	var detail C.int32_t
	status := C.oa_started_process_create(C.int32_t(process.Pid), &native, &info, &detail)
	runtime.KeepAlive(process)
	if err := startedProcessError(status, detail); err != nil {
		return nil, nil, err
	}
	if info.generation == 0 || info.audit_session == 0 {
		C.oa_started_process_free(native)
		return nil, nil, ErrNotProven
	}
	note := "caller-owned child task-name right and kernel audit token; occurrence ends on exec or exit"
	peer := &Peer{Platform: "darwin", ObservedAt: time.Now(), Notes: []string{note}}
	peer.User = attr("user", User{Kind: "posix", UID: int(info.uid), GID: int(info.gid), AuditSessionID: uint32(info.audit_session)}, ProofKernel, note)
	peer.Process = attr("process", Process{PID: int(info.pid), Generation: uint32(info.generation)}, ProofBound, note)
	peer.Path = attr("path", C.GoString(&info.path[0]), ProofBound, "main executable of the token-selected dynamic code")
	peer.Package = unknown[string]("package", "started occurrence does not authenticate a package")
	peer.Code = unknown[Code]("code", "platform trust requires sealed-resource generation verification")
	return &startedDarwinBinding{native}, peer, nil
}

func (p *startedDarwinBinding) status() (C.oa_xpc_status, C.int32_t) {
	var detail C.int32_t
	status := C.oa_started_process_check(p.native, &detail)
	return status, detail
}
func (p *startedDarwinBinding) recheck() error {
	status, detail := p.status()
	if status == C.OA_XPC_OCCURRENCE_ENDED {
		return nil // Historical capture remains true; active use also requires Alive.
	}
	return startedProcessError(status, detail)
}
func (p *startedDarwinBinding) alive() (bool, error) {
	status, detail := p.status()
	if status == C.OA_XPC_OCCURRENCE_ENDED {
		return false, nil
	}
	err := startedProcessError(status, detail)
	return err == nil, err
}
func (p *startedDarwinBinding) release() error {
	C.oa_started_process_free(p.native)
	p.native = nil
	return nil
}
func (p *startedDarwinBinding) retainProcess() (binder, error) {
	var native *C.oa_started_process
	var detail C.int32_t
	status := C.oa_started_process_retain(p.native, &native, &detail)
	if err := startedProcessError(status, detail); err != nil {
		return nil, err
	}
	return &startedDarwinBinding{native}, nil
}

// The resource and binding owners hold their locks through this operation.
// Request acquisition adds its close barrier after those two owners.
func (p *startedDarwinBinding) matchStarted(resource sealedResourceNative, request *XPCRequest) (Code, Proof, error) {
	var code C.SecCodeRef
	var detail C.int32_t
	var status C.oa_xpc_status
	var nativeRequest *C.oa_xpc_request
	if request != nil {
		var acquired bool
		nativeRequest, acquired = request.acquire()
		if !acquired {
			return Code{}, ProofUnmet, net.ErrClosed
		}
		defer request.calls.Done()
		status = C.oa_started_process_request_code(p.native, nativeRequest, &code, &detail)
	} else {
		status = C.oa_started_process_code(p.native, &code, &detail)
	}
	if err := startedProcessError(status, detail); err != nil {
		return Code{}, ProofUnmet, err
	}
	defer C.CFRelease(C.CFTypeRef(code))
	e, ok := resource.(*sealedDarwinResource)
	if !ok || e.native == nil {
		return Code{}, ProofUnmet, ErrNotProven
	}
	var index C.size_t
	if detail = C.oa_sealed_resource_match_code(e.native, code, &index); detail != 0 {
		return Code{}, ProofUnmet, sealedResourceFailure(detail)
	}
	status, detail = p.status()
	if err := startedProcessError(status, detail); err != nil {
		return Code{}, ProofUnmet, err
	}
	if nativeRequest != nil && C.oa_xpc_request_active(nativeRequest) == 0 {
		return Code{}, ProofUnmet, net.ErrClosed
	}
	runtime.KeepAlive(request)
	return e.code(index)
}
