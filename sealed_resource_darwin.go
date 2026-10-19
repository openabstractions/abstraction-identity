//go:build darwin && cgo

package identity

/*
#cgo LDFLAGS: -framework CoreFoundation -framework Security
#include "sealed_resource_native.h"
#include <stdlib.h>
*/
import "C"

import (
	"context"
	"fmt"
	"io/fs"
	"net"
	"runtime"
	"strings"
	"unsafe"

	"github.com/openabstractions/abstraction-identity/fileid"
)

type sealedDarwinResource struct{ native *C.oa_sealed_resource }

func sealedResourceFailure(status C.int32_t) error {
	return fmt.Errorf("%w: sealed resource Security status %d", ErrNotProven, int32(status))
}

func sealedBundleAt(ctx context.Context, bundle fileid.Handle) error {
	h, err := fileid.Open(ctx, fileid.Self, bundle.FileID().Path(), fileid.Options{Links: fileid.RefuseLinks})
	if err != nil {
		return err
	}
	defer h.Close()
	if !h.FileID().Equal(bundle.FileID()) {
		return fmt.Errorf("%w: app bundle changed", ErrNotProven)
	}
	return nil
}

func verifySealedResource(ctx context.Context, bundle, program fileid.Handle, name string, limit int64) (*SealedResourceEvidence, Code, Proof, error) {
	fail := func(err error) (*SealedResourceEvidence, Code, Proof, error) { return nil, Code{}, ProofUnmet, err }
	data, err := captureSealedResource(ctx, bundle, program, name, limit)
	if err != nil {
		return fail(err)
	}
	if err = sealedBundleAt(ctx, bundle); err != nil {
		return fail(err)
	}
	rel, err := program.Relate(bundle)
	if err != nil {
		return fail(err)
	}
	parts := strings.Split(rel.Rel, "/")
	if len(parts) != 3 || parts[0] != "Contents" || parts[1] != "MacOS" {
		return fail(fmt.Errorf("%w: program is not bundle main code", ErrNotProven))
	}
	if err = fileid.SafeName(parts[2]); err != nil {
		return fail(err)
	}
	main, err := bundle.Beneath(rel.Rel, fileid.Options{Read: true})
	if err != nil {
		return fail(err)
	}
	defer main.Close()
	if !main.FileID().Equal(program.FileID()) {
		return fail(fmt.Errorf("%w: selected program changed", ErrNotProven))
	}
	stat, err := main.File().Stat()
	if err != nil {
		return fail(err)
	}
	if !stat.Mode().IsRegular() {
		return fail(fmt.Errorf("%w: program is not regular", fs.ErrInvalid))
	}
	arch, err := sealedResourceArchitectures(main.File(), stat.Size())
	if err != nil {
		return fail(err)
	}
	cpus, subs, offsets := make([]C.uint32_t, len(arch)), make([]C.uint32_t, len(arch)), make([]C.uint64_t, len(arch))
	for i, a := range arch {
		cpus[i] = C.uint32_t(a.cpu)
		subs[i] = C.uint32_t(a.sub)
		offsets[i] = C.uint64_t(a.offset)
	}
	path, relative := C.CString(bundle.FileID().Path()), C.CString(name)
	defer C.free(unsafe.Pointer(path))
	defer C.free(unsafe.Pointer(relative))
	var native *C.oa_sealed_resource
	var selected C.size_t
	mainName := make([]C.char, 1024)
	status := C.oa_sealed_resource_create(path, relative, unsafe.Pointer(&data[0]), C.size_t(len(data)), &cpus[0], &subs[0], &offsets[0], C.size_t(len(arch)), &native, &mainName[0], C.size_t(len(mainName)), &selected)
	runtime.KeepAlive(data)
	if status != 0 {
		return fail(sealedResourceFailure(status))
	}
	n := &sealedDarwinResource{native}
	keep := false
	defer func() {
		if !keep {
			n.close()
		}
	}()
	if C.GoString(&mainName[0]) != parts[2] {
		return fail(fmt.Errorf("%w: selected program differs from authenticated main code", ErrNotProven))
	}
	if err = ctx.Err(); err != nil {
		return fail(err)
	}
	if err = sealedBundleAt(ctx, bundle); err != nil {
		return fail(err)
	}
	check, err := bundle.Beneath(rel.Rel, fileid.Options{})
	if err != nil {
		return fail(err)
	}
	same := check.FileID().Equal(program.FileID())
	check.Close()
	if !same {
		return fail(fmt.Errorf("%w: selected program changed", ErrNotProven))
	}
	if err = sealedResourceInside(program, bundle); err != nil {
		return fail(err)
	}
	code, proof, err := n.code(selected)
	if err != nil {
		return fail(err)
	}
	keep = true
	return &SealedResourceEvidence{state: &sealedResourceState{data: data, native: n}}, code, proof, nil
}

func (n *sealedDarwinResource) code(i C.size_t) (Code, Proof, error) {
	var info C.oa_sealed_resource_info
	if status := C.oa_sealed_resource_info_at(n.native, i, &info); status != 0 {
		return Code{}, ProofUnmet, sealedResourceFailure(status)
	}
	return Code{Subject: C.GoString(&info.subject[0]), Issuer: C.GoString(&info.issuer[0]), TeamID: C.GoString(&info.team[0]), Trusted: true, Status: "valid"}, ProofBound, nil
}
func (n *sealedDarwinResource) close() {
	if n.native != nil {
		C.oa_sealed_resource_free(n.native)
		n.native = nil
	}
}
func (n *sealedDarwinResource) match(r *XPCRequest) (Code, Proof, error) {
	request, ok := r.acquire()
	if !ok {
		return Code{}, ProofUnmet, net.ErrClosed
	}
	defer r.calls.Done()
	var process *C.oa_xpc_process
	var security C.int32_t
	status := C.oa_xpc_request_retain_process(request, &process, &security)
	if status != C.OA_XPC_OK {
		if security != 0 {
			return Code{}, ProofUnmet, sealedResourceFailure(security)
		}
		return Code{}, ProofUnmet, xpcError(status)
	}
	defer C.oa_xpc_process_free(process)
	var i C.size_t
	security = C.oa_sealed_resource_match_code(n.native, C.SecCodeRef(C.oa_xpc_process_sealed_resource_code(process)), &i)
	if security != 0 {
		return Code{}, ProofUnmet, sealedResourceFailure(security)
	}
	if C.oa_xpc_request_active(request) == 0 {
		return Code{}, ProofUnmet, net.ErrClosed
	}
	runtime.KeepAlive(r)
	return n.code(i)
}
