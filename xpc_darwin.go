//go:build darwin && cgo

package identity

/*
#cgo CFLAGS: -std=c17 -fblocks
#cgo LDFLAGS: -framework CoreFoundation -framework Security
#include "xpc_native.h"
#include <stdlib.h>
*/
import "C"

import (
	"context"
	"errors"
	"fmt"
	"net"
	"runtime"
	"strings"
	"sync"
	"time"
	"unsafe"
)

type XPCListener struct {
	mu      sync.Mutex
	calls   sync.WaitGroup
	native  *C.oa_xpc_listener
	closing bool
}
type XPCRequest struct {
	mu        sync.Mutex
	calls     sync.WaitGroup
	native    *C.oa_xpc_request
	frame     []byte
	done      chan struct{}
	closing   bool
	closeOnce sync.Once
}
type XPCClient struct {
	mu      sync.Mutex
	calls   sync.WaitGroup
	native  *C.oa_xpc_client
	closing bool
}

// XPCProofRefusal is the receiver's fixed policy refusal. It does not report
// the caller evidence the receiver observed.
type XPCProofRefusal struct {
	Attribute uint8
	Required  Proof
}

func (e *XPCProofRefusal) Error() string        { return "identity: XPC receiver refused caller proof" }
func (e *XPCProofRefusal) Is(target error) bool { return target == ErrNotProven }

func xpcError(status C.oa_xpc_status) error {
	switch status {
	case C.OA_XPC_OK:
		return nil
	case C.OA_XPC_CLOSED:
		return net.ErrClosed
	case C.OA_XPC_TIMEOUT:
		return context.DeadlineExceeded
	case C.OA_XPC_CANCELLED:
		return context.Canceled
	case C.OA_XPC_INVALID_ARGUMENT:
		return fmt.Errorf("identity: XPC invalid argument")
	case C.OA_XPC_UNTRUSTED:
		return fmt.Errorf("%w: XPC peer", ErrNoBinding)
	case C.OA_XPC_PROTOCOL:
		return errors.New("identity: XPC protocol violation")
	case C.OA_XPC_UNAVAILABLE:
		return errors.New("identity: authenticated XPC requires macOS 12 or later")
	case C.OA_XPC_CALLER_PROOF_UNMET:
		return &XPCProofRefusal{}
	default:
		return errors.New("identity: XPC system failure")
	}
}

func OpenXPCListener(service string, maxFrame uint32) (*XPCListener, error) {
	if service == "" || strings.IndexByte(service, 0) >= 0 || maxFrame == 0 {
		return nil, errors.New("identity: invalid XPC listener arguments")
	}
	name := C.CString(service)
	defer C.free(unsafe.Pointer(name))
	var native *C.oa_xpc_listener
	if err := xpcError(C.oa_xpc_listener_open(name, C.size_t(maxFrame), &native)); err != nil {
		return nil, err
	}
	l := &XPCListener{native: native}
	runtime.SetFinalizer(l, (*XPCListener).Close)
	return l, nil
}
func (l *XPCListener) acquire() (*C.oa_xpc_listener, bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closing || l.native == nil {
		return nil, false
	}
	l.calls.Add(1)
	return l.native, true
}
func (l *XPCListener) Accept() (*XPCRequest, error) {
	nativeListener, ok := l.acquire()
	if !ok {
		return nil, net.ErrClosed
	}
	defer l.calls.Done()
	var native *C.oa_xpc_request
	if err := xpcError(C.oa_xpc_listener_next(nativeListener, 0, nil, &native)); err != nil {
		return nil, err
	}
	var data unsafe.Pointer
	var length C.size_t
	if err := xpcError(C.oa_xpc_request_bytes(native, &data, &length)); err != nil {
		C.oa_xpc_request_free(native)
		return nil, err
	}
	if uint64(length) > uint64(^uint32(0)>>1) {
		C.oa_xpc_request_free(native)
		return nil, errors.New("identity: XPC request exceeds Go copy limit")
	}
	r := &XPCRequest{native: native, frame: C.GoBytes(data, C.int(length)), done: make(chan struct{})}
	r.calls.Add(1)
	go func() { defer r.calls.Done(); C.oa_xpc_request_wait(native, 0, nil); r.closeDone() }()
	runtime.SetFinalizer(r, (*XPCRequest).Close)
	return r, nil
}
func (l *XPCListener) Close() error {
	if l == nil {
		return nil
	}
	l.mu.Lock()
	if l.closing {
		l.mu.Unlock()
		l.calls.Wait()
		return nil
	}
	l.closing = true
	native := l.native
	if native != nil {
		C.oa_xpc_listener_close(native)
	}
	l.mu.Unlock()
	l.calls.Wait()
	l.mu.Lock()
	if l.native != nil {
		C.oa_xpc_listener_free(l.native)
		l.native = nil
	}
	l.mu.Unlock()
	runtime.SetFinalizer(l, nil)
	return nil
}
func (r *XPCRequest) closeDone() { r.closeOnce.Do(func() { close(r.done) }) }
func (r *XPCRequest) acquire() (*C.oa_xpc_request, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closing || r.native == nil {
		return nil, false
	}
	r.calls.Add(1)
	return r.native, true
}
func (r *XPCRequest) Frame() []byte         { return append([]byte(nil), r.frame...) }
func (r *XPCRequest) Done() <-chan struct{} { return r.done }
func (r *XPCRequest) Reply(frame []byte) error {
	native, ok := r.acquire()
	if !ok {
		return net.ErrClosed
	}
	defer r.calls.Done()
	var p unsafe.Pointer
	if len(frame) > 0 {
		p = unsafe.Pointer(&frame[0])
	}
	err := xpcError(C.oa_xpc_request_reply(native, p, C.size_t(len(frame))))
	runtime.KeepAlive(r)
	return err
}
func (r *XPCRequest) RefuseUnmetProof(attribute uint8, required Proof) error {
	native, ok := r.acquire()
	if !ok {
		return net.ErrClosed
	}
	defer r.calls.Done()
	err := xpcError(C.oa_xpc_request_refuse_unmet_proof(native, C.uint8_t(attribute), C.uint8_t(required)))
	runtime.KeepAlive(r)
	return err
}
func (r *XPCRequest) Close() error {
	if r == nil {
		return nil
	}
	r.mu.Lock()
	if r.closing {
		r.mu.Unlock()
		r.calls.Wait()
		return nil
	}
	r.closing = true
	native := r.native
	if native != nil {
		C.oa_xpc_request_cancel(native)
	}
	r.mu.Unlock()
	r.calls.Wait()
	r.mu.Lock()
	if r.native != nil {
		C.oa_xpc_request_free(r.native)
		r.native = nil
	}
	r.mu.Unlock()
	r.closeDone()
	runtime.SetFinalizer(r, nil)
	return nil
}

type xpcBinder struct{ request *XPCRequest }

func (b *xpcBinder) recheck() error {
	if b.request == nil {
		return net.ErrClosed
	}
	native, ok := b.request.acquire()
	if !ok {
		return net.ErrClosed
	}
	defer b.request.calls.Done()
	if C.oa_xpc_request_active(native) == 0 {
		return net.ErrClosed
	}
	runtime.KeepAlive(b.request)
	return nil
}
func (b *xpcBinder) alive() (bool, error) {
	if err := b.recheck(); err != nil {
		return false, err
	}
	return true, nil
}
func (b *xpcBinder) release() error { return nil }

func xpcCeiling() (Limits, error) {
	if C.oa_xpc_available() == 0 {
		return Limits{}, fmt.Errorf("%w: XPC requires macOS 12 or newer", ErrUnsupportedConn)
	}
	return xpcLimits(), nil
}

// BindXPCRequest builds identity only from the native core's validation of this
// exact received XPC dictionary. Callers cannot supply identity field values.
func BindXPCRequest(request *XPCRequest) (*Binding, error) {
	if request == nil {
		return nil, ErrNoBinding
	}
	native, ok := request.acquire()
	if !ok {
		return nil, ErrNoBinding
	}
	defer request.calls.Done()
	var observed C.oa_xpc_identity
	if err := xpcError(C.oa_xpc_request_identity(native, &observed)); err != nil {
		return nil, err
	}
	runtime.KeepAlive(request)
	coherent := observed.connection_principal_message_coherent != 0
	principalProof, processProof := ProofPID, ProofPID
	note := "the connection credentials and message code were observed separately"
	if coherent {
		principalProof, processProof = ProofKernel, ProofKernel
		note = "the remote connection was obtained from this exact XPC dictionary and its process path matched the message-bound dynamic code"
	}
	path := C.GoString(observed.message_path)
	identifier := C.GoString(observed.signing_identifier)
	team := C.GoString(observed.team_identifier)
	peer := &Peer{Platform: "darwin", Transport: "xpc", ObservedAt: time.Now(), Notes: []string{note, "audit session and pidversion are unavailable through the public received-message API"}}
	peer.User = attr("user", User{Kind: "posix", UID: int(observed.connection_euid), GID: int(observed.connection_egid)}, principalProof, note)
	peer.Process = attr("process", Process{PID: int(observed.connection_pid)}, processProof, note)
	peer.Path = attr("path", path, ProofBound, "path of dynamic code selected from the exact XPC message")
	peer.Package = unknown[string]("package", "message code validity does not establish a trusted publisher; observed signing identifier "+identifier)
	peer.Code = unknown[Code]("code", "message-bound code passed structural validity, but no trusted publisher requirement was applied; team "+team+" status "+C.GoString(observed.signing_status))
	return &Binding{peer: peer, boundAt: time.Now(), inner: &bindingState{inner: &xpcBinder{request: request}}}, nil
}

func xpcDeadline(ctx context.Context) C.uint64_t {
	deadline, ok := ctx.Deadline()
	if !ok {
		return 0
	}
	remaining := time.Until(deadline)
	if remaining <= 0 {
		return C.uint64_t(C.oa_xpc_now_ns())
	}
	return C.uint64_t(uint64(C.oa_xpc_now_ns()) + uint64(remaining))
}
func xpcCancellation(ctx context.Context) (*C.oa_xpc_cancel, func(), error) {
	if err := ctx.Err(); err != nil {
		return nil, nil, err
	}
	var token *C.oa_xpc_cancel
	if err := xpcError(C.oa_xpc_cancel_create(&token)); err != nil {
		return nil, nil, err
	}
	done := make(chan struct{})
	stop := context.AfterFunc(ctx, func() { C.oa_xpc_cancel_fire(token); close(done) })
	release := func() {
		if !stop() {
			<-done
		}
		C.oa_xpc_cancel_free(token)
	}
	return token, release, nil
}
func OpenXPCClient(ctx context.Context, service, expectedProgram string, expectedEUID uint32, maxReply uint32) (*XPCClient, error) {
	if service == "" || expectedProgram == "" || strings.IndexByte(service, 0) >= 0 || strings.IndexByte(expectedProgram, 0) >= 0 {
		return nil, errors.New("identity: invalid XPC client arguments")
	}
	name := C.CString(service)
	program := C.CString(expectedProgram)
	defer C.free(unsafe.Pointer(name))
	defer C.free(unsafe.Pointer(program))
	token, release, err := xpcCancellation(ctx)
	if err != nil {
		return nil, err
	}
	defer release()
	var native *C.oa_xpc_client
	if err := xpcError(C.oa_xpc_client_open(name, program, C.uint32_t(expectedEUID), C.size_t(maxReply), xpcDeadline(ctx), token, &native)); err != nil {
		return nil, err
	}
	client := &XPCClient{native: native}
	runtime.SetFinalizer(client, (*XPCClient).Close)
	return client, nil
}
func (c *XPCClient) acquire() (*C.oa_xpc_client, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closing || c.native == nil {
		return nil, false
	}
	c.calls.Add(1)
	return c.native, true
}
func (c *XPCClient) Call(ctx context.Context, frame []byte, oneWay bool) ([]byte, int, error) {
	if c == nil {
		return nil, 0, net.ErrClosed
	}
	native, ok := c.acquire()
	if !ok {
		return nil, 0, net.ErrClosed
	}
	defer c.calls.Done()
	token, release, cancelErr := xpcCancellation(ctx)
	if cancelErr != nil {
		return nil, 0, cancelErr
	}
	defer release()
	var input unsafe.Pointer
	if len(frame) > 0 {
		input = unsafe.Pointer(&frame[0])
	}
	var sent C.size_t
	var output unsafe.Pointer
	var length C.size_t
	var proofAttribute, proofRequired C.uint8_t
	one := C.uint8_t(0)
	if oneWay {
		one = 1
	}
	status := C.oa_xpc_client_call(native, input, C.size_t(len(frame)), one, xpcDeadline(ctx), token, &sent, &output, &length, &proofAttribute, &proofRequired)
	if output != nil {
		defer C.oa_xpc_bytes_free(output)
	}
	if status == C.OA_XPC_CALLER_PROOF_UNMET {
		return nil, int(sent), &XPCProofRefusal{Attribute: uint8(proofAttribute), Required: Proof(proofRequired)}
	}
	if err := xpcError(status); err != nil {
		return nil, int(sent), err
	}
	if uint64(length) > uint64(^uint32(0)>>1) {
		return nil, int(sent), errors.New("identity: XPC reply exceeds Go copy limit")
	}
	reply := C.GoBytes(output, C.int(length))
	runtime.KeepAlive(c)
	return reply, int(sent), nil
}
func (c *XPCClient) Close() error {
	if c == nil {
		return nil
	}
	c.mu.Lock()
	if c.closing {
		c.mu.Unlock()
		c.calls.Wait()
		return nil
	}
	c.closing = true
	native := c.native
	if native != nil {
		C.oa_xpc_client_close(native)
	}
	c.mu.Unlock()
	c.calls.Wait()
	c.mu.Lock()
	if c.native != nil {
		C.oa_xpc_client_free(c.native)
		c.native = nil
	}
	c.mu.Unlock()
	runtime.SetFinalizer(c, nil)
	return nil
}
