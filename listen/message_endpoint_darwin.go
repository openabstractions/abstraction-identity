//go:build darwin && cgo

package listen

import (
	"context"
	"errors"
	"fmt"
	identity "github.com/openabstractions/abstraction-identity"
	"io"
	"strings"
)

type xpcListener struct{ native *identity.XPCListener }
type xpcConn struct{ request *identity.XPCRequest }

func listenMessageEndpoint(endpoint string) (Listener, bool, error) {
	service, err := xpcService(endpoint)
	if err != nil {
		return nil, strings.HasPrefix(endpoint, "xpc:"), err
	}
	if service == "" {
		return nil, strings.HasPrefix(endpoint, "xpc:"), nil
	}
	native, err := identity.OpenXPCListener(service, DefaultMaxFrame)
	if err != nil {
		return nil, true, err
	}
	return &xpcListener{native}, true, nil
}
func (l *xpcListener) Accept() (Conn, error) {
	request, err := l.native.Accept()
	if err != nil {
		return nil, err
	}
	return &xpcConn{request}, nil
}
func (l *xpcListener) Close() error                 { return l.native.Close() }
func (c *xpcConn) Read([]byte) (int, error)         { return 0, io.EOF }
func (c *xpcConn) Write([]byte) (int, error)        { return 0, io.ErrClosedPipe }
func (c *xpcConn) Bind() (*identity.Binding, error) { return nil, identity.ErrNoBinding }
func (c *xpcConn) Close() error                     { return c.request.Close() }
func (c *xpcConn) refuseProof(err error) error {
	tokens := proofRefusalBytes(err)
	return c.request.RefuseUnmetProof(tokens[4], identity.Proof(tokens[5]))
}
func (c *xpcConn) receiveMessage(ctx context.Context, limit uint32) (receivedMessage, error) {
	frame := c.request.Frame()
	if uint64(len(frame)) > uint64(limit) {
		return receivedMessage{}, ErrFrameTooLarge
	}
	binding, err := identity.BindXPCRequest(c.request)
	if err != nil {
		return receivedMessage{}, err
	}
	return receivedMessage{frame: frame, binding: binding, done: c.request.Done(), reply: func(replyCtx context.Context, reply []byte) error {
		if err := replyCtx.Err(); err != nil {
			return err
		}
		return c.request.Reply(reply)
	}}, nil
}
func (c FrameClient) messageFrameCall(ctx context.Context, frame []byte, oneWay bool) ([]byte, bool, error) {
	if c.Dialer != nil {
		return nil, false, nil
	}
	service, err := xpcService(c.Endpoint)
	if err != nil {
		return nil, strings.HasPrefix(c.Endpoint, "xpc:"), err
	}
	if service == "" {
		return nil, strings.HasPrefix(c.Endpoint, "xpc:"), nil
	}
	if c.Server == nil {
		return nil, true, ErrServerUntrusted
	}
	if c.Server.Process != nil {
		return nil, true, fmt.Errorf("%w: XPC process-instance pinning is unavailable", ErrServerUntrusted)
	}
	if err = c.Server.validate(); err != nil {
		return nil, true, err
	}
	if c.Server.Principal.Kind != "posix" || c.Server.Principal.UID < 0 || uint64(c.Server.Principal.UID) > uint64(^uint32(0)) {
		return nil, true, ErrServerUntrusted
	}
	client, err := identity.OpenXPCClient(ctx, service, c.Server.Program, uint32(c.Server.Principal.UID), frameLimit(c.MaxFrame))
	if err != nil {
		if errors.Is(err, identity.ErrNoBinding) {
			return nil, true, fmt.Errorf("%w: %w", ErrServerUntrusted, err)
		}
		return nil, true, err
	}
	defer client.Close()
	reply, _, err := client.Call(ctx, frame, oneWay)
	var refusal *identity.XPCProofRefusal
	if errors.As(err, &refusal) {
		if int(refusal.Attribute) < len(proofAttributes) {
			return nil, true, &ProofRefusal{Attribute: proofAttributes[refusal.Attribute], Required: refusal.Required}
		}
	}
	return reply, true, err
}
