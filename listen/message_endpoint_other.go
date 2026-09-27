//go:build !darwin || !cgo

package listen

import (
	"context"
	"errors"
	"strings"
)

func listenMessageEndpoint(endpoint string) (Listener, bool, error) {
	if strings.HasPrefix(endpoint, "xpc:") {
		return nil, true, errors.New("listen: XPC requires macOS with cgo")
	}
	return nil, false, nil
}
func (c FrameClient) messageFrameCall(context.Context, []byte, bool) ([]byte, bool, error) {
	if c.Dialer != nil {
		return nil, false, nil
	}
	if strings.HasPrefix(c.Endpoint, "xpc:") {
		return nil, true, errors.New("listen: XPC requires macOS with cgo")
	}
	return nil, false, nil
}
