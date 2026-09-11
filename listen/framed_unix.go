//go:build !windows

package listen

import (
	"context"
	"net"
)

func dialFramed(ctx context.Context, path string) (net.Conn, error) {
	return (&net.Dialer{}).DialContext(ctx, "unix", path)
}
