//go:build !windows && !linux && !darwin

package identity

import (
	"fmt"
	"runtime"
)

func bindUnixServer(Handle, *Options) (binder, *Peer, error) {
	return nil, nil, fmt.Errorf("%w: AF_UNIX server binding on %s", ErrNoBinding, runtime.GOOS)
}
