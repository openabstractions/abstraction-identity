//go:build !windows

package identity

import (
	"fmt"
	"runtime"
	"time"
)

// Sockets reads the socket owner tables. Only the Windows tables are wired;
// elsewhere it answers ErrNoBinding.
func Sockets() ([]Socket, error) {
	return nil, fmt.Errorf("%w: socket owner tables on %s", ErrNoBinding, runtime.GOOS)
}

// AllSockets reads every TCP and UDP socket with its owner. Only the
// Windows tables are wired; elsewhere it answers ErrNoBinding.
func AllSockets() ([]Socket, error) {
	return nil, fmt.Errorf("%w: socket owner tables on %s", ErrNoBinding, runtime.GOOS)
}

func processCreation(int) (time.Time, error) {
	return time.Time{}, fmt.Errorf("%w: process creation time on %s", ErrNoBinding, runtime.GOOS)
}
