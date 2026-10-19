//go:build !darwin || !cgo

package identity

import "os"

func bindStartedProcess(*os.Process) (binder, *Peer, error) {
	return nil, nil, ErrUnimplemented
}
