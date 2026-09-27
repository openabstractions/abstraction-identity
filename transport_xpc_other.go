//go:build !darwin || !cgo

package identity

import "fmt"

func xpcCeiling() (Limits, error) {
	return Limits{}, fmt.Errorf("%w: XPC requires macOS 12 or newer and cgo", ErrUnsupportedConn)
}
