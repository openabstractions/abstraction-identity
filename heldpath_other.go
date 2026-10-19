//go:build !windows

package identity

import "os"

// heldFilePath is program on this platform, where VerifyFile reads no file
// (ErrUnimplemented) and only a test's verifier reads the path.
func heldFilePath(_ *os.File, program string) (path string, ok bool) {
	return program, true
}
