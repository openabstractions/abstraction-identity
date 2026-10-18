//go:build !windows

package identity

import (
	"errors"
	"testing"
)

// TestVerifyFileIsUnimplementedOffWindows asserts ID-W4's platform rule
// through ID-E4: no portable fallback answers for a file signature.
func TestVerifyFileIsUnimplementedOffWindows(t *testing.T) {
	code, proof, err := VerifyFile("/usr/bin/env", nil)
	if !errors.Is(err, ErrUnimplemented) || proof != ProofNone || code != (Code{}) {
		t.Fatalf("VerifyFile = %+v %v %v", code, proof, err)
	}
}
