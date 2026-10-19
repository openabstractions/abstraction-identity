//go:build !darwin || !cgo

package identity

import (
	"context"
	"errors"
	"github.com/openabstractions/abstraction-identity/fileid"
	"testing"
)

func TestVerifySealedResourceUnsupported(t *testing.T) {
	e, c, p, err := VerifySealedResource(context.Background(), fileid.Handle{}, fileid.Handle{}, "Resources/data", 1)
	if e != nil || c != (Code{}) || p != ProofUnmet || !errors.Is(err, ErrUnimplemented) {
		t.Fatalf("%v %v %v %v", e, c, p, err)
	}
}
