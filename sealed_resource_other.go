//go:build !darwin || !cgo

package identity

import (
	"context"
	"github.com/openabstractions/abstraction-identity/fileid"
)

// XPCRequest is unavailable on this platform; native requests require Darwin/cgo.
type XPCRequest struct{}

func verifySealedResource(context.Context, fileid.Handle, fileid.Handle, string, int64) (*SealedResourceEvidence, Code, Proof, error) {
	return nil, Code{}, ProofUnmet, ErrUnimplemented
}
