package identity

import (
	api "github.com/openabstractions/abstraction-identity/go/abstraction/identity/api"
	"testing"
)

func TestDescriptorProofOrderMatchesNative(t *testing.T) {
	if len(api.ProofValues()) != len(proofNames) {
		t.Fatal("proof roster changed")
	}
	for i, name := range api.ProofValues() {
		if Proof(i).String() != name.String() {
			t.Fatalf("proof %d: %s", i, name)
		}
	}
	record := api.ProofRequirement{
		User:    api.ProofKernel,
		Process: api.ProofBound,
		Path:    api.ProofBound,
		Package: api.ProofNone,
		Code:    api.ProofNone,
	}
	got, err := api.Decode(api.Encode(&record))
	if err != nil || *got != record {
		t.Fatalf("%+v %v", got, err)
	}
	// Decoded metadata cannot construct Peer or Attr; those native types retain
	// unexported evidence and extraction through the connection boundary.
}
