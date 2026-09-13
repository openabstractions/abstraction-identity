package identity

import (
	api "github.com/openabstractions/abstraction-identity/go/abstraction/identity/api"
	"testing"
)

func TestDescriptorProofOrderMatchesNative(t *testing.T) {
	if len(api.ProofNames) != len(proofNames) {
		t.Fatal("proof roster changed")
	}
	for i, name := range api.ProofNames {
		if Proof(i).String() != name {
			t.Fatalf("proof %d: %s", i, name)
		}
	}
	record := api.ProofRequirement{User: "kernel", Process: "bound", Path: "bound", Package: "none", Code: "none"}
	got, err := api.Decode(api.Encode(&record))
	if err != nil || *got != record {
		t.Fatalf("%+v %v", got, err)
	}
	// Decoded metadata cannot construct Peer or Attr; those native types retain
	// unexported evidence and extraction through the connection boundary.
}
