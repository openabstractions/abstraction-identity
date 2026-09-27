package identity

import (
	"errors"
	"testing"
)

func TestTransportCeilingRefusesUnknownAndPreservesDefault(t *testing.T) {
	limits, err := CeilingFor(TransportNative)
	if err != nil || limits.Best != Ceiling().Best || limits.Transport != Ceiling().Transport {
		t.Fatalf("default limits=%+v err=%v", limits, err)
	}
	if _, err := CeilingFor(Transport("invented")); !errors.Is(err, ErrUnsupportedConn) {
		t.Fatalf("unknown transport: %v", err)
	}
}

func TestXPCPolicyUsesSharedComparison(t *testing.T) {
	limits := xpcLimits()
	if err := limits.CanEver(Need{User: ProofKernel, Process: ProofKernel, Path: ProofBound}); err != nil {
		t.Fatal(err)
	}
	for _, need := range []Need{{Code: ProofSigned}, {Code: ProofBound}, {Package: ProofPID}, {Path: ProofSigned}} {
		if err := limits.CanEver(need); !errors.Is(err, ErrNotProven) {
			t.Fatalf("unsupported policy %+v: %v", need, err)
		}
	}
}
