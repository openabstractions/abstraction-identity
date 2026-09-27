package listen

import (
	"errors"
	identity "github.com/openabstractions/abstraction-identity"
	"strings"
	"testing"
)

func TestXPCServiceValidation(t *testing.T) {
	for _, endpoint := range []string{"xpc:", "xpc:a/b", "xpc:a\\b", "xpc:a\r", "xpc:a\n", "xpc:a\x00b", "xpc:" + strings.Repeat("a", 256)} {
		if _, err := xpcService(endpoint); err == nil {
			t.Fatalf("xpcService(%q) accepted malformed service", endpoint)
		}
	}
	if service, err := xpcService("xpc:org.openabstractions.test"); err != nil || service != "org.openabstractions.test" {
		t.Fatalf("valid service = %q, %v", service, err)
	}
	if service, err := xpcService("/tmp/socket"); err != nil || service != "" {
		t.Fatalf("non-XPC endpoint = %q, %v", service, err)
	}
}

func TestFramedStartupRefusesBeforeTakingEndpoint(t *testing.T) {
	endpoint := framedEndpoint(t)
	l, err := ListenFramed(endpoint, identity.Need{Code: identity.ProofSigned})
	if l != nil || !errors.Is(err, identity.ErrNotProven) {
		t.Fatalf("unsupported startup: listener=%v error=%v", l, err)
	}
	// Refusal must leave the endpoint available for a satisfiable policy.
	l, err = ListenFramed(endpoint, framingNeed)
	if err != nil {
		t.Fatal(err)
	}
	l.Close()
}

func TestXPCEndpointCeilingNeverUsesSocketCeiling(t *testing.T) {
	limits, err := Ceiling("xpc:org.openabstractions.test")
	if err != nil {
		if !errors.Is(err, identity.ErrUnsupportedConn) {
			t.Fatal(err)
		}
		if CanEver("xpc:org.openabstractions.test", identity.Need{}) == nil {
			t.Fatal("unavailable transport accepted an empty policy")
		}
		return
	}
	if limits.Transport != "xpc" || !limits.Bindable {
		t.Fatalf("XPC limits=%+v", limits)
	}
	if err := CanEver("xpc:org.openabstractions.test", Program); err != nil {
		t.Fatal(err)
	}
	if err := CanEver("xpc:org.openabstractions.test", identity.Need{Code: identity.ProofSigned}); !errors.Is(err, identity.ErrNotProven) {
		t.Fatalf("signed policy: %v", err)
	}
}
