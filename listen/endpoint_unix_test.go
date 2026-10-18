//go:build !windows

package listen

import (
	"path/filepath"
	"testing"
)

func TestEndpointKeepsAbsoluteLocalSocket(t *testing.T) {
	short := "provider-image"
	qualified := Endpoint(short)
	if !filepath.IsAbs(qualified) {
		t.Fatalf("short endpoint did not resolve to an absolute socket: %q", qualified)
	}
	if got := Endpoint(qualified); got != qualified {
		t.Fatalf("qualified endpoint doubled = %q", got)
	}
	custom := filepath.Join(t.TempDir(), "custom-provider.sock")
	if got := Endpoint(custom); got != custom {
		t.Fatalf("explicit absolute socket changed = %q", got)
	}
}
