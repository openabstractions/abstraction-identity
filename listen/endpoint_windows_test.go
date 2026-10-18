//go:build windows

package listen

import "testing"

func TestEndpointKeepsQualifiedLocalPipe(t *testing.T) {
	const short = "provider-image"
	const qualified = `\\.\pipe\openabstractions-provider-image`
	if got := Endpoint(short); got != qualified {
		t.Fatalf("short endpoint = %q", got)
	}
	if got := Endpoint(qualified); got != qualified {
		t.Fatalf("qualified endpoint doubled = %q", got)
	}
	const custom = `\\.\pipe\custom-provider-image`
	if got := Endpoint(custom); got != custom {
		t.Fatalf("custom local pipe changed = %q", got)
	}
	if got := Endpoint(`\\server\pipe\provider-image`); got != `\\.\pipe\openabstractions-\\server\pipe\provider-image` {
		t.Fatalf("remote UNC pipe was treated as a qualified endpoint: %q", got)
	}
	if got := Endpoint(`\\.\pipe\`); got == `\\.\pipe\` {
		t.Fatal("empty local pipe name was treated as a qualified endpoint")
	}
}
