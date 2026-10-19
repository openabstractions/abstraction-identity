//go:build windows

package profile

import "testing"

func TestCurrentKeepsOneProcessAnswer(t *testing.T) {
	first, err := Current()
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("LOCALAPPDATA", "relative-second-probe-must-not-run")
	again, againErr := Current()
	if againErr != nil || again != first {
		t.Fatalf("cached view changed: %v %v %v", first, again, againErr)
	}
}
