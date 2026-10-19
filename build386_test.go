package identity

import (
	"os"
	"os/exec"
	"testing"
)

// TestVetsOnWindows386 keeps the module building for 32-bit Windows, where
// int is 32 bits and a constant compared as int overflows (backlog J-5).
func TestVetsOnWindows386(t *testing.T) {
	if testing.Short() {
		t.Skip("cross-compiles the module")
	}
	goTool, err := exec.LookPath("go")
	if err != nil {
		t.Skip("go tool not on PATH")
	}
	cmd := exec.Command(goTool, "vet", ".")
	cmd.Env = append(os.Environ(), "GOOS=windows", "GOARCH=386", "CGO_ENABLED=0")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("GOOS=windows GOARCH=386 go vet: %v\n%s", err, out)
	}
}
