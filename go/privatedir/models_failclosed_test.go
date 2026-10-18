//go:build windows || darwin || linux

package privatedir

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	identity "github.com/openabstractions/abstraction-identity"
)

// ID-D3 with ID-F1: a models root identity refuses is refused before any
// comparison, and an identity error in the home check reads as "may hold",
// never as "does not hold". under never counts a root it could not compare.
func TestModelsRootFailsClosedOnRefusedVolume(t *testing.T) {
	refused := refusedFolder(t)
	if err := CheckModelsRoot(refused); !errors.Is(err, ErrNotModelFolder) {
		t.Fatalf("CheckModelsRoot(%q) on a refused volume = %v", refused, err)
	}
	local := filepath.Join(t.TempDir(), "OA-models")
	if err := os.MkdirAll(local, 0o700); err != nil {
		t.Fatal(err)
	}
	if !holds(local, []string{refused}) {
		t.Fatal("holds answered no for a folder it could not compare")
	}
	if !holds(refused, []string{local}) {
		t.Fatal("holds answered no for a refused root")
	}
	if under(filepath.Join(refused, "video"), []string{local}) || under(local, []string{refused}) {
		t.Fatal("under counted a root it could not compare")
	}
	if err := ProtectModelFolder(filepath.Join(refused, "video"), []string{refused}); !errors.Is(err, ErrNotModelFolder) {
		t.Fatalf("ProtectModelFolder on a refused volume = %v", err)
	}
	opens := 0
	stop, ok := identity.ObserveOpens(func(string) { opens++ })
	if !ok {
		t.Fatal("another open observer is set")
	}
	defer stop()
	_ = CheckModelsRoot(refused)
	_ = holds(local, []string{refused})
	_ = under(refused, []string{local})
	if opens != 0 {
		t.Fatalf("refusing %q opened %d paths", refused, opens)
	}
}
