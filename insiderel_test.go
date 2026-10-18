package identity

import (
	"os"
	"path/filepath"
	"testing"
)

// [ID-F1] InsideRel answers by Within when folder exists, by spelling only
// when folder does not, and returns the remainder.
func TestInsideRelExistingAndMissingFolder(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "a", "b"), 0o755); err != nil {
		t.Fatal(err)
	}
	rel, in, err := InsideRel(filepath.Join(dir, "a", "b", "c"), dir)
	if err != nil || !in || rel != filepath.Join("a", "b", "c") {
		t.Errorf("existing folder: %q %v %v", rel, in, err)
	}
	if _, in, err := InsideRel(dir, dir); err != nil || in {
		t.Errorf("the folder itself: %v %v", in, err)
	}
	missing := filepath.Join(dir, "missing")
	rel, in, err = InsideRel(filepath.Join(missing, "x", "y"), missing)
	if err != nil || !in || rel != filepath.Join("x", "y") {
		t.Errorf("missing folder by spelling: %q %v %v", rel, in, err)
	}
	if _, in, err := InsideRel(filepath.Join(dir, "other"), missing); err != nil || in {
		t.Errorf("a sibling of a missing folder: %v %v", in, err)
	}
}
