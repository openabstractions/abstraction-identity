package privatedir

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"testing"
)

// INF-EL2, INF-MS7: Ensure makes an absent folder private, accepts it again,
// and refuses a relative path, a folder open beyond the account, a file and
// a link; Make refuses an existing path.
func TestEnsure(t *testing.T) {
	base := t.TempDir()
	dir := filepath.Join(base, "parent", "private")
	for range 2 {
		if err := Ensure(dir); err != nil {
			t.Fatalf("Ensure: %v", err)
		}
	}
	if err := Make(dir); !errors.Is(err, fs.ErrExist) {
		t.Fatalf("Make over an existing folder: %v", err)
	}
	if err := Ensure("relative"); !errors.Is(err, ErrNotPrivate) {
		t.Fatalf("a relative path: %v", err)
	}
	wide := filepath.Join(base, "wide")
	if err := os.Mkdir(wide, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(wide, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := Ensure(wide); !errors.Is(err, ErrNotPrivate) {
		t.Fatalf("a folder open beyond the account: %v", err)
	}
	file := filepath.Join(base, "file")
	if err := os.WriteFile(file, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := Ensure(file); !errors.Is(err, ErrNotPrivate) {
		t.Fatalf("a file: %v", err)
	}
	link := filepath.Join(base, "link")
	if err := os.Symlink(dir, link); err != nil {
		t.Skipf("this account cannot make a link here: %v", err)
	}
	if err := Ensure(link); !errors.Is(err, ErrNotPrivate) {
		t.Fatalf("a link to a private folder: %v", err)
	}
}
