//go:build unix

package privatedir

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

func mode(t *testing.T, p string) os.FileMode {
	t.Helper()
	info, err := os.Lstat(p)
	if err != nil {
		t.Fatal(err)
	}
	return info.Mode().Perm()
}

// ID-D3 elsewhere: group and other write bits are cleared through each
// entry's descriptor; a symbolic link and a named pipe (never opened) each
// refuse the folder before anything changes.
func TestProtectModelFolderUnix(t *testing.T) {
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(root, "video")
	nested := filepath.Join(dir, "nested")
	if err := os.MkdirAll(nested, 0o700); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(nested, "weights.gguf")
	if err := os.WriteFile(file, []byte("w"), 0o600); err != nil {
		t.Fatal(err)
	}
	for p, m := range map[string]os.FileMode{dir: 0o777, nested: 0o775, file: 0o666} {
		if err := os.Chmod(p, m); err != nil {
			t.Fatal(err)
		}
	}
	for name, make := range map[string]func(string) error{
		"link": func(p string) error { return os.Symlink(file, p) },
		"pipe": func(p string) error { return unix.Mkfifo(p, 0o600) },
	} {
		p := filepath.Join(dir, name)
		if err := make(p); err != nil {
			t.Fatal(err)
		}
		if err := ProtectModelFolder(dir, []string{root}); !errors.Is(err, ErrNotModelFolder) {
			t.Fatalf("%s: %v", name, err)
		}
		if mode(t, file) != 0o666 || mode(t, dir) != 0o777 {
			t.Fatalf("%s: a refused folder was changed", name)
		}
		if err := os.Remove(p); err != nil {
			t.Fatal(err)
		}
	}
	if err := ProtectModelFolder(dir, []string{root}); err != nil {
		t.Fatal(err)
	}
	for p, want := range map[string]os.FileMode{dir: 0o755, nested: 0o755, file: 0o644} {
		if got := mode(t, p); got != want {
			t.Fatalf("%s: mode %#o, want %#o", p, got, want)
		}
	}
	if err := CheckModelFolder(dir); err != nil {
		t.Fatal(err)
	}
}

func TestProtectModelFolderUnixAliases(t *testing.T) {
	for _, scenario := range []string{"inside", "overlapping", "foreign", "incomplete", "moved", "added"} {
		t.Run(scenario, func(t *testing.T) {
			base, err := filepath.EvalSymlinks(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			root := filepath.Join(base, "models")
			dir := filepath.Join(root, "set")
			jobs := filepath.Join(base, "jobs")
			for _, p := range []string{dir, jobs} {
				if err := os.MkdirAll(p, 0o700); err != nil {
					t.Fatal(err)
				}
			}
			file := filepath.Join(dir, "weights")
			if err := os.WriteFile(file, []byte("weights"), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(file, 0o666); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(dir, 0o777); err != nil {
				t.Fatal(err)
			}
			alias := filepath.Join(jobs, "result")
			roots := []string{root, jobs}
			if scenario == "foreign" {
				alias = filepath.Join(base, "foreign")
			}
			if scenario == "overlapping" {
				roots = append(roots, dir, root)
			}
			if err := os.Link(file, alias); err != nil {
				t.Fatal(err)
			}
			if scenario == "incomplete" {
				if err := os.Symlink(base, filepath.Join(jobs, "unobserved")); err != nil {
					t.Fatal(err)
				}
			}
			if scenario == "moved" || scenario == "added" {
				afterScan = func() {
					var err error
					if scenario == "moved" {
						err = os.Rename(alias, filepath.Join(base, "escaped"))
					} else {
						err = os.Link(file, filepath.Join(base, "extra"))
					}
					if err != nil {
						t.Fatal(err)
					}
				}
				t.Cleanup(func() { afterScan = nil })
			}
			err = ProtectModelFolder(dir, roots)
			if scenario == "inside" || scenario == "overlapping" {
				if err != nil {
					t.Fatal(err)
				}
				if mode(t, file) != 0o644 || mode(t, dir) != 0o755 {
					t.Fatal("held model entries were not protected")
				}
				if mode(t, jobs) != 0o700 {
					t.Fatal("inventory folder was changed")
				}
			} else {
				if !errors.Is(err, ErrNotModelFolder) {
					t.Fatalf("wanted refusal, got %v", err)
				}
				if mode(t, file) != 0o666 || mode(t, dir) != 0o777 {
					t.Fatal("refusal changed the model folder")
				}
			}
		})
	}
}
