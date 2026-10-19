package placetest_test

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"testing"

	identity "github.com/openabstractions/abstraction-identity"
	"github.com/openabstractions/abstraction-identity/fileid"
)

func TestDistinctNameFixtureRequiresNativeDistinction(t *testing.T) {
	t.Run("distinct files", func(t *testing.T) {
		dir := t.TempDir()
		a, b := filepath.Join(dir, "first"), filepath.Join(dir, "second")
		f, why, err := distinctNameFiles(a, b)
		if err != nil || why != "" || f.a != a || f.b != b {
			t.Fatalf("fixture=%+v skip=%q error=%v", f, why, err)
		}
		left, err := os.Stat(a)
		if err != nil {
			t.Fatal(err)
		}
		right, err := os.Stat(b)
		if err != nil || os.SameFile(left, right) {
			t.Fatalf("native distinction: right=%v error=%v", right, err)
		}
		for name, same := range map[string]func(string, string) (bool, error){
			"identity": identity.SameFile, "fileid": fileid.SameFile,
		} {
			if got, err := same(a, b); err != nil || got {
				t.Errorf("%s: same=%v error=%v", name, got, err)
			}
		}
	})
	t.Run("native aliases", func(t *testing.T) {
		dir := t.TempDir()
		a, b := filepath.Join(dir, "first"), throughDotDot(t, dir, "first")
		f, why, err := distinctNameFiles(a, b)
		if err != nil || why == "" || f.a != "" || f.b != "" {
			t.Fatalf("fixture=%+v skip=%q error=%v", f, why, err)
		}
		for name, same := range map[string]func(string, string) (bool, error){
			"identity": identity.SameFile, "fileid": fileid.SameFile,
		} {
			if got, err := same(a, b); err != nil || !got {
				t.Errorf("%s: same=%v error=%v", name, got, err)
			}
		}
	})
	t.Run("different existing file", func(t *testing.T) {
		dir := t.TempDir()
		a, b := filepath.Join(dir, "first"), filepath.Join(dir, "second")
		if err := os.WriteFile(b, []byte("existing"), 0o600); err != nil {
			t.Fatal(err)
		}
		_, why, err := distinctNameFiles(a, b)
		if !errors.Is(err, fs.ErrExist) || why != "" {
			t.Fatalf("skip=%q error=%v", why, err)
		}
	})
	t.Run("unexpected creation error", func(t *testing.T) {
		dir := t.TempDir()
		_, why, err := distinctNameFiles(filepath.Join(dir, "first"), filepath.Join(dir, "missing", "second"))
		if !errors.Is(err, fs.ErrNotExist) || why != "" {
			t.Fatalf("skip=%q error=%v", why, err)
		}
	})
}
