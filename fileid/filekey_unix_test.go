//go:build unix

package fileid

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestFileKeyOfUnixKeepsHeldIdentityAfterNameChanges(t *testing.T) {
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, "held")
	if err := os.WriteFile(path, []byte("original"), 0600); err != nil {
		t.Fatal(err)
	}
	held, err := Open(context.Background(), Self, path, Options{Read: true, Links: RefuseLinks})
	if err != nil {
		t.Fatal(err)
	}
	defer held.Close()
	expected := held.FileID().Key()
	check := func() {
		t.Helper()
		key, err := FileKeyOf(held.File())
		if err != nil || key != expected {
			t.Fatal("held key changed", key, expected, err)
		}
	}
	check()
	key, err := FileKey(path)
	if err != nil || key != expected {
		t.Fatal("legacy key encoding differs", key, expected, err)
	}
	moved := path + ".moved"
	if err := os.Rename(path, moved); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("replacement"), 0600); err != nil {
		t.Fatal(err)
	}
	check()
	replacement, err := Resolve(context.Background(), Self, path, Options{Links: RefuseLinks})
	if err != nil || replacement.Key() == expected {
		t.Fatal("replacement identity", replacement, err)
	}
	if err := os.Remove(moved); err != nil {
		t.Fatal(err)
	}
	check()
	if err := held.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := FileKeyOf(held.File()); err == nil {
		t.Fatal("closed handle accepted")
	}
	if _, err := FileKeyOf(nil); err == nil {
		t.Fatal("nil handle accepted")
	}
}
