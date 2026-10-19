//go:build windows || unix

package privatedir

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/openabstractions/abstraction-identity/fileid"
)

func TestProtectModelFolderAtBorrowsLiveHandles(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "set")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	open := func(p string) fileid.Handle {
		h, err := fileid.Open(context.Background(), fileid.Self, p, fileid.Options{Links: fileid.RefuseLinks})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { h.Close() })
		return h
	}
	r, d := open(root), open(dir)
	if err := ProtectModelFolderAt(d, []fileid.Handle{r}); err != nil {
		t.Fatal(err)
	}
	for _, h := range []fileid.Handle{r, d} {
		if _, err := h.File().Stat(); err != nil {
			t.Fatalf("borrowed handle was closed: %v", err)
		}
	}
	if err := CheckModelFolder(dir); err != nil {
		t.Fatal(err)
	}
	if err := ProtectModelFolderAt(fileid.Handle{}, []fileid.Handle{r}); !errors.Is(err, ErrNotModelFolder) {
		t.Fatalf("zero handle: %v", err)
	}
	closed := open(dir)
	if err := closed.Close(); err != nil {
		t.Fatal(err)
	}
	if err := ProtectModelFolderAt(closed, []fileid.Handle{r}); !errors.Is(err, ErrNotModelFolder) {
		t.Fatalf("closed handle: %v", err)
	}
	if err := ProtectModelFolderAt(d, []fileid.Handle{closed}); !errors.Is(err, ErrNotModelFolder) {
		t.Fatalf("closed root: %v", err)
	}
	if _, err := d.File().Stat(); err != nil {
		t.Fatalf("refusal closed the caller's other handle: %v", err)
	}
}
