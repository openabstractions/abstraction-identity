package fileid

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestFromFileOwnsOnlyItsDuplicate(t *testing.T) {
	path := filepath.Join(t.TempDir(), "native-object")
	if err := os.WriteFile(path, []byte("fixture"), 0600); err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	h, err := FromFile(context.Background(), f)
	if err != nil {
		t.Fatal(err)
	}
	key, err := FileKeyOf(f)
	if err != nil || h.FileID().Key() != key {
		t.Fatal(h.FileID(), err)
	}
	if err := h.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := f.Stat(); err != nil {
		t.Fatal("adopt closed caller descriptor", err)
	}
	h, err = FromFile(context.Background(), f)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := h.File().Stat(); err != nil {
		t.Fatal("caller close invalidated duplicate", err)
	}
	if err := h.Close(); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := FromFile(ctx, f); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if _, err := FromFile(context.Background(), nil); !errors.Is(err, ErrNoFile) {
		t.Fatal(err)
	}
}
