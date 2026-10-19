package placetest_test

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	identity "github.com/openabstractions/abstraction-identity"
	"github.com/openabstractions/abstraction-identity/fileid"
	"github.com/openabstractions/abstraction-identity/placetest"
)

func nativeAdapter(t *testing.T) string {
	t.Helper()
	program := os.Getenv("OA_FILEID_NATIVE_TEST")
	if program == "" {
		t.Skip("private native FileID conformance adapter not supplied")
	}
	if !filepath.IsAbs(program) {
		t.Fatal("OA_FILEID_NATIVE_TEST must name an absolute built adapter")
	}
	return program
}

func nativeAnswer(t *testing.T, program string, args ...string) string {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, program, args...)
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("native %q: %v: %s", args, err, output)
	}
	return strings.TrimSuffix(strings.TrimSuffix(string(output), "\n"), "\r")
}

func sameNativePath(a, b string) bool {
	// GetFinalPathNameByHandle always emits this prefix; Go's Path emits it
	// for exact trailing-dot/space names. Compare the retained physical names.
	if runtime.GOOS == "windows" {
		a = strings.TrimPrefix(a, `\\?\`)
		b = strings.TrimPrefix(b, `\\?\`)
	}
	return identity.SamePathName(a, b)
}

// TestNativeFileIDCases reuses the same owned fixtures and Go reference as the
// shared path table. Only the private migration seam's leaf/containment behavior
// is received here; the complete FileID public behavior remains with its owner.
func TestNativeFileIDCases(t *testing.T) {
	program := nativeAdapter(t)
	table, _, err := placetest.Load()
	if errors.Is(err, placetest.ErrNoTable) {
		t.Skip(err)
	}
	if err != nil {
		t.Fatal(err)
	}
	for _, row := range table.Rows {
		// These existing SameFile fixtures also exercise physical parent and
		// leaf spelling. Their object equality stays with the Go FileID owner.
		leafFixture := row.Op == "SameFile" && (row.Setup == "short-temp" ||
			row.Setup == "kelvin" || row.Setup == "nfc-nfd" ||
			row.Setup == "long-path" || row.Setup == "dot-dot")
		if !row.ForThisPlatform() || row.Skip != "" || row.Op != "PlaceKey" && row.Op != "Within" && !leafFixture {
			continue
		}
		t.Run(row.ID, func(t *testing.T) {
			f, why := build(t, row)
			if why != "" {
				t.Skip(string(why))
			}
			if row.Op == "Within" {
				want := owner(t, row, f)
				if got := nativeAnswer(t, program, "within", f.a, f.b); got != want {
					t.Fatalf("native containment %s, Go FileID %s", got, want)
				}
				return
			}
			checkLeaf := func(path string) string {
				leaf, err := fileid.ResolveLeaf(context.Background(), fileid.Self, path)
				got := nativeAnswer(t, program, "leaf", path)
				if err != nil {
					if got != "refused" {
						t.Fatalf("Go ResolveLeaf refused %v; native leaf returned %q", err, got)
					}
					return "refused"
				}
				if !sameNativePath(got, leaf.Path()) {
					t.Fatalf("native physical leaf %q, Go ResolveLeaf %q", got, leaf.Path())
				}
				return leaf.Key()
			}
			a := checkLeaf(f.a)
			if f.change != nil {
				if err := f.change(); err != nil {
					t.Fatal(err)
				}
			}
			if f.b == "" {
				return
			}
			b := checkLeaf(f.b)
			if row.Op == "PlaceKey" && row.Want == "same" && a != b {
				t.Fatalf("shared fixture's native leaves differ: %q, %q", a, b)
			}
		})
	}
}

func TestNativeFileIDOwnedPlacement(t *testing.T) {
	program := nativeAdapter(t)
	ctx := context.Background()
	root := filepath.Join(t.TempDir(), "owned root")
	if err := os.Mkdir(root, 0700); err != nil {
		t.Fatal(err)
	}
	t.Run("pending parents", func(t *testing.T) {
		path := filepath.Join(root, "not created", "nested", "counter")
		pending, err := fileid.Pending(ctx, fileid.Self, path)
		if err != nil {
			t.Fatal(err)
		}
		if got := nativeAnswer(t, program, "leaf", path); !sameNativePath(got, pending.Path()) {
			t.Fatalf("native pending leaf %q, Go Pending %q", got, pending.Path())
		}
		if _, err := os.Stat(filepath.Dir(path)); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("read-only resolution created pending parents: %v", err)
		}
	})
	t.Run("junction escape and unfollowed leaf", func(t *testing.T) {
		outside := t.TempDir()
		file := write(t, filepath.Join(outside, "counter"))
		link := filepath.Join(root, "escape")
		if err := placetest.Junction(link, outside); err != nil {
			t.Skip(err)
		}
		path := filepath.Join(link, filepath.Base(file))
		row := placetest.Case{Op: "Within"}
		want := owner(t, row, fixture{a: path, b: root})
		if want != "outside" {
			t.Fatalf("owned escape fixture resolved %s", want)
		}
		if got := nativeAnswer(t, program, "within", path, root); got != want {
			t.Fatalf("native junction escape %s, Go FileID %s", got, want)
		}
		leaf, err := fileid.ResolveLeaf(ctx, fileid.Self, link)
		if err != nil {
			t.Fatal(err)
		}
		if got := nativeAnswer(t, program, "leaf", link); !sameNativePath(got, leaf.Path()) {
			t.Fatalf("native followed the final junction: %q; Go leaf %q", got, leaf.Path())
		}
		if got := nativeAnswer(t, program, "within", link, root); got != "within" {
			t.Fatalf("the junction entry itself belongs to its parent: %s", got)
		}
	})
}
