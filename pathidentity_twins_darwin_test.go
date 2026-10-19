package identity

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/openabstractions/abstraction-identity/fileid"
)

// The volume answers every equality question. The first seven pairs mirror
// the Windows corpus; the Georgian pair probes newer case mappings. Cross-script
// visual twins supply independent distinct-name controls. The volume decides
// every pair, without assuming it implements Go's Unicode tables.
var darwinPathTwins = []struct{ name, a, b string }{
	{"kelvin_sign", "link.exe", "lin" + string(rune(0x212A)) + ".exe"},
	{"long_s", "xs.exe", "x" + string(rune(0x017F)) + ".exe"},
	{"angstrom_sign", string(rune(0x00C5)) + "ngstrom.exe", string(rune(0x212B)) + "ngstrom.exe"},
	{"ohm_sign", string(rune(0x03A9)) + ".exe", string(rune(0x2126)) + ".exe"},
	{"micro_sign", string(rune(0x00B5)) + ".exe", string(rune(0x03BC)) + ".exe"},
	{"final_sigma", string(rune(0x03C3)) + ".exe", string(rune(0x03C2)) + ".exe"},
	{"ascii_case", "link.exe", "LINK.EXE"},
	{"georgian_mtavruli", string(rune(0x10D0)) + ".exe", string(rune(0x1C90)) + ".exe"},
	{"latin_cyrillic_a", "a.exe", string(rune(0x0430)) + ".exe"},
	{"latin_greek_o", "o.exe", string(rune(0x03BF)) + ".exe"},
}

func darwinPathGate(t *testing.T) {
	t.Helper()
	if os.Getenv("OA_PATH_IDENTITY_REPRODUCERS") != "1" {
		t.Skip("run by scripts/invariant_path_identity.py --gate (OA_PATH_IDENTITY_REPRODUCERS=1)")
	}
}

func darwinPathDir(t *testing.T) string {
	t.Helper()
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return dir
}

func darwinPathCreate(t *testing.T, path string) {
	t.Helper()
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
}

func darwinVolumeSame(t *testing.T, a, b string) bool {
	t.Helper()
	left, err := os.Stat(a)
	if err != nil {
		t.Fatal(err)
	}
	right, err := os.Stat(b)
	if err != nil {
		t.Fatal(err)
	}
	return os.SameFile(left, right)
}

func darwinTwinPaths(t *testing.T, a, b string, folders bool) (string, string, bool) {
	t.Helper()
	dir := darwinPathDir(t)
	left, right := filepath.Join(dir, a), filepath.Join(dir, b)
	create := func(path string) {
		if folders {
			if err := os.Mkdir(path, 0o700); err != nil {
				t.Fatal(err)
			}
		} else {
			darwinPathCreate(t, path)
		}
	}
	create(left)
	if _, err := os.Stat(right); errors.Is(err, os.ErrNotExist) {
		create(right)
	} else if err != nil {
		t.Fatal(err)
	}
	same := darwinVolumeSame(t, left, right)
	t.Logf("native volume: %q and %q same=%v", a, b, same)
	return left, right, same
}

func darwinNativeSame(t *testing.T, a, b string) bool {
	t.Helper()
	left, err := fileid.Resolve(context.Background(), fileid.Self, a, fileid.Options{})
	if err != nil {
		t.Fatal(err)
	}
	right, err := fileid.Resolve(context.Background(), fileid.Self, b, fileid.Options{})
	if err != nil {
		t.Fatal(err)
	}
	return left.Equal(right)
}

func TestPathIdentityTwinsSameProgram(t *testing.T) {
	darwinPathGate(t)
	distinct := 0
	for _, pair := range darwinPathTwins {
		t.Run(pair.name, func(t *testing.T) {
			a, b, want := darwinTwinPaths(t, pair.a, pair.b, false)
			if !want && pair.name != "ascii_case" {
				distinct++
			}
			if got := SameSubjectProgram(a, b); got != want {
				t.Fatalf("subject program equality=%v, native volume equality=%v", got, want)
			}
		})
	}
	if distinct == 0 {
		t.Fatal("the selected corpus supplied no volume-distinct Unicode pair")
	}
}

func TestPathIdentityTwinsSameFile(t *testing.T) {
	darwinPathGate(t)
	for _, pair := range darwinPathTwins {
		t.Run(pair.name, func(t *testing.T) {
			a, b, want := darwinTwinPaths(t, pair.a, pair.b, false)
			if got := samePath(a, b); got != want {
				t.Fatalf("peer same-file equality=%v, native volume equality=%v", got, want)
			}
			if got := darwinNativeSame(t, a, b); got != want {
				t.Fatalf("native FileID equality=%v, native volume equality=%v", got, want)
			}
		})
	}
}

func TestPathIdentityTwinsWithin(t *testing.T) {
	darwinPathGate(t)
	for _, pair := range darwinPathTwins {
		t.Run(pair.name, func(t *testing.T) {
			a, b, want := darwinTwinPaths(t, pair.a, pair.b, true)
			child := filepath.Join(b, "program")
			darwinPathCreate(t, child)
			if got := within(child, a); got != want {
				t.Fatalf("package containment=%v, native folder equality=%v", got, want)
			}
		})
	}
}

func TestPathIdentityTwinsAlternateSpelling(t *testing.T) {
	darwinPathGate(t)
	dir := darwinPathDir(t)
	a, b := filepath.Join(dir, "program"), filepath.Join(dir, "alternate-program-name")
	darwinPathCreate(t, a)
	if err := os.Link(a, b); err != nil {
		t.Fatal(err)
	}
	if !darwinVolumeSame(t, a, b) {
		t.Fatal("owned hard-link spellings do not name one file")
	}
	t.Run("SameSubjectProgram", func(t *testing.T) {
		if !SameSubjectProgram(a, b) {
			t.Fatal("one native file received two subject-program identities")
		}
	})
	t.Run("samePath", func(t *testing.T) {
		if !samePath(a, b) {
			t.Fatal("one native file received two peer file identities")
		}
	})
	t.Run("native_fileid", func(t *testing.T) {
		if !darwinNativeSame(t, a, b) {
			t.Fatal("one native file received two FileIDs")
		}
	})
}

func TestPathIdentityTwinsSymlink(t *testing.T) {
	darwinPathGate(t)
	dir := darwinPathDir(t)
	folder, outside := filepath.Join(dir, "folder"), filepath.Join(dir, "outside")
	for _, path := range []string{folder, outside} {
		if err := os.Mkdir(path, 0o700); err != nil {
			t.Fatal(err)
		}
		darwinPathCreate(t, filepath.Join(path, "program"))
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(folder, link); err != nil {
		t.Fatal(err)
	}
	a, b := filepath.Join(folder, "program"), filepath.Join(link, "program")
	if !darwinVolumeSame(t, a, b) {
		t.Fatal("owned symbolic link does not reach the native file")
	}
	t.Run("SameSubjectProgram", func(t *testing.T) {
		if !SameSubjectProgram(a, b) {
			t.Fatal("symbolic-link spelling changed subject identity")
		}
	})
	t.Run("samePath", func(t *testing.T) {
		if !samePath(a, b) {
			t.Fatal("symbolic-link spelling changed peer file identity")
		}
	})
	t.Run("native_fileid", func(t *testing.T) {
		if !darwinNativeSame(t, a, b) {
			t.Fatal("symbolic-link spelling changed native identity")
		}
	})
	t.Run("within", func(t *testing.T) {
		if !within(b, folder) {
			t.Fatal("symbolic link into the folder was treated as outside")
		}
	})
	t.Run("outside", func(t *testing.T) {
		escape := filepath.Join(folder, "escape")
		if err := os.Symlink(outside, escape); err != nil {
			t.Fatal(err)
		}
		if within(filepath.Join(escape, "program"), folder) {
			t.Fatal("symbolic link to another owned folder was treated as inside")
		}
	})
}
