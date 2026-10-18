package identity

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"golang.org/x/sys/windows"
)

// The path-identity reproducers that scripts/invariant_path_identity.py runs
// on every branch (go test -run TestPathIdentityTwins). The ruling they hold
// the owner to: whether two paths name one file is asked of the filesystem
// (VISION.md L623, from the 2026-09-08 ruling; DL-R31 in the download
// contract). Each case is made of real files on the volume under the test, and
// the volume is the oracle: a pair it keeps as two files is two programs and
// two files, and two spellings it resolves to one file are one.
//
// Every identity function that answers a path question is held to it:
// SameSubjectProgram, the owner every program comparison goes through;
// samePath, peer identity's same-file comparison; within, the package-folder
// check; and underDirectory, the Windows-directory check. The privatedir
// package holds its samePath and under to the same cases.

const pathIdentityRuling = "whether two paths name one file is asked of the filesystem (VISION.md L623; DL-R31: os.SameFile)"

// The one skip the gate accepts, matched by this exact prefix: a volume with
// 8.3 names turned off, shown by a probe that makes a long name and asks for
// its alias; the probe's result follows the prefix. Junctions need no
// administrator rights and no volume feature on NTFS, so a junction that
// cannot be made fails its test. Any other skip of a reproducer fails the gate.
const pathIdentitySkipShortName = "path identity: this volume gives no 8.3 alias (8.3 names are disabled on it); probe: "

// pathIdentityShortNameProbe makes a long name in dir and returns its 8.3
// alias, or skips the test with the probe's result when the volume gives none.
func pathIdentityShortNameProbe(t *testing.T, long string) string {
	t.Helper()
	short, err := pathIdentityShortErr(long)
	if err != nil {
		t.Skip(pathIdentitySkipShortName + "GetShortPathNameW " + long + ": " + err.Error())
	}
	if short == long {
		t.Skip(pathIdentitySkipShortName + "GetShortPathNameW returned the long name " + long)
	}
	return short
}

// pathIdentityReproducers is set by scripts/invariant_path_identity.py --gate,
// which runs these tests on every change and holds their results against
// the [expected-reproducers] and [failing-reproducers] rows of
// scripts/invariants/path_identity.baseline. Several fail on purpose until
// the owner asks the filesystem; a plain module test run skips them so a
// known defect does not turn every identity change red. The assertions are
// the same either way.
const pathIdentityReproducers = "OA_PATH_IDENTITY_REPRODUCERS"

func pathIdentityGate(t *testing.T) {
	t.Helper()
	if os.Getenv(pathIdentityReproducers) != "1" {
		t.Skipf("run by scripts/invariant_path_identity.py --gate on every change (set %s=1 to run here)", pathIdentityReproducers)
	}
}

// pathIdentityTwins are name pairs and what each tests. The first six are
// names NTFS keeps apart and Unicode case folding (strings.EqualFold) merges:
// a pair the volume holds as two files is never one. In the first four the
// two members differ in UTF-8 length, which hides them from a prefix check
// that slices by byte length; the micro sign and final sigma pairs have equal
// lengths and reach it. The last is one file under two spellings NTFS folds
// together: an owner that compares exact strings fails it. Each non-ASCII
// member is built from its code point, so the source shows which character it
// is.
var pathIdentityTwins = []struct{ name, a, b string }{
	{"kelvin_sign", "link.exe", "lin" + string(rune(0x212A)) + ".exe"},
	{"long_s", "xs.exe", "x" + string(rune(0x017F)) + ".exe"},
	{"angstrom_sign", string(rune(0x00C5)) + "ngstrom.exe", string(rune(0x212B)) + "ngstrom.exe"},
	{"ohm_sign", string(rune(0x03A9)) + ".exe", string(rune(0x2126)) + ".exe"},
	{"micro_sign", string(rune(0x00B5)) + ".exe", string(rune(0x03BC)) + ".exe"},
	{"final_sigma", string(rune(0x03C3)) + ".exe", string(rune(0x03C2)) + ".exe"},
	{"ascii_case", "link.exe", "LINK.EXE"},
}

// pathIdentityDir is a fresh temporary folder spelled by its long name, so a
// short component in the temporary folder's own path cannot decide a case.
func pathIdentityDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if long, ok := pathIdentityLong(dir); ok {
		dir = long
	}
	return dir
}

func pathIdentityLong(p string) (string, bool) {
	u, err := windows.UTF16PtrFromString(p)
	if err != nil {
		return "", false
	}
	buf := make([]uint16, windows.MAX_LONG_PATH)
	n, err := windows.GetLongPathName(u, &buf[0], uint32(len(buf)))
	if err != nil || n == 0 || n >= uint32(len(buf)) {
		return "", false
	}
	return windows.UTF16ToString(buf[:n]), true
}

func pathIdentityShortErr(p string) (string, error) {
	u, err := windows.UTF16PtrFromString(p)
	if err != nil {
		return "", err
	}
	buf := make([]uint16, windows.MAX_LONG_PATH)
	n, err := windows.GetShortPathName(u, &buf[0], uint32(len(buf)))
	if err != nil {
		return "", err
	}
	if n == 0 || n >= uint32(len(buf)) {
		return "", fmt.Errorf("GetShortPathNameW returned %d characters", n)
	}
	return windows.UTF16ToString(buf[:n]), nil
}

func pathIdentityCreate(t *testing.T, p string) {
	t.Helper()
	f, err := os.OpenFile(p, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatalf("create %q: %v", p, err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
}

// pathIdentityVolumeSame asks the volume whether a and b, both existing, are
// one file.
func pathIdentityVolumeSame(t *testing.T, a, b string) bool {
	t.Helper()
	fa, err := os.Stat(a)
	if err != nil {
		t.Fatalf("stat %q: %v", a, err)
	}
	fb, err := os.Stat(b)
	if err != nil {
		t.Fatalf("stat %q: %v", b, err)
	}
	return os.SameFile(fa, fb)
}

// pathIdentityTwinFiles makes the pair in a fresh folder and reports whether
// the volume holds them as one file: it creates a, then b only when the volume
// does not already resolve b to a.
func pathIdentityTwinFiles(t *testing.T, a, b string) (pa, pb string, same bool) {
	t.Helper()
	dir := pathIdentityDir(t)
	pa, pb = filepath.Join(dir, a), filepath.Join(dir, b)
	pathIdentityCreate(t, pa)
	if _, err := os.Stat(pb); err == nil {
		return pa, pb, pathIdentityVolumeSame(t, pa, pb)
	}
	pathIdentityCreate(t, pb)
	return pa, pb, pathIdentityVolumeSame(t, pa, pb)
}

// pathIdentityTwinFolders makes two folders named as the pair and reports
// whether the volume holds them as one folder.
func pathIdentityTwinFolders(t *testing.T, a, b string) (fa, fb string, same bool) {
	t.Helper()
	dir := pathIdentityDir(t)
	fa, fb = filepath.Join(dir, a), filepath.Join(dir, b)
	if err := os.Mkdir(fa, 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(fb); err != nil {
		if err := os.Mkdir(fb, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	return fa, fb, pathIdentityVolumeSame(t, fa, fb)
}

// pathIdentityJunction makes link a junction to target; the junction is
// removed afterwards, never its target. NTFS needs no administrator rights
// and no volume feature for a junction, so failing to make one fails the
// test with the error.
func pathIdentityJunction(t *testing.T, link, target string) {
	t.Helper()
	if out, err := exec.Command("cmd", "/c", "mklink", "/J", link, target).CombinedOutput(); err != nil {
		t.Fatalf("mklink /J %q %q: %v %s", link, target, err, out)
	}
	t.Cleanup(func() {
		if p, err := windows.UTF16PtrFromString(link); err == nil {
			//unchecked: test cleanup; removes the junction itself, never what it points at
			windows.RemoveDirectory(p)
		}
	})
}

// TestPathIdentityTwinsSameProgram: a twin pair the volume keeps as two files
// is never one program, and one file under two spellings is one program.
func TestPathIdentityTwinsSameProgram(t *testing.T) {
	pathIdentityGate(t)
	for _, c := range pathIdentityTwins {
		t.Run(c.name, func(t *testing.T) {
			pa, pb, want := pathIdentityTwinFiles(t, c.a, c.b)
			if got := SameSubjectProgram(pa, pb); got != want {
				t.Errorf("SameSubjectProgram(%q, %q) = %v; the volume says one file: %v. Ruling: %s",
					pa, pb, got, want, pathIdentityRuling)
			}
		})
	}
}

// TestPathIdentityTwinsSameFile: peer identity's same-file comparison answers
// what the volume answers for every pair.
func TestPathIdentityTwinsSameFile(t *testing.T) {
	pathIdentityGate(t)
	for _, c := range pathIdentityTwins {
		t.Run(c.name, func(t *testing.T) {
			pa, pb, want := pathIdentityTwinFiles(t, c.a, c.b)
			if got := samePath(pa, pb); got != want {
				t.Errorf("samePath(%q, %q) = %v; the volume says one file: %v. Ruling: %s",
					pa, pb, got, want, pathIdentityRuling)
			}
		})
	}
}

// TestPathIdentityTwinsJunction: a path through a junction and the path of
// its target name one file, and a same-file question answers yes.
func TestPathIdentityTwinsJunction(t *testing.T) {
	pathIdentityGate(t)
	dir := pathIdentityDir(t)
	target := filepath.Join(dir, "target")
	if err := os.Mkdir(target, 0o700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "junction")
	pathIdentityJunction(t, link, target)
	direct := filepath.Join(target, "program.exe")
	through := filepath.Join(link, "program.exe")
	pathIdentityCreate(t, direct)
	if !pathIdentityVolumeSame(t, direct, through) {
		t.Fatalf("the volume does not resolve %q to %q", through, direct)
	}
	t.Run("SameSubjectProgram", func(t *testing.T) {
		if !SameSubjectProgram(through, direct) {
			t.Errorf("SameSubjectProgram(%q, %q) = false; they are one file. Ruling: %s", through, direct, pathIdentityRuling)
		}
	})
	t.Run("samePath", func(t *testing.T) {
		if !samePath(through, direct) {
			t.Errorf("samePath(%q, %q) = false; they are one file. Ruling: %s", through, direct, pathIdentityRuling)
		}
	})
}

// TestPathIdentityTwinsShortName: an 8.3 alias and its long name are one file.
func TestPathIdentityTwinsShortName(t *testing.T) {
	pathIdentityGate(t)
	dir := pathIdentityDir(t)
	long := filepath.Join(dir, "PathIdentityLongProgramName.exe")
	pathIdentityCreate(t, long)
	short := pathIdentityShortNameProbe(t, long)
	if !pathIdentityVolumeSame(t, short, long) {
		t.Fatalf("the volume does not resolve %q to %q", short, long)
	}
	t.Run("SameSubjectProgram", func(t *testing.T) {
		if !SameSubjectProgram(short, long) {
			t.Errorf("SameSubjectProgram(%q, %q) = false; they are one file. Ruling: %s", short, long, pathIdentityRuling)
		}
	})
	t.Run("samePath", func(t *testing.T) {
		if !samePath(short, long) {
			t.Errorf("samePath(%q, %q) = false; they are one file. Ruling: %s", short, long, pathIdentityRuling)
		}
	})
}

// pathIdentityContainment holds a containment check, inside(path, folder), to
// the volume:
//   - a file in a twin folder the volume keeps apart from the folder is not
//     inside it; a file in a folder the volume folds into it (ascii_case) is;
//   - a file reached through a junction into the folder is inside it;
//   - a file reached through the folder's 8.3 alias is inside it.
func pathIdentityContainment(t *testing.T, name string, inside func(path, folder string) bool) {
	t.Helper()
	pathIdentityGate(t)
	for _, c := range pathIdentityTwins {
		t.Run(c.name, func(t *testing.T) {
			fa, fb, want := pathIdentityTwinFolders(t, c.a, c.b)
			file := filepath.Join(fb, "program.exe")
			pathIdentityCreate(t, file)
			if got := inside(file, fa); got != want {
				t.Errorf("%s(%q, %q) = %v; the volume says the folders are one: %v. Ruling: %s",
					name, file, fa, got, want, pathIdentityRuling)
			}
		})
	}
	t.Run("junction", func(t *testing.T) {
		dir := pathIdentityDir(t)
		folder := filepath.Join(dir, "folder")
		if err := os.Mkdir(folder, 0o700); err != nil {
			t.Fatal(err)
		}
		link := filepath.Join(dir, "junction")
		pathIdentityJunction(t, link, folder)
		pathIdentityCreate(t, filepath.Join(folder, "program.exe"))
		through := filepath.Join(link, "program.exe")
		if !inside(through, folder) {
			t.Errorf("%s(%q, %q) = false; the file is in the folder. Ruling: %s", name, through, folder, pathIdentityRuling)
		}
	})
	t.Run("short_name", func(t *testing.T) {
		dir := pathIdentityDir(t)
		folder := filepath.Join(dir, "PathIdentityLongFolderName")
		if err := os.Mkdir(folder, 0o700); err != nil {
			t.Fatal(err)
		}
		short := pathIdentityShortNameProbe(t, folder)
		pathIdentityCreate(t, filepath.Join(folder, "program.exe"))
		through := filepath.Join(short, "program.exe")
		if !inside(through, folder) {
			t.Errorf("%s(%q, %q) = false; the file is in the folder. Ruling: %s", name, through, folder, pathIdentityRuling)
		}
	})
}

// TestPathIdentityTwinsWithin holds program.go's package-folder check.
func TestPathIdentityTwinsWithin(t *testing.T) {
	pathIdentityContainment(t, "within", within)
}

// TestPathIdentityTwinsUnderDirectory holds authenticode_windows.go's
// Windows-directory check.
func TestPathIdentityTwinsUnderDirectory(t *testing.T) {
	pathIdentityContainment(t, "underDirectory", underDirectory)
}
