package privatedir

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	identity "github.com/openabstractions/abstraction-identity"
	"golang.org/x/sys/windows"
)

// The privatedir path-identity reproducers, run by
// scripts/invariant_path_identity.py --gate with the identity package's
// TestPathIdentityTwins* (see abstraction-identity/pathidentity_twins_windows_test.go
// for the ruling and the cases). They hold samePath, the same-file comparison
// of the model-folder checks, and under, their containment check, to what the
// volume says.

const pidRuling = "whether two paths name one file is asked of the filesystem (VISION.md L623; DL-R31: os.SameFile)"

// The one skip the gate accepts, matched by this exact prefix (the identity
// package's): a volume whose 8.3 probe gives no alias, with the probe's result
// after the prefix. A junction that cannot be made fails its test.
const pidSkipShortName = "path identity: this volume gives no 8.3 alias (8.3 names are disabled on it); probe: "

func pidShortNameProbe(t *testing.T, long string) string {
	t.Helper()
	u, err := windows.UTF16PtrFromString(long)
	if err != nil {
		t.Fatal(err)
	}
	buf := make([]uint16, windows.MAX_LONG_PATH)
	n, err := windows.GetShortPathName(u, &buf[0], uint32(len(buf)))
	if err != nil {
		t.Skip(pidSkipShortName + "GetShortPathNameW " + long + ": " + err.Error())
	}
	if n == 0 || n >= uint32(len(buf)) {
		t.Fatalf("GetShortPathNameW %s returned %d characters", long, n)
	}
	short := windows.UTF16ToString(buf[:n])
	if short == long {
		t.Skip(pidSkipShortName + "GetShortPathNameW returned the long name " + long)
	}
	return short
}

func pidGate(t *testing.T) {
	t.Helper()
	if os.Getenv("OA_PATH_IDENTITY_REPRODUCERS") != "1" {
		t.Skip("run by scripts/invariant_path_identity.py --gate on every change (set OA_PATH_IDENTITY_REPRODUCERS=1 to run here)")
	}
}

// pidTwins: the first six are names NTFS keeps apart and Unicode case folding
// merges (micro sign and final sigma with members of equal UTF-8 length);
// ascii_case is one name NTFS folds together. Non-ASCII members are built
// from their code points.
var pidTwins = []struct{ name, a, b string }{
	{"kelvin_sign", "link.exe", "lin" + string(rune(0x212A)) + ".exe"},
	{"long_s", "xs.exe", "x" + string(rune(0x017F)) + ".exe"},
	{"angstrom_sign", string(rune(0x00C5)) + "ngstrom.exe", string(rune(0x212B)) + "ngstrom.exe"},
	{"ohm_sign", string(rune(0x03A9)) + ".exe", string(rune(0x2126)) + ".exe"},
	{"micro_sign", string(rune(0x00B5)) + ".exe", string(rune(0x03BC)) + ".exe"},
	{"final_sigma", string(rune(0x03C3)) + ".exe", string(rune(0x03C2)) + ".exe"},
	{"ascii_case", "link.exe", "LINK.EXE"},
}

func pidDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	u, err := windows.UTF16PtrFromString(dir)
	if err != nil {
		return dir
	}
	buf := make([]uint16, windows.MAX_LONG_PATH)
	if n, err := windows.GetLongPathName(u, &buf[0], uint32(len(buf))); err == nil && n > 0 && n < uint32(len(buf)) {
		return windows.UTF16ToString(buf[:n])
	}
	return dir
}

func pidCreate(t *testing.T, p string) {
	t.Helper()
	f, err := os.OpenFile(p, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatalf("create %q: %v", p, err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
}

func pidMkdir(t *testing.T, p string) {
	t.Helper()
	if _, err := os.Stat(p); err == nil {
		return
	}
	if err := os.Mkdir(p, 0o700); err != nil {
		t.Fatal(err)
	}
}

func pidSame(t *testing.T, a, b string) bool {
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

func pidJunction(t *testing.T, link, target string) {
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

// samePath is the model-folder checks' same-file comparison: the owner's
// identity.SameFile, which privatedir calls directly.
func samePath(a, b string) bool {
	same, err := identity.SameFile(a, b)
	return err == nil && same
}

// TestPathIdentityTwinsPrivatedirSamePath: identity.SameFile, as the
// model-folder checks call it, answers what the volume answers for every
// pair, a junction path and an 8.3 alias.
func TestPathIdentityTwinsPrivatedirSamePath(t *testing.T) {
	pidGate(t)
	for _, c := range pidTwins {
		t.Run(c.name, func(t *testing.T) {
			dir := pidDir(t)
			pa, pb := filepath.Join(dir, c.a), filepath.Join(dir, c.b)
			pidCreate(t, pa)
			if _, err := os.Stat(pb); err != nil {
				pidCreate(t, pb)
			}
			want := pidSame(t, pa, pb)
			if got := samePath(pa, pb); got != want {
				t.Errorf("samePath(%q, %q) = %v; the volume says one file: %v. Ruling: %s", pa, pb, got, want, pidRuling)
			}
		})
	}
	t.Run("junction", func(t *testing.T) {
		dir := pidDir(t)
		target, link := filepath.Join(dir, "target"), filepath.Join(dir, "junction")
		pidMkdir(t, target)
		pidJunction(t, link, target)
		if !samePath(link, target) {
			t.Errorf("samePath(%q, %q) = false; they are one folder. Ruling: %s", link, target, pidRuling)
		}
	})
	t.Run("short_name", func(t *testing.T) {
		dir := pidDir(t)
		long := filepath.Join(dir, "PathIdentityLongFolderName")
		pidMkdir(t, long)
		short := pidShortNameProbe(t, long)
		if !samePath(short, long) {
			t.Errorf("samePath(%q, %q) = false; they are one folder. Ruling: %s", short, long, pidRuling)
		}
	})
}

// TestPathIdentityTwinsPrivatedirUnder: a file in a twin folder the volume
// keeps apart is not under the root; one reached through a junction into the
// root, or through the root's 8.3 alias, is.
func TestPathIdentityTwinsPrivatedirUnder(t *testing.T) {
	pidGate(t)
	for _, c := range pidTwins {
		t.Run(c.name, func(t *testing.T) {
			dir := pidDir(t)
			fa, fb := filepath.Join(dir, c.a), filepath.Join(dir, c.b)
			pidMkdir(t, fa)
			pidMkdir(t, fb)
			want := pidSame(t, fa, fb)
			file := filepath.Join(fb, "model.gguf")
			pidCreate(t, file)
			if got := under(file, []string{fa}); got != want {
				t.Errorf("under(%q, [%q]) = %v; the volume says the folders are one: %v. Ruling: %s", file, fa, got, want, pidRuling)
			}
			if got, err := identity.Within(file, fa); err != nil || got != want {
				t.Errorf("identity.Within(%q, %q) = %v, %v; the volume says the folders are one: %v. Ruling: %s", file, fa, got, err, want, pidRuling)
			}
		})
	}
	t.Run("junction", func(t *testing.T) {
		dir := pidDir(t)
		root, link := filepath.Join(dir, "root"), filepath.Join(dir, "junction")
		pidMkdir(t, root)
		pidJunction(t, link, root)
		pidCreate(t, filepath.Join(root, "model.gguf"))
		through := filepath.Join(link, "model.gguf")
		if !under(through, []string{root}) {
			t.Errorf("under(%q, [%q]) = false; the file is in the root. Ruling: %s", through, root, pidRuling)
		}
	})
	t.Run("short_name", func(t *testing.T) {
		dir := pidDir(t)
		root := filepath.Join(dir, "PathIdentityLongFolderName")
		pidMkdir(t, root)
		short := pidShortNameProbe(t, root)
		pidCreate(t, filepath.Join(root, "model.gguf"))
		through := filepath.Join(short, "model.gguf")
		if !under(through, []string{root}) {
			t.Errorf("under(%q, [%q]) = false; the file is in the root. Ruling: %s", through, root, pidRuling)
		}
	})
}
