package identity

import (
	"errors"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/windows"
)

// twinNamePairs are names Unicode case folding treats as equal and NTFS
// keeps apart (KELVIN SIGN, LONG S, ANGSTROM SIGN, OHM SIGN), and names that
// differ only in ordinary case, which NTFS treats as one.
var twinNamePairs = [][2]string{
	{"link", "linK"},
	{"xs", "xſ"},
	{"å", "Å"},
	{"ω", "Ω"},
	{"Panel", "pANEL"},
	{"ä", "Ä"},
}

// sameOnDisk asks the file system: it creates a, then creates b exclusively
// in the same folder; b exists already exactly when the two name one file.
func sameOnDisk(t *testing.T, a, b string) bool {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, a), []byte("a"), 0o600); err != nil {
		t.Fatal(err)
	}
	f, err := os.OpenFile(filepath.Join(dir, b), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if errors.Is(err, fs.ErrExist) {
		return true
	}
	if err != nil {
		t.Fatal(err)
	}
	f.Close()
	return false
}

// SamePathName and PathNameKey, the name rule for files that may not exist,
// follow the file system's own rule (the system uppercase table), never
// Unicode case folding: every pair reads the same as NTFS reads it, and the
// twins with a KELVIN SIGN or a LONG S are two names.
func TestPathNamesCompareAsTheFileSystemDoes(t *testing.T) {
	for _, pair := range twinNamePairs {
		a, b := pair[0], pair[1]
		disk := sameOnDisk(t, a, b)
		if got := SamePathName(a, b); got != disk {
			t.Errorf("SamePathName(%q, %q) = %v; the file system says %v", a, b, got, disk)
		}
		if got := PathNameKey(a) == PathNameKey(b); got != disk {
			t.Errorf("PathNameKey(%q) == PathNameKey(%q) is %v; the file system says %v", a, b, got, disk)
		}
	}
	for _, twin := range [][2]string{{"link", "linK"}, {"xs", "xſ"}} {
		if sameOnDisk(t, twin[0], twin[1]) {
			t.Fatalf("this file system keeps %q and %q as one name", twin[0], twin[1])
		}
	}
}

func shortPath(t *testing.T, p string) (string, bool) {
	t.Helper()
	u, err := windows.UTF16PtrFromString(p)
	if err != nil {
		t.Fatal(err)
	}
	buf := make([]uint16, windows.MAX_LONG_PATH)
	n, err := windows.GetShortPathName(u, &buf[0], uint32(len(buf)))
	if err != nil || n == 0 || n >= uint32(len(buf)) {
		return "", false
	}
	short := windows.UTF16ToString(buf[:n])
	return short, !strings.EqualFold(short, p)
}

// junction makes link a junction to target, or skips when the volume will
// not hold one.
func junction(t *testing.T, link, target string) {
	t.Helper()
	if out, err := exec.Command("cmd", "/c", "mklink", "/J", link, target).CombinedOutput(); err != nil {
		t.Skipf("this volume will not hold a junction: mklink /J: %v %s", err, out)
	}
	t.Cleanup(func() {
		if p, err := windows.UTF16PtrFromString(link); err == nil {
			//unchecked: test cleanup; removes the junction itself, never what it points at
			windows.RemoveDirectory(p)
		}
	})
}

// SameFile, Within and FileKey answer by file identity: twins NTFS keeps
// apart are two files; a junction and its target, and an 8.3 alias and its
// long name, are one; a missing side answers false with its error.
func TestPathIdentityOwnerAnswersByFileIdentity(t *testing.T) {
	dir := t.TempDir()
	if long, err := filepath.EvalSymlinks(dir); err == nil {
		dir = long
	}
	t.Run("twins", func(t *testing.T) {
		for _, twin := range [][2]string{{"link", "linK"}, {"xs", "xſ"}, {"å", "Å"}, {"ω", "Ω"}, {"µ", "μ"}, {"σ", "ς"}} {
			a, b := filepath.Join(dir, twin[0]), filepath.Join(dir, twin[1])
			for _, folder := range []string{a, b} {
				if err := os.Mkdir(folder, 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(folder, "app.exe"), []byte(folder), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			if same, err := SameFile(a, b); err != nil || same {
				t.Errorf("SameFile(%q, %q) = %v, %v; NTFS keeps them apart", a, b, same, err)
			}
			if inside, err := Within(filepath.Join(b, "app.exe"), a); err != nil || inside {
				t.Errorf("Within(%q in %q) = %v, %v; a twin folder is another folder", b, a, inside, err)
			}
			if inside, err := Within(filepath.Join(a, "app.exe"), a); err != nil || !inside {
				t.Errorf("Within(a file of %q) = %v, %v", a, inside, err)
			}
			ka, errA := FileKey(a)
			kb, errB := FileKey(b)
			if errA != nil || errB != nil || ka == kb {
				t.Errorf("FileKey(%q) = %q, FileKey(%q) = %q (%v, %v); two files need two keys", a, ka, b, kb, errA, errB)
			}
			if samePath(filepath.Join(a, "app.exe"), filepath.Join(b, "app.exe")) || SameSubjectProgram(filepath.Join(a, "app.exe"), filepath.Join(b, "app.exe")) {
				t.Errorf("the programs in %q and %q compared as one", a, b)
			}
		}
	})
	t.Run("junction", func(t *testing.T) {
		target := filepath.Join(dir, "target")
		if err := os.Mkdir(target, 0o755); err != nil {
			t.Fatal(err)
		}
		link := filepath.Join(dir, "junction")
		junction(t, link, target)
		direct, through := filepath.Join(target, "program.exe"), filepath.Join(link, "program.exe")
		if err := os.WriteFile(direct, []byte("p"), 0o600); err != nil {
			t.Fatal(err)
		}
		if same, err := SameFile(through, direct); err != nil || !same {
			t.Errorf("SameFile(%q, %q) = %v, %v; one file", through, direct, same, err)
		}
		if inside, err := Within(through, target); err != nil || !inside {
			t.Errorf("Within(%q, %q) = %v, %v; the file lies in the target", through, target, inside, err)
		}
		kd, _ := FileKey(direct)
		kt, _ := FileKey(through)
		if kd == "" || kd != kt {
			t.Errorf("FileKey through the junction %q, direct %q", kt, kd)
		}
		if !SameSubjectProgram(through, direct) || !samePath(through, direct) {
			t.Errorf("a program reached through a junction is not its target")
		}
	})
	t.Run("short_name", func(t *testing.T) {
		folder := filepath.Join(dir, "PathIdentityLongFolderName")
		if err := os.Mkdir(folder, 0o755); err != nil {
			t.Fatal(err)
		}
		long := filepath.Join(folder, "PathIdentityLongProgramName.exe")
		if err := os.WriteFile(long, []byte("p"), 0o600); err != nil {
			t.Fatal(err)
		}
		short, ok := shortPath(t, long)
		shortFolder, okFolder := shortPath(t, folder)
		if !ok || !okFolder {
			t.Skip("this volume gives no 8.3 aliases")
		}
		if same, err := SameFile(short, long); err != nil || !same {
			t.Errorf("SameFile(%q, %q) = %v, %v; one file", short, long, same, err)
		}
		if inside, err := Within(long, shortFolder); err != nil || !inside {
			t.Errorf("Within(%q, %q) = %v, %v", long, shortFolder, inside, err)
		}
		if inside, err := Within(short, folder); err != nil || !inside {
			t.Errorf("Within(%q, %q) = %v, %v", short, folder, inside, err)
		}
		if !SameSubjectProgram(short, long) || !samePath(short, long) {
			t.Errorf("an 8.3 alias of a program is not the program")
		}
	})
	t.Run("missing", func(t *testing.T) {
		missing := filepath.Join(dir, "missing.exe")
		if same, err := SameFile(missing, missing); same || !errors.Is(err, fs.ErrNotExist) {
			t.Errorf("SameFile of a missing file = %v, %v; want false with ErrNotExist", same, err)
		}
		if _, err := FileKey(missing); err == nil {
			t.Error("FileKey of a missing file has a key")
		}
		// A file not created yet lies where its existing folder lies.
		if inside, err := Within(filepath.Join(dir, "later", "app.exe"), dir); err != nil || !inside {
			t.Errorf("Within(a file still to be created in %q) = %v, %v", dir, inside, err)
		}
		// A folder not created yet holds only paths spelled exactly below it.
		future := filepath.Join(dir, "future")
		if !Inside(filepath.Join(future, "app.exe"), future) || Inside(filepath.Join(dir, "FUTURE", "app.exe"), future) ||
			Inside(filepath.Join(dir, "futurK", "app.exe"), filepath.Join(dir, "futurk")) {
			t.Error("Inside of a folder not created yet does not compare spellings exactly")
		}
	})
}

// Peer identity compares kernel-reported paths (samePath) and checks that an
// image lies under a protected folder (underDirectory). Neither may take a
// twin file or folder for the real one.
func TestPeerPathChecksRefuseTwinNames(t *testing.T) {
	dir := t.TempDir()
	for _, twin := range [][2]string{{"link", "linK"}, {"xs", "xſ"}, {"µ", "μ"}, {"σ", "ς"}} {
		real, other := filepath.Join(dir, twin[0]), filepath.Join(dir, twin[1])
		for _, folder := range []string{real, other} {
			if err := os.Mkdir(folder, 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(folder, "app.exe"), []byte(folder), 0o600); err != nil {
				t.Fatal(err)
			}
		}
		if samePath(filepath.Join(real, "app.exe"), filepath.Join(other, "app.exe")) {
			t.Errorf("samePath took the program in %q for the one in %q", other, real)
		}
		if underDirectory(filepath.Join(other, "app.exe"), real) || within(filepath.Join(other, "app.exe"), real) {
			t.Errorf("a file in %q read as under %q", other, real)
		}
		if !underDirectory(filepath.Join(real, "app.exe"), real) {
			t.Errorf("underDirectory refused a file in %q", real)
		}
	}
}
