package identity

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"golang.org/x/sys/windows"
)

// notLocalPaths are paths identity must refuse before any open: a UNC path in
// both spellings, \\?\UNC, a pipe, \\?\GLOBALROOT, a \\.\ drive, an NT object
// path, and device names alone and in a folder with an extension, a stream
// or a trailing space.
var notLocalPaths = []string{
	`\\192.0.2.1\share\app.exe`,
	`//192.0.2.1/share/app.exe`,
	`\\?\UNC\192.0.2.1\share\app.exe`,
	`\\.\pipe\oa-identity-refused`,
	`\\?\GLOBALROOT\Device\HarddiskVolume1\Windows\notepad.exe`,
	`\\?\Volume{00000000-0000-0000-0000-000000000000}\app.exe`,
	`\\.\C:\Windows\notepad.exe`,
	`\??\C:\Windows\notepad.exe`,
	`CON`,
	`C:\Windows\con.txt`,
	`C:\Windows\AUX`,
	`C:\Windows\nul .log`,
	`C:\Windows\COM1:stream`,
	`C:\Windows\lpt¹.txt`,
	`C:\Windows\CONOUT$`,
	`\\?\C:\Windows\prn`,
}

// observeOpens records every path identity opens or reads by name while it
// runs, through openObserver.
func observeOpens(t *testing.T) func() []string {
	t.Helper()
	var mu sync.Mutex
	var seen []string
	observe := func(path string) {
		mu.Lock()
		seen = append(seen, path)
		mu.Unlock()
	}
	stop, ok := ObserveOpens(observe)
	if !ok {
		t.Fatal("another test holds the open observer")
	}
	t.Cleanup(stop)
	return func() []string {
		mu.Lock()
		defer mu.Unlock()
		return append([]string(nil), seen...)
	}
}

// R1: every path function refuses a path that is not on a local drive with
// ErrNotLocalPath and opens nothing, even when its other side is local; a
// local path is opened, so the observer sees opens when there are any.
func TestPathIdentityRefusesPathsOffALocalDriveWithoutOpening(t *testing.T) {
	dir := t.TempDir()
	local := filepath.Join(dir, "app.exe")
	if err := os.WriteFile(local, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	opens := observeOpens(t)
	if same, err := SameFile(local, local); err != nil || !same {
		t.Fatalf("SameFile of a local file: %v %v", same, err)
	}
	if len(opens()) == 0 {
		t.Fatal("the observer saw no open for a local file")
	}
	before := len(opens())
	for _, p := range notLocalPaths {
		if err := LocalPath(p); !errors.Is(err, ErrNotLocalPath) {
			t.Errorf("LocalPath(%q) = %v", p, err)
		}
		var typed *NotLocalPathError
		if err := LocalPath(p); !errors.As(err, &typed) || typed.Path != p || typed.Reason == "" {
			t.Errorf("LocalPath(%q) is not a NotLocalPathError naming it: %v", p, err)
		}
		calls := map[string]error{}
		_, calls["SameFile(p, local)"] = SameFile(p, local)
		_, calls["SameFile(local, p)"] = SameFile(local, p)
		_, calls["Within(p, dir)"] = Within(p, dir)
		_, calls["Within(local, p)"] = Within(local, p)
		_, _, calls["WithinRel(p, dir)"] = WithinRel(p, dir)
		_, calls["FileKey(p)"] = FileKey(p)
		_, calls["PlaceKey(p)"] = PlaceKey(p)
		for call, err := range calls {
			if !errors.Is(err, ErrNotLocalPath) {
				t.Errorf("%s with p=%q: %v; want ErrNotLocalPath", call, p, err)
			}
		}
		if Inside(p, dir) || Inside(local, p) || Inside(p+`\child.exe`, p) {
			t.Errorf("Inside placed %q by spelling", p)
		}
		if ProgramKey(p) != "" {
			t.Errorf("ProgramKey(%q) is not empty", p)
		}
		if got := CanonicalProgramPath(p); got != p {
			t.Errorf("CanonicalProgramPath(%q) = %q; a refused path keeps its spelling", p, got)
		}
		if seen := opens(); len(seen) != before {
			t.Fatalf("refusing %q opened %q", p, seen[before:])
		}
	}
}

// R1: a program run from a share is matched by its name alone, without any
// open, and a short-shaped name on a share is never resolved: an edit
// storing it is refused.
func TestSubjectProgramsOnAShareCompareByNameWithoutOpening(t *testing.T) {
	opens := observeOpens(t)
	share := `\\192.0.2.1\share\Tools\app.exe`
	if !SameSubjectProgram(share, `\\192.0.2.1\SHARE\tools\APP.exe`) {
		t.Error("two spellings of one share program under the name rule compared as two")
	}
	if SameSubjectProgram(share, `\\192.0.2.1\share\Tools\other.exe`) {
		t.Error("two share programs compared as one")
	}
	if !UnresolvedShortName(`\\192.0.2.1\share\PROGRA~1\app.exe`) {
		t.Error("a short-shaped name on a share counted as resolved")
	}
	if seen := opens(); len(seen) != 0 {
		t.Fatalf("comparing share programs opened %q", seen)
	}
}

// R1: a drive letter mapped to a share is refused in every spelling of it,
// with nothing opened. The mapping is stood in by pathDriveType, so the test
// maps no drive.
func TestAMappedNetworkDriveIsRefusedWithoutOpening(t *testing.T) {
	saved := pathDriveType
	t.Cleanup(func() { pathDriveType = saved })
	pathDriveType = func(root string) uint32 {
		if strings.EqualFold(root, `X:\`) {
			return windows.DRIVE_REMOTE
		}
		return saved(root)
	}
	opens := observeOpens(t)
	for _, p := range []string{`X:\state\x`, `x:/state/x`, `\\?\X:\state\x`, `\??\X:\state\x`} {
		if err := LocalPath(p); !errors.Is(err, ErrNotLocalPath) {
			t.Errorf("LocalPath(%q) = %v", p, err)
		}
		if _, err := FileKey(p); !errors.Is(err, ErrNotLocalPath) {
			t.Errorf("FileKey(%q) = %v", p, err)
		}
	}
	// TreatDriveAsNetwork, the consumers' stand-in, marks a letter the same
	// way.
	restore := TreatDriveAsNetwork('Y')
	if _, err := FileKey(`y:\state\x`); !errors.Is(err, ErrNotLocalPath) {
		t.Errorf("a letter marked as a network drive: %v", err)
	}
	restore()
	if seen := opens(); len(seen) != 0 {
		t.Fatalf("a mapped drive was opened: %q", seen)
	}
}

func TestReservedDeviceNamesInAnyFolderAndExtension(t *testing.T) {
	for _, name := range []string{"con", "CON", "Con.txt", "con .txt", "con:stream", "PRN", "aux.tar.gz", "nul",
		"COM0", "com1", "COM9.log", "com¹", "LPT0", "lpt3.txt", "LPT²", "conin$", "CONOUT$.x"} {
		if !reservedDeviceName(name) {
			t.Errorf("%q is a device name", name)
		}
	}
	for _, name := range []string{"console", "com", "com10", "comx", "aux_", "conx.txt", "lpt", "nul-thing", "", ".", " con"} {
		if reservedDeviceName(name) {
			t.Errorf("%q is no device name", name)
		}
	}
	if err := LocalPath(`C:\Windows\console.exe`); err != nil {
		t.Errorf("an ordinary local path: %v", err)
	}
	if err := LocalPath(`\\?\C:\Windows\notepad.exe`); err != nil {
		t.Errorf(`a \\?\ local drive path: %v`, err)
	}
}

// Minor: a name still to be created keys without the trailing dots and
// spaces Windows strips when it creates it; a segment of only dots keeps its
// spelling.
func TestPlaceKeyTrimsWhatWindowsStripsOnCreate(t *testing.T) {
	dir := t.TempDir()
	for _, pair := range [][2]string{
		{filepath.Join(dir, "new."), filepath.Join(dir, "new")},
		{filepath.Join(dir, "new  "), filepath.Join(dir, "new")},
		{dir + `\new . \model.gguf`, filepath.Join(dir, "new", "model.gguf")},
		{dir + `\a..\b. .\c`, filepath.Join(dir, "a", "b", "c")},
	} {
		a, errA := PlaceKey(pair[0])
		b, errB := PlaceKey(pair[1])
		if errA != nil || errB != nil || a != b {
			t.Errorf("PlaceKey(%q) = %q, PlaceKey(%q) = %q (%v, %v)", pair[0], a, pair[1], b, errA, errB)
		}
	}
	// The key stays the same once Windows has created the folder, under the
	// name it strips.
	planned, err := PlaceKey(dir + `\made. \x`)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(dir+`\made. `, 0o755); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var made []string
	for _, e := range entries {
		made = append(made, e.Name())
	}
	if len(made) != 1 || made[0] != "made" {
		t.Fatalf("Windows created %q", made)
	}
	for _, p := range []string{dir + `\made. \x`, filepath.Join(dir, "made", "x")} {
		if created, err := PlaceKey(p); err != nil || created != planned || !strings.HasSuffix(created, `\MADE\X`) {
			t.Errorf("PlaceKey(%q) after the create = %q, before %q (%v)", p, created, planned, err)
		}
	}
	// A folder segment of only dots and spaces is no name Windows makes, and
	// keeps its spelling.
	if a, b := trimCreatedNames(dir+`\. .\x`), dir+`\. .\x`; a != b {
		t.Errorf("trimCreatedNames(%q) = %q", b, a)
	}
}
