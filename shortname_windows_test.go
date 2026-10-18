package identity

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/windows"
)

func TestHasShortNameComponentReadsTheSpellingOnly(t *testing.T) {
	for path, want := range map[string]bool{
		`C:\PROGRA~1\App\app.exe`:           true,
		`C:\Program Files\App\SUBJEC~2.EXE`: true,
		`C:\Program Files\App\app.exe`:      false,
		`C:\Tools\backup~old\app.exe`:       false,
		`C:\Tools\a~b\app.exe`:              false,
		`msix:Contoso.App_8wekyb3d8bbwe`:    false,
	} {
		if got := HasShortNameComponent(path); got != want {
			t.Errorf("HasShortNameComponent(%q) = %v, want %v", path, got, want)
		}
	}
}

// A short alias in a folder that exists reads long, even when the file below
// it does not exist yet; an alias for a folder that does not exist stays and
// is reported unresolved.
func TestCanonicalSpellingOfAFileNotYetCreated(t *testing.T) {
	folder := filepath.Join(t.TempDir(), "existing folder")
	if err := os.Mkdir(folder, 0o755); err != nil {
		t.Fatal(err)
	}
	p, err := windows.UTF16PtrFromString(folder)
	if err != nil {
		t.Fatal(err)
	}
	buf := make([]uint16, windows.MAX_LONG_PATH)
	n, err := windows.GetShortPathName(p, &buf[0], uint32(len(buf)))
	if err != nil {
		t.Fatal(err)
	}
	short := windows.UTF16ToString(buf[:n])
	if strings.EqualFold(short, folder) {
		t.Skip("filesystem has no distinct DOS alias for this folder")
	}
	missingFile := filepath.Join(short, "later.exe")
	if got, want := CanonicalProgramPath(missingFile), filepath.Join(CanonicalProgramPath(folder), "later.exe"); got != want {
		t.Fatalf("CanonicalProgramPath(%q) = %q, want %q", missingFile, got, want)
	}
	if UnresolvedShortName(missingFile) {
		t.Fatalf("%q resolves through an existing folder", missingFile)
	}
	missingFolder := filepath.Join(filepath.Dir(folder), "LATERF~1", "later.exe")
	if !UnresolvedShortName(missingFolder) {
		t.Fatalf("%q names an alias for no folder", missingFolder)
	}
}
