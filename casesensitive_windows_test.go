package identity

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// caseSensitiveFolder makes a folder under the test's temporary folder with
// NTFS per-directory case sensitivity on (fsutil file setCaseSensitiveInfo),
// or skips with fsutil's answer when this account or volume cannot.
func caseSensitiveFolder(t *testing.T) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "case-sensitive")
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command("fsutil.exe", "file", "setCaseSensitiveInfo", dir, "enable").CombinedOutput(); err != nil {
		t.Skipf("fsutil cannot make a case-sensitive folder here: %v %s", err, out)
	}
	return dir
}

// Names that match only ignoring case are one program by name alone only
// when a side does not exist; two existing files in a case-sensitive folder
// whose names differ only in case are two programs, by file identity.
func TestCaseDifferentProgramsInACaseSensitiveFolderAreTwo(t *testing.T) {
	dir := caseSensitiveFolder(t)
	upper, lower := filepath.Join(dir, "App.exe"), filepath.Join(dir, "app.exe")
	for _, p := range []string{upper, lower} {
		if err := os.WriteFile(p, []byte(p), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if entries, err := os.ReadDir(dir); err != nil || len(entries) != 2 {
		t.Fatalf("the folder does not hold two files differing in case: %d %v", len(entries), err)
	}
	if SameSubjectProgram(upper, lower) {
		t.Errorf("SameSubjectProgram(%q, %q): two files compared as one program", upper, lower)
	}
	if !SameSubjectProgram(upper, upper) {
		t.Errorf("SameSubjectProgram(%q, itself) is false", upper)
	}
	// A side that does not exist is matched by name.
	if !SameSubjectProgram(upper, filepath.Join(dir, "APP.exe")) {
		t.Errorf("a program not yet installed did not match by name")
	}
}
