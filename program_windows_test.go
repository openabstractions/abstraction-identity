package identity

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/windows"
)

func TestSubjectProgramComparisonExpandsRealDOSAlias(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "program with spaces")
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	long := filepath.Join(dir, "subject.exe")
	if err := os.WriteFile(long, []byte("subject"), 0o600); err != nil {
		t.Fatal(err)
	}
	short := windowsTestPathName(t, long, true)
	wantLong := windowsTestPathName(t, long, false)
	if strings.EqualFold(short, wantLong) {
		t.Skip("filesystem has no distinct DOS 8.3 alias")
	}
	if got := NormalizeSubjectProgram(short); !strings.EqualFold(got, wantLong) || !SameSubjectProgram(short, wantLong) || !SameSubjectProgram(strings.ToUpper(wantLong), short) {
		t.Fatalf("short alias %q normalized to %q instead of %q", short, got, wantLong)
	}
	other := filepath.Join(t.TempDir(), "subject.exe")
	if err := os.WriteFile(other, []byte("other"), 0o600); err != nil {
		t.Fatal(err)
	}
	if SameSubjectProgram(short, other) {
		t.Fatal("different file matched the subject alias")
	}
}

// The test's own TEMP path may contain an 8.3 parent, as on hosted Windows.
// Build one explicitly so the expected value must expand the parent too.
func TestSubjectProgramComparisonExpandsShortParent(t *testing.T) {
	parent := filepath.Join(t.TempDir(), "parent directory with spaces")
	if err := os.Mkdir(parent, 0o755); err != nil {
		t.Fatal(err)
	}
	shortParent := windowsTestPathName(t, parent, true)
	if strings.EqualFold(shortParent, windowsTestPathName(t, parent, false)) {
		t.Skip("filesystem has no distinct DOS 8.3 parent alias")
	}
	dir := filepath.Join(shortParent, "program with spaces")
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	raw := filepath.Join(dir, "subject.exe")
	if err := os.WriteFile(raw, []byte("subject"), 0o600); err != nil {
		t.Fatal(err)
	}
	wantLong := windowsTestPathName(t, raw, false)
	if strings.EqualFold(raw, wantLong) {
		t.Fatal("fixture did not retain a short parent")
	}
	if got := NormalizeSubjectProgram(raw); !strings.EqualFold(got, wantLong) || !SameSubjectProgram(raw, wantLong) {
		t.Fatalf("short-parent path %q normalized to %q instead of %q", raw, got, wantLong)
	}
}

// Query Win32 directly for the test oracle. The expected full path does not
// call the subject normalizer under test.
func windowsTestPathName(t *testing.T, path string, short bool) string {
	t.Helper()
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		t.Fatal(err)
	}
	buf := make([]uint16, windows.MAX_LONG_PATH)
	query := windows.GetLongPathName
	if short {
		query = windows.GetShortPathName
	}
	n, err := query(p, &buf[0], uint32(len(buf)))
	if err != nil || n == 0 || n >= uint32(len(buf)) {
		t.Fatalf("path query for %q: n=%d err=%v", path, n, err)
	}
	return windows.UTF16ToString(buf[:n])
}

// An installed package's folder is found by its full name. Set
// OA_PACKAGED_FULL_NAME to an installed package's full name, for example
// Claude_2.110.1.0_x64__pzs8sxrjxfjjc from Get-AppxPackage.
func TestPackagePathOfAnInstalledPackage(t *testing.T) {
	full := os.Getenv("OA_PACKAGED_FULL_NAME")
	if full == "" {
		t.Skip("set OA_PACKAGED_FULL_NAME to an installed package's full name")
	}
	root, err := packagePathByFullName(full)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.EqualFold(filepath.Base(root), full) {
		t.Fatalf("package folder %s does not end in %s", root, full)
	}
	if info, err := os.Stat(root); err != nil || !info.IsDir() {
		t.Fatalf("package folder %s: %v", root, err)
	}
	t.Logf("package folder %s", root)
	if _, err := packagePathByFullName("NotInstalled_1.0.0.0_x64__aaaaaaaaaaaaa"); err == nil {
		t.Fatal("a package that is not installed has a folder")
	}
}
