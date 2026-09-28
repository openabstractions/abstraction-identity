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
	p, err := windows.UTF16PtrFromString(long)
	if err != nil {
		t.Fatal(err)
	}
	buf := make([]uint16, windows.MAX_LONG_PATH)
	n, err := windows.GetShortPathName(p, &buf[0], uint32(len(buf)))
	if err != nil || n == 0 || n >= uint32(len(buf)) {
		t.Fatalf("short path n=%d err=%v", n, err)
	}
	short := windows.UTF16ToString(buf[:n])
	if strings.EqualFold(short, long) {
		t.Skip("filesystem has no distinct DOS 8.3 alias")
	}
	if got := NormalizeSubjectProgram(short); !strings.EqualFold(got, long) || !SameSubjectProgram(short, long) || !SameSubjectProgram(strings.ToUpper(long), short) {
		t.Fatalf("short alias %q normalized to %q instead of %q", short, got, long)
	}
	other := filepath.Join(t.TempDir(), "subject.exe")
	if err := os.WriteFile(other, []byte("other"), 0o600); err != nil {
		t.Fatal(err)
	}
	if SameSubjectProgram(short, other) {
		t.Fatal("different file matched the subject alias")
	}
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
