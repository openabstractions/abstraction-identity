package identity

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

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
