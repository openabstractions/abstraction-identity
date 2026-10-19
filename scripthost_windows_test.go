//go:build windows

package identity

import (
	"os"
	"path/filepath"
	"testing"
)

// The inbox shared interpreters on this machine verify trusted, and the
// OriginalFilename read from each is on the reviewed list, so the list's
// spellings are the signed ones. A host this Windows does not ship is skipped.
func TestSharedInterpretersMatchTheirSignedNames(t *testing.T) {
	root := os.Getenv("SystemRoot")
	for _, path := range []string{
		filepath.Join(root, `System32\WindowsPowerShell\v1.0\powershell.exe`),
		filepath.Join(root, `System32\cmd.exe`),
		filepath.Join(root, `System32\wscript.exe`),
		filepath.Join(root, `System32\cscript.exe`),
		filepath.Join(root, `System32\mshta.exe`),
		filepath.Join(root, `System32\rundll32.exe`),
		filepath.Join(root, `System32\regsvr32.exe`),
		filepath.Join(root, `System32\wsl.exe`),
		filepath.Join(root, `System32\bash.exe`),
		filepath.Join(root, `Microsoft.NET\Framework64\v4.0.30319\MSBuild.exe`),
		filepath.Join(root, `Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe`),
		filepath.Join(root, `Microsoft.NET\Framework64\v4.0.30319\RegAsm.exe`),
		filepath.Join(root, `Microsoft.NET\Framework64\v4.0.30319\csc.exe`),
	} {
		if _, err := os.Stat(path); err != nil {
			t.Logf("skipped %s: %v", path, err)
			continue
		}
		code, _, err := VerifyFile(path, nil)
		if err != nil || !code.Trusted || !SharedInterpreterName(code.OriginalName) {
			t.Errorf("%s: trusted %t, OriginalFilename %q, %v", path, code.Trusted, code.OriginalName, err)
		}
	}
}
