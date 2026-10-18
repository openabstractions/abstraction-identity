//go:build windows

package identity

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"
)

// TestVerifyFileOpensOnlyLocalDrivePaths asserts ID-W4's path rule: a UNC,
// device, relative or unclean path is refused before any open.
func TestVerifyFileOpensOnlyLocalDrivePaths(t *testing.T) {
	for path, want := range map[string]bool{
		`C:\apps\opencode.exe`:         true,
		`d:\tools\bun.exe`:             true,
		`\\server\share\app.exe`:       false,
		`\\?\C:\apps\opencode.exe`:     false,
		`\\.\pipe\openabstractions`:    false,
		`C:\apps\..\apps\opencode.exe`: false,
		`C:apps\opencode.exe`:          false,
		`opencode.exe`:                 false,
		`1:\apps\opencode.exe`:         false,
		`C:/apps/opencode.exe`:         false,
		`UNC\server\share\app.exe`:     false,
		"":                             false,
	} {
		if got := localDrivePath(path); got != want {
			t.Errorf("localDrivePath(%q) = %v, want %v", path, got, want)
		}
	}
	if _, proof, err := VerifyFile(`\\127.0.0.1\c$\Windows\explorer.exe`, nil); !errors.Is(err, ErrNotLocalFile) || proof != ProofNone {
		t.Fatalf("a UNC path must be refused unopened: %v %v", proof, err)
	}
}

// TestVerifyFileRefusesRemoteDrives asserts ID-W4's drive rule on the
// decision function: a mapped network drive, an absent drive and an unknown
// drive type are refused; fixed, removable and optical drives are local.
func TestVerifyFileRefusesRemoteDrives(t *testing.T) {
	for kind, want := range map[uint32]bool{
		windows.DRIVE_FIXED:       true,
		windows.DRIVE_REMOVABLE:   true,
		windows.DRIVE_CDROM:       true,
		windows.DRIVE_RAMDISK:     true,
		windows.DRIVE_REMOTE:      false,
		windows.DRIVE_NO_ROOT_DIR: false,
		windows.DRIVE_UNKNOWN:     false,
	} {
		var asked string
		got := localDrive(`Z:\apps\app.exe`, func(root string) uint32 { asked = root; return kind })
		if got != want || asked != `Z:\` {
			t.Errorf("drive type %d: local=%v root=%q, want %v", kind, got, asked, want)
		}
	}
	if system := os.Getenv("SystemRoot"); system != "" && !localDrive(system, driveType) {
		t.Fatalf("the system drive of %q must read local", system)
	}
}

// TestStillSameFileFollowsTheHandle asserts the same-file check VerifyFile
// runs after its path-based signer read: the handle's final path must still
// be the verified path, and a rename away is refused.
func TestStillSameFileFollowsTheHandle(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "program.exe")
	if err := os.WriteFile(path, []byte("MZ"), 0o600); err != nil {
		t.Fatal(err)
	}
	long, err := longImagePath(path)
	if err != nil {
		t.Fatal(err)
	}
	pathW, _ := windows.UTF16PtrFromString(long)
	file, err := windows.CreateFile(pathW, windows.GENERIC_READ,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil, windows.OPEN_EXISTING, windows.FILE_ATTRIBUTE_NORMAL, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer windows.CloseHandle(file)
	if err := stillSameFile(file, strings.ToUpper(long)); err != nil {
		t.Fatalf("the same file in another case must match: %v", err)
	}
	if err := os.Rename(path, filepath.Join(dir, "moved.exe")); err != nil {
		t.Fatal(err)
	}
	if err := stillSameFile(file, long); err == nil {
		t.Fatal("a file renamed away from the verified path must be refused")
	}
	if err := sameFinalPath(`C:\a\b.exe`, `C:\a\c.exe`); err == nil {
		t.Fatal("different final paths must be refused")
	}
}

func signedGit(t *testing.T) string {
	t.Helper()
	git := filepath.Join(os.Getenv("ProgramFiles"), "Git", "cmd", "git.exe")
	if _, err := os.Stat(git); err != nil {
		t.Skip("Git for Windows is not installed")
	}
	return git
}

// TestVerifyFileNamesEmbeddedSigner reads Git for Windows' embedded
// Authenticode signer; it runs nothing.
func TestVerifyFileNamesEmbeddedSigner(t *testing.T) {
	git := signedGit(t)
	code, proof, err := VerifyFile(git, nil)
	if err != nil || proof != ProofBound || !code.Trusted || code.Catalog || code.Subject == "" || code.Issuer == "" {
		t.Fatalf("VerifyFile(%q) = %+v %v %v", git, code, proof, err)
	}
	t.Logf("signer %q issued by %q", code.Subject, code.Issuer)
}

// systemPowerShell is Windows PowerShell, signed through a system catalog with
// no signature embedded in the file.
const systemPowerShell = `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`

// TestVerifyFileNamesCatalogSigner: inbox files bind trusted with their signer
// named, the name Get-AuthenticodeSignature reports as the signer
// certificate's CN (CN=Microsoft Windows for both). powershell.exe carries no
// embedded signature, so its signer is the catalog's; kernel32.dll embeds one
// on Windows 11 and is catalog-signed only on older builds.
func TestVerifyFileNamesCatalogSigner(t *testing.T) {
	for _, path := range []string{systemPowerShell, `C:\Windows\System32\kernel32.dll`} {
		pathW, err := windows.UTF16PtrFromString(path)
		if err != nil {
			t.Fatal(err)
		}
		_, _, embedErr := signerName(pathW, windows.CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED)
		if path == systemPowerShell && embedErr == nil {
			t.Fatalf("%s carries an embedded signature; this test needs a catalog-only file", path)
		}
		code, proof, err := VerifyFile(path, nil)
		if err != nil || proof != ProofBound || !code.Trusted || code.Catalog != (embedErr != nil) ||
			code.Subject != "Microsoft Windows" || code.Issuer == "" {
			t.Fatalf("VerifyFile(%q) = %+v %v %v (catalog %v)", path, code, proof, err, code.Catalog)
		}
		t.Logf("%s: signer %q issued by %q (%s)", path, code.Subject, code.Issuer, code.Status)
	}
}

// trustCall is one verification winTrustCall received: for WTD_CHOICE_FILE
// the handle it was given, for WTD_CHOICE_CATALOG the member it was given.
type trustCall struct {
	choice uint32
	file   windows.Handle
	member wintrustCatalogInfo
}

// recordTrust records every verification until the test ends. A non-nil
// catalogAnswer is returned for every catalog verification in place of
// Windows' verdict; file verifications always reach Windows.
func recordTrust(t *testing.T, catalogAnswer error) *[]trustCall {
	t.Helper()
	calls := &[]trustCall{}
	previous := winTrustCall
	winTrustCall = func(choice uint32, subject unsafe.Pointer, revocation bool) error {
		c := trustCall{choice: choice}
		switch choice {
		case windows.WTD_CHOICE_FILE:
			c.file = (*windows.WinTrustFileInfo)(subject).File
		case windows.WTD_CHOICE_CATALOG:
			c.member = *(*wintrustCatalogInfo)(subject)
		}
		*calls = append(*calls, c)
		if choice == windows.WTD_CHOICE_CATALOG && catalogAnswer != nil {
			return catalogAnswer
		}
		return previous(choice, subject, revocation)
	}
	t.Cleanup(func() { winTrustCall = previous })
	return calls
}

// TestVerifyFileCatalogRefusal: a catalog listing powershell.exe that refuses
// it with a bad digest makes the file invalid with no signer named, and the
// catalog verification is of the held file by its SHA-256 member hash. A
// refusal on the unsigned rung is a catalog that does not list the file, and
// with no other catalog the file is unsigned (ID-W4).
func TestVerifyFileCatalogRefusal(t *testing.T) {
	for _, tc := range []struct {
		name    string
		answer  syscall.Errno
		proof   Proof
		catalog bool
		status  string
	}{
		{"bad digest", trustEBadDigest, ProofInvalid, true,
			"listed by a system catalog Windows refused: signed, but the file has been modified since it was signed"},
		{"no signature", trustENoSignature, ProofUnsigned, false, "no signature"},
		{"not found", cryptENotFound, ProofUnsigned, false, "no signature"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			calls := recordTrust(t, tc.answer)
			code, proof, err := VerifyFile(systemPowerShell, nil)
			if err != nil || proof != tc.proof || code.Trusted || code.Catalog != tc.catalog || code.Subject != "" ||
				code.Issuer != "" || code.Status != tc.status {
				t.Fatalf("VerifyFile(%q) with catalogs answering %v = %+v %v %v (catalog %v)", systemPowerShell, tc.answer, code, proof, err, code.Catalog)
			}
			var held windows.Handle
			catalogs := 0
			for _, c := range *calls {
				switch c.choice {
				case windows.WTD_CHOICE_FILE:
					held = c.file
				case windows.WTD_CHOICE_CATALOG:
					catalogs++
					if held == 0 || c.member.MemberFile != held || c.member.CalculatedHashSize != 32 ||
						c.member.CatAdmin == 0 || c.member.MemberTag == nil || c.member.CatalogFilePath == nil {
						t.Fatalf("catalog verification of %+v, held file %v", c.member, held)
					}
				}
			}
			if catalogs == 0 {
				t.Fatal("no catalog verification was made")
			}
		})
	}
}

// TestVerifyFileLooksUpCatalogsOnlyUnderTheWindowsDirectory: a file with no
// embedded signature outside the Windows directory is unsigned with no catalog
// verification, even an unmodified copy of powershell.exe a catalog lists;
// powershell.exe in place is still named through its catalog (ID-W2).
func TestVerifyFileLooksUpCatalogsOnlyUnderTheWindowsDirectory(t *testing.T) {
	data, err := os.ReadFile(systemPowerShell)
	if err != nil {
		t.Skipf("cannot read %s: %v", systemPowerShell, err)
	}
	copied := filepath.Join(t.TempDir(), "renamed.exe")
	if err := os.WriteFile(copied, data, 0o600); err != nil {
		t.Fatal(err)
	}
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	calls := recordTrust(t, nil)
	for _, path := range []string{copied, exe} {
		code, proof, err := VerifyFile(path, nil)
		if err != nil || proof != ProofUnsigned || code.Trusted || code.Catalog || code.Subject != "" || code.Status != "no signature" {
			t.Fatalf("VerifyFile(%q) = %+v %v %v", path, code, proof, err)
		}
	}
	for _, c := range *calls {
		if c.choice == windows.WTD_CHOICE_CATALOG {
			t.Fatalf("a file outside the Windows directory was verified against a catalog: %+v", c.member)
		}
	}
	code, proof, err := VerifyFile(systemPowerShell, nil)
	if err != nil || proof != ProofBound || !code.Catalog || code.Subject != "Microsoft Windows" {
		t.Fatalf("VerifyFile(%q) = %+v %v %v", systemPowerShell, code, proof, err)
	}
}

func TestUnderDirectoryNeedsASeparator(t *testing.T) {
	for path, want := range map[string]bool{
		`C:\Windows\System32\cmd.exe`: true,
		`c:\windows\notepad.exe`:      true,
		`C:\WindowsApps\app.exe`:      false,
		`C:\Windows`:                  false,
		`C:\Windows\`:                 false,
		`D:\Windows\x.exe`:            false,
	} {
		if got := underDirectory(path, `C:\Windows`); got != want {
			t.Errorf("underDirectory(%q) = %v, want %v", path, got, want)
		}
	}
}

// TestVerifyFileReportsAModifiedSignedFileInvalid copies git.exe, changes
// one byte past the PE headers and expects the invalid rung (ID-P9).
func TestVerifyFileReportsAModifiedSignedFileInvalid(t *testing.T) {
	data, err := os.ReadFile(signedGit(t))
	if err != nil {
		t.Fatal(err)
	}
	const offset = 0x800 // inside the first section, before the certificate table
	if len(data) < 4*offset {
		t.Skipf("git.exe is only %d bytes", len(data))
	}
	data[offset] ^= 0xff
	copied := filepath.Join(t.TempDir(), "git.exe")
	if err := os.WriteFile(copied, data, 0o600); err != nil {
		t.Fatal(err)
	}
	code, proof, err := VerifyFile(copied, nil)
	if err != nil || proof != ProofInvalid || code.Trusted || code.Status != "signed, but the file has been modified since it was signed" {
		t.Fatalf("modified signed file: %+v %v %v", code, proof, err)
	}
}

func TestVerifyFileUnsignedAndMissing(t *testing.T) {
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	code, proof, err := VerifyFile(exe, nil)
	if err != nil || proof != ProofUnsigned || code.Trusted || code.Catalog || code.Subject != "" || code.Status != "no signature" {
		t.Fatalf("an unsigned go test binary: %+v %v %v", code, proof, err)
	}
	if _, proof, err := VerifyFile(exe+".missing", nil); err == nil || proof != ProofNone {
		t.Fatalf("a missing file must be an error: %v %v", proof, err)
	}
}
