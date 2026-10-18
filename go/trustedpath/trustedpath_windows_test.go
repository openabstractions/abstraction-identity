//go:build windows

package trustedpath

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/windows"
)

// ID-D2 on descriptors: a test cannot give a file another owner without
// privilege. The ASUS files and folders on the owner's machine carry the
// first file and first folder descriptors (icacls, 2026-10-01).
func TestTheRuleOnDescriptors(t *testing.T) {
	trusted, err := MachineOwners().sids()
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		name, sddl string
		folder, ok bool
	}{
		{"ASUS model file", "O:BAD:(A;ID;FA;;;SY)(A;ID;FA;;;BA)(A;ID;0x1200a9;;;BU)", false, true},
		{"SYSTEM owner", "O:SYD:P(A;;FA;;;SY)(A;;FR;;;WD)", false, true},
		{"TrustedInstaller owner", "O:" + trustedInstaller + "D:P(A;;FA;;;" + trustedInstaller + ")(A;;0x1200a9;;;BU)", false, true},
		{"an inherit-only grant passes to children only", "O:BAD:(A;;FA;;;BA)(A;OICIIO;FA;;;BU)", false, true},
		{"a deny entry narrows", "O:BAD:(A;;FA;;;BA)(D;;FA;;;BU)", false, true},
		{"owned by Users", "O:BUD:(A;;FA;;;SY)", false, false},
		{"owned by an account", "O:S-1-5-21-1-2-3-1001D:(A;;FA;;;SY)", false, false},
		{"Users may write", "O:BAD:(A;;FA;;;BA)(A;;0x120116;;;BU)", false, false},
		{"Users may delete", "O:BAD:(A;;FA;;;BA)(A;;SD;;;BU)", false, false},
		{"Users may change the times", "O:BAD:(A;;FA;;;BA)(A;;0x100;;;BU)", false, false},
		{"Everyone has full control", "O:SYD:(A;;GA;;;WD)", false, false},
		{"no DACL", "O:SYD:NO_ACCESS_CONTROL", false, false},
		{"ASUS model folder", "O:BAD:(A;OICIID;FA;;;SY)(A;OICIID;FA;;;BA)(A;OICIIOID;GA;;;CO)(A;OICIID;0x1200a9;;;BU)(A;CIID;0x116;;;BU)", true, true},
		{"volume root", "O:" + trustedInstaller + "D:(A;OICI;FA;;;BA)(A;OICI;FA;;;SY)(A;OICI;0x1200a9;;;BU)(A;OICIIO;SDGRGWGX;;;AU)(A;;0x4;;;AU)", true, true},
		{"Users may delete children", "O:BAD:(A;;FA;;;BA)(A;;0x40;;;BU)", true, false},
		{"Users may rename the folder", "O:BAD:(A;;FA;;;BA)(A;;SD;;;BU)", true, false},
		{"Users may rewrite the folder's DACL", "O:BAD:(A;;FA;;;BA)(A;;WD;;;BU)", true, false},
		{"a folder owned by an account", "O:S-1-5-21-1-2-3-1001D:(A;;FA;;;SY)", true, false},
	} {
		sd, err := windows.SecurityDescriptorFromString(c.sddl)
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		mask := windows.ACCESS_MASK(fileChange)
		if c.folder {
			mask = folderChange
		}
		if err := checkDescriptor(sd, mask, trusted); (err == nil) != c.ok {
			t.Fatalf("%s: %v, want ok %v", c.name, err, c.ok)
		}
	}
}

// ID-D2's executable folder on descriptors: the folder an elevated program
// runs from also refuses another principal's right to add a file or a
// subfolder, which CheckFile's folders allow (the ASUS model folder lets
// Users add files).
func TestTheExecutableFolderRule(t *testing.T) {
	trusted, err := MachineOwners().sids()
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		name, sddl       string
		folder, runnable bool
	}{
		{"Program Files tools folder", "O:" + trustedInstaller + "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1200a9;;;BU)", true, true},
		{"ASUS model folder (Users add files)", "O:BAD:(A;OICIID;FA;;;SY)(A;OICIID;FA;;;BA)(A;OICIIOID;GA;;;CO)(A;OICIID;0x1200a9;;;BU)(A;CIID;0x116;;;BU)", true, false},
		{"Users may add a file", "O:BAD:(A;;FA;;;BA)(A;;0x2;;;BU)", true, false},
		{"Users may add a subfolder", "O:BAD:(A;;FA;;;BA)(A;;0x4;;;AU)", true, false},
		{"Users hold generic write", "O:BAD:(A;;FA;;;BA)(A;;GW;;;BU)", true, false},
		{"an inherit-only add right passes to children only", "O:BAD:(A;;FA;;;BA)(A;OICIIO;0x2;;;BU)", true, true},
	} {
		sd, err := windows.SecurityDescriptorFromString(c.sddl)
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		if err := checkDescriptor(sd, executableFolderChange, trusted); (err == nil) != c.runnable {
			t.Fatalf("%s: %v, want runnable %v", c.name, err, c.runnable)
		}
		if c.name == "ASUS model folder (Users add files)" {
			if err := checkDescriptor(sd, folderChange, trusted); err != nil {
				t.Fatalf("CheckFile's folder rule changed: %v", err)
			}
		}
	}
	dir := t.TempDir()
	file := filepath.Join(dir, "openabstractions-system.exe")
	if err := os.WriteFile(file, []byte("MZ"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := CheckExecutable(file, MachineOwners()); !errors.Is(err, ErrUntrusted) {
		t.Fatalf("a program in this account's temporary folder: %v", err)
	}
	if err := CheckExecutable("openabstractions-system.exe", MachineOwners()); !errors.Is(err, ErrUntrusted) {
		t.Fatalf("a relative path: %v", err)
	}
	system, err := windows.GetSystemDirectory()
	if err != nil {
		t.Fatal(err)
	}
	if err := CheckExecutable(filepath.Join(system, "wevtutil.exe"), MachineOwners()); err != nil {
		t.Logf("wevtutil.exe in the system directory: %v (its folders decide)", err)
	}
}

// ID-D2 on real paths: a file of this account is refused under MachineOwnersOwners and
// judged by its folders when the account is trusted; a junction on the
// path, a relative path and a UNC path are refused.
func TestRealPaths(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "weights.safetensors")
	if err := os.WriteFile(file, []byte("w"), 0o600); err != nil {
		t.Fatal(err)
	}
	elevated := windows.GetCurrentProcessToken().IsElevated()
	if err := CheckFile(file, MachineOwners()); !elevated && (!errors.Is(err, ErrUntrusted) || !strings.Contains(err.Error(), "owned by")) {
		t.Fatalf("this account's file under MachineOwnersOwners: %v", err)
	}
	mine := MachineOwners()
	mine.Account = true
	if err := CheckFile(file, mine); err != nil {
		t.Logf("this account's temporary file with the account trusted: %v (its folders decide)", err)
	}

	target := filepath.Join(dir, "target")
	if err := os.Mkdir(target, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(target, "w.gguf"), []byte("w"), 0o600); err != nil {
		t.Fatal(err)
	}
	junction := filepath.Join(dir, "junction")
	if out, err := exec.Command("cmd", "/c", "mklink", "/J", junction, target).CombinedOutput(); err != nil {
		t.Skipf("mklink /J: %v %s", err, out)
	}
	if err := CheckFile(filepath.Join(junction, "w.gguf"), mine); !errors.Is(err, ErrUntrusted) || !strings.Contains(err.Error(), "reparse point") {
		t.Fatalf("a junction on the path: %v", err)
	}
	for _, p := range []string{"weights.safetensors", `\\server\share\w.gguf`} {
		if err := CheckFile(p, mine); !errors.Is(err, ErrUntrusted) {
			t.Fatalf("%q: %v", p, err)
		}
	}
	if _, err := (Owners{SIDs: []string{"not a SID"}}).sids(); err == nil {
		t.Fatal("a malformed SID was accepted")
	}
}

// The ASUS files this rule was written for pass it where they exist.
func TestASUSModelFilesPass(t *testing.T) {
	for _, p := range []string{
		`C:\ProgramData\ASUS\AICreator\hummingbird\HM_2.2_5B\transformer_20251218\diffusion_pytorch_model_i2v.safetensors`,
		`C:\ProgramData\ASUS\WhisperRecorder\models\ggml-medium.bin`,
	} {
		if _, err := os.Lstat(p); err != nil {
			t.Skipf("%s: %v", p, err)
		}
		if err := CheckFile(p, MachineOwners()); err != nil {
			t.Fatalf("%s: %v", p, err)
		}
	}
}
