package privatedir

import (
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/windows"
)

// ID-D1, ID-D3, storage STO-L9, ST-1 review round 3: Tighten writes the
// folder's own descriptor and nothing below it. A data root made by the
// 0.4.0 runtime carries this account, SYSTEM and Administrators, inherited
// by everything it holds; tightening it leaves a child that inherits those
// entries, and a model file whose second name lies in the job store
// (JOB-A17), with the descriptor each had. SetNamedSecurityInfo re-propagates
// inheritance through every name below the folder and rewrote both. A
// junction is refused on its handle, and the folder it names keeps its
// descriptor.
func TestTightenWritesOnlyTheFolder(t *testing.T) {
	base := pidDir(t)
	d := filepath.Join(base, "D")
	if err := os.Mkdir(d, 0o700); err != nil {
		t.Fatal(err)
	}
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	me := user.User.Sid.String()
	// The 0.4.0 data root's descriptor, set while the folder is empty.
	old, err := windows.SecurityDescriptorFromString("D:PAI(A;OICI;FA;;;" + me + ")(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)")
	if err != nil {
		t.Fatal(err)
	}
	dacl, _, err := old.DACL()
	if err != nil {
		t.Fatal(err)
	}
	if err := windows.SetNamedSecurityInfo(d, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, dacl, nil); err != nil {
		t.Fatal(err)
	}

	child := filepath.Join(d, "inherits")
	childFile := filepath.Join(child, "record.json")
	models := filepath.Join(d, "models")
	jobs := filepath.Join(d, "jobs")
	for _, dir := range []string{child, models, jobs} {
		if err := os.Mkdir(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(childFile, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	set := filepath.Join(models, "set")
	if err := os.Mkdir(set, 0o700); err != nil {
		t.Fatal(err)
	}
	result := filepath.Join(jobs, "result.webm")
	if err := os.WriteFile(result, []byte("video"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(result, filepath.Join(set, "result.webm")); err != nil {
		t.Fatal(err)
	}
	if err := ProtectModelFolder(set, []string{models, jobs}); err != nil {
		t.Fatal(err)
	}

	kept := []string{child, childFile, set, result}
	before := map[string]string{}
	for _, p := range kept {
		before[p] = descriptor(t, p)
	}
	if err := CheckDir(d); err == nil {
		t.Fatal("the 0.4.0 descriptor passed CheckDir before Tighten")
	}
	if err := Tighten(d); err != nil {
		t.Fatalf("Tighten: %v", err)
	}
	if err := CheckDir(d); err != nil {
		t.Fatalf("a tightened folder: %v", err)
	}
	for _, p := range kept {
		if got := descriptor(t, p); got != before[p] {
			t.Errorf("Tighten changed %s below the folder:\n before %s\n after  %s", p, before[p], got)
		}
	}
	if err := CheckModelFolder(set); err != nil {
		t.Fatalf("the model folder after Tighten: %v", err)
	}

	target := filepath.Join(base, "target")
	if err := os.Mkdir(target, 0o700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(base, "link")
	junction(t, link, target)
	was := descriptor(t, target)
	if err := Tighten(link); err == nil {
		t.Fatal("Tighten followed a junction")
	}
	if descriptor(t, target) != was {
		t.Fatal("the folder a junction names was changed")
	}
	file := filepath.Join(base, "file")
	if err := os.WriteFile(file, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := Tighten(file); err == nil {
		t.Fatal("Tighten accepted a file")
	}
}
