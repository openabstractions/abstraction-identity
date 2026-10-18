package privatedir

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"
)

// allowsOnly reports the first allow entry of p's DACL for a principal other
// than this account, SYSTEM and Administrators, or an owner other than this
// account.
func allowsOnly(t *testing.T, p string) error {
	t.Helper()
	sd, err := windows.GetNamedSecurityInfo(p, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatal(err)
	}
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	if owner, _, err := sd.Owner(); err != nil || !owner.Equals(user.User.Sid) {
		return errors.New("not owned by this account")
	}
	dacl, _, err := sd.DACL()
	if err != nil || dacl == nil {
		t.Fatalf("%s: DACL %v", p, err)
	}
	system, _ := windows.CreateWellKnownSid(windows.WinLocalSystemSid)
	admins, _ := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	for i := uint32(0); i < uint32(dacl.AceCount); i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, i, &ace); err != nil {
			t.Fatal(err)
		}
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		if ace.Header.AceType == windows.ACCESS_ALLOWED_ACE_TYPE && !sid.Equals(user.User.Sid) && !sid.Equals(system) && !sid.Equals(admins) {
			return errors.New("allows " + sid.String())
		}
	}
	return nil
}

// everyone gives p an explicit entry letting Everyone modify it.
func everyone(t *testing.T, p string) {
	t.Helper()
	sd, err := windows.SecurityDescriptorFromString("D:(A;;0x1301bf;;;WD)")
	if err != nil {
		t.Fatal(err)
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		t.Fatal(err)
	}
	if err := windows.SetNamedSecurityInfo(p, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION, nil, nil, dacl, nil); err != nil {
		t.Fatal(err)
	}
}

// descriptor is p's owner and DACL as SDDL.
func descriptor(t *testing.T, p string) string {
	t.Helper()
	sd, err := windows.GetNamedSecurityInfo(p, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatal(err)
	}
	return sd.String()
}

func junction(t *testing.T, link, target string) {
	t.Helper()
	if out, err := exec.Command("cmd", "/c", "mklink", "/J", link, target).CombinedOutput(); err != nil {
		t.Fatalf("mklink /J: %v %s", err, out)
	}
	t.Cleanup(func() {
		//unchecked: test cleanup; the temporary folder's removal takes what is left
		os.Remove(link)
	})
}

// modelSet makes root\video with a file, a nested folder and a file in it,
// and gives the first file an entry a move left on it.
func modelSet(t *testing.T, root string) (dir, moved string) {
	t.Helper()
	dir = filepath.Join(root, "video")
	if err := os.MkdirAll(filepath.Join(dir, "nested"), 0o700); err != nil {
		t.Fatal(err)
	}
	moved = filepath.Join(dir, "weights.gguf")
	for _, p := range []string{moved, filepath.Join(dir, "nested", "encoder.gguf")} {
		if err := os.WriteFile(p, []byte("weights"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	everyone(t, moved)
	return dir, moved
}

// ID-D3: a model folder whose files carry entries a move left on them (here
// Everyone with modify on one file, and the temporary folder's inherited
// entries on all) is given the model descriptor; every file and folder
// below it then allows only this account, SYSTEM and Administrators, as
// entries inherited from it. A junction below it refuses the folder before
// anything changes, and a relative path, a file and a folder outside every
// root are refused.
func TestProtectModelFolder(t *testing.T) {
	root := t.TempDir()
	dir, moved := modelSet(t, root)
	roots := []string{root}
	if allowsOnly(t, moved) == nil {
		t.Fatal("the stand-in for a moved file carries no foreign entry")
	}
	if err := CheckModelFolder(dir); !errors.Is(err, ErrNotModelFolder) {
		t.Fatalf("an unprotected folder passed: %v", err)
	}

	link := filepath.Join(dir, "linked")
	junction(t, link, t.TempDir())
	before := descriptor(t, moved)
	if err := ProtectModelFolder(dir, roots); !errors.Is(err, ErrNotModelFolder) {
		t.Fatalf("a folder holding a junction: %v", err)
	}
	if descriptor(t, moved) != before || CheckModelFolder(dir) == nil {
		t.Fatal("a refused folder was changed")
	}
	if err := os.Remove(link); err != nil {
		t.Fatal(err)
	}

	if err := ProtectModelFolder(dir, roots); err != nil {
		t.Fatal(err)
	}
	if err := CheckModelFolder(dir); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{dir, moved, filepath.Join(dir, "nested"), filepath.Join(dir, "nested", "encoder.gguf")} {
		if err := allowsOnly(t, p); err != nil {
			t.Fatalf("%s: %v", p, err)
		}
	}
	if d := descriptor(t, moved); !strings.Contains(d, ";ID;") || strings.Contains(d, "D:P") {
		t.Fatalf("a file below does not inherit from the folder alone: %s", d)
	}
	if data, err := os.ReadFile(moved); err != nil || string(data) != "weights" {
		t.Fatalf("the file's content: %q %v", data, err)
	}
	for _, bad := range []string{"video", moved} {
		if err := ProtectModelFolder(bad, roots); !errors.Is(err, ErrNotModelFolder) {
			t.Fatalf("%s: %v", bad, err)
		}
	}
	if err := ProtectModelFolder(dir, []string{t.TempDir()}); !errors.Is(err, ErrNotModelFolder) {
		t.Fatalf("a folder outside every root: %v", err)
	}
}

// Review of 6607b567d, hard links: a file outside OA's folders hard-linked
// into a set folder refuses the folder, and that file's access is unchanged;
// a second name inside OA's own folders (a job result LinkResult made, JOB-A17)
// is accepted.
func TestProtectModelFolderHardLinks(t *testing.T) {
	base := t.TempDir()
	models := filepath.Join(base, "OA-models")
	jobs := filepath.Join(base, "jobs")
	outside := filepath.Join(base, "elsewhere")
	for _, d := range []string{jobs, outside} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	dir, _ := modelSet(t, models)
	foreign := filepath.Join(outside, "theirs.bin")
	if err := os.WriteFile(foreign, []byte("theirs"), 0o600); err != nil {
		t.Fatal(err)
	}
	everyone(t, foreign)
	if err := os.Link(foreign, filepath.Join(dir, "theirs.bin")); err != nil {
		t.Fatal(err)
	}
	before := descriptor(t, foreign)
	err := ProtectModelFolder(dir, []string{models, jobs})
	if !errors.Is(err, ErrNotModelFolder) || !strings.Contains(err.Error(), "outside OA's own folders") {
		t.Fatalf("an outside file linked in: %v", err)
	}
	if descriptor(t, foreign) != before {
		t.Fatal("the outside file's access was changed")
	}
	if err := os.Remove(filepath.Join(dir, "theirs.bin")); err != nil {
		t.Fatal(err)
	}

	result := filepath.Join(jobs, "result.webm")
	if err := os.WriteFile(result, []byte("video"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(result, filepath.Join(dir, "result.webm")); err != nil {
		t.Fatal(err)
	}
	if err := ProtectModelFolder(dir, []string{models, jobs}); err != nil {
		t.Fatalf("a second name in OA's job store: %v", err)
	}

	// Second review of 6958c169b: a broad job store cannot widen OA's own
	// folders. A drive root, the home and a junctioned folder are refused
	// as roots before anything is read; a store that does not exist yet is
	// left out.
	home, err := windows.KnownFolderPath(windows.FOLDERID_Profile, 0)
	if err != nil {
		t.Fatal(err)
	}
	linked := filepath.Join(base, "linked-jobs")
	junction(t, linked, jobs)
	for _, broad := range []string{`C:\`, home, linked} {
		if err := ProtectModelFolder(dir, []string{models, broad}); !errors.Is(err, ErrNotModelFolder) {
			t.Fatalf("job store %s: %v", broad, err)
		}
	}
	if err := ProtectModelFolder(dir, []string{models, jobs, filepath.Join(base, "absent")}); err != nil {
		t.Fatalf("an absent job store: %v", err)
	}
}

// Review of 6607b567d, the swap: between the scan and the first write, a
// subfolder already held cannot be renamed away for a junction, and the
// folder the junction would name keeps its access.
func TestProtectModelFolderSwapAfterScan(t *testing.T) {
	base := t.TempDir()
	dir, _ := modelSet(t, filepath.Join(base, "OA-models"))
	target := filepath.Join(base, "target")
	if err := os.MkdirAll(target, 0o700); err != nil {
		t.Fatal(err)
	}
	everyone(t, target)
	before := descriptor(t, target)
	// An empty folder: no open file below it blocks its rename, so only its
	// own hold does.
	nested := filepath.Join(dir, "empty")
	if err := os.Mkdir(nested, 0o700); err != nil {
		t.Fatal(err)
	}
	var renamed error = errors.New("the hook did not run")
	afterScan = func() {
		renamed = os.Rename(nested, nested+".moved")
		if renamed == nil {
			junction(t, nested, target)
		}
	}
	t.Cleanup(func() { afterScan = nil })
	if err := ProtectModelFolder(dir, []string{base}); err != nil {
		t.Fatal(err)
	}
	if renamed == nil {
		t.Fatal("a held subfolder was renamed between the scan and the write")
	}
	if descriptor(t, target) != before {
		t.Fatal("the junction's target had its access changed")
	}
}

// ID-D3, the models root: a drive root, the home folder, a known folder, a
// folder holding the home, a junctioned root and one under a junction are
// refused; a plain folder passes.
func TestCheckModelsRoot(t *testing.T) {
	home, err := windows.KnownFolderPath(windows.FOLDERID_Profile, 0)
	if err != nil {
		t.Fatal(err)
	}
	docs, err := windows.KnownFolderPath(windows.FOLDERID_Documents, 0)
	if err != nil {
		t.Fatal(err)
	}
	base := t.TempDir()
	plain := filepath.Join(base, "OA-models")
	if err := os.MkdirAll(filepath.Join(plain, "video"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := CheckModelsRoot(plain); err != nil {
		t.Fatalf("a plain root: %v", err)
	}
	// A short (8.3) name of the same folder does not resolve to itself.
	buf := make([]uint16, 1024)
	long, _ := windows.UTF16PtrFromString(plain)
	if n, err := windows.GetShortPathName(long, &buf[0], uint32(len(buf))); err == nil && n > 0 {
		if short := windows.UTF16ToString(buf[:n]); !strings.EqualFold(short, plain) {
			if err := CheckModelsRoot(short); !errors.Is(err, ErrNotModelFolder) {
				t.Fatalf("the short name %s: %v", short, err)
			}
		}
	}
	linked := filepath.Join(base, "linked")
	junction(t, linked, plain)
	for _, bad := range []string{`C:\`, home, docs, filepath.Dir(home), linked, filepath.Join(linked, "video"), "OA-models"} {
		if err := CheckModelsRoot(bad); !errors.Is(err, ErrNotModelFolder) {
			t.Fatalf("%s: %v", bad, err)
		}
	}
}
