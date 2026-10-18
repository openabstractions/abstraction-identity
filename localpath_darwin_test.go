//go:build darwin

package identity

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// markLocal makes a stubbed statfs answer a local volume.
func markLocal(st *unix.Statfs_t) { st.Flags = unix.MNT_LOCAL }

// [ID-F1] systemRootAliases reads every firmlink and every symbolic link in
// the root folder.
func TestSystemRootAliasesReadsFirmlinksAndRootLinks(t *testing.T) {
	if os.Getenv("OA_IDENTITY_ROOT_ALIASES_HELPER") != "1" {
		// A prior LocalPath call can leave a system alias reader in flight.
		// Run only this fixture in a fresh test process before changing paths.
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		child := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestSystemRootAliasesReadsFirmlinksAndRootLinks$")
		child.Env = append(os.Environ(), "OA_IDENTITY_ROOT_ALIASES_HELPER=1")
		if out, err := child.CombinedOutput(); err != nil {
			t.Fatalf("alias fixture: %v\n%s", err, out)
		}
		return
	}
	dir := t.TempDir()
	list := filepath.Join(dir, "firmlinks")
	if err := os.WriteFile(list, []byte("/Users\tUsers\n/usr/local\tusr/local\nbroken line\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	root := filepath.Join(dir, "root")
	if err := os.MkdirAll(filepath.Join(root, "folder"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/System/Volumes/Data/home", filepath.Join(root, "home")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("private/var", filepath.Join(root, "var")); err != nil {
		t.Fatal(err)
	}
	previousList, previousRoot := firmlinksFile, rootFolder
	firmlinksFile, rootFolder = list, root
	defer func() { firmlinksFile, rootFolder = previousList, previousRoot }()
	aliases, err := systemRootAliases()
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, a := range aliases {
		got[a.from] = a.to
	}
	want := map[string]string{
		"/Users":     "/System/Volumes/Data/Users",
		"/usr/local": "/System/Volumes/Data/usr/local",
		"/home":      "/System/Volumes/Data/home",
		"/var":       filepath.Join(root, "private/var"),
	}
	if len(got) != len(want) {
		t.Errorf("aliases %v, want %v", got, want)
	}
	for from, to := range want {
		if got[from] != to {
			t.Errorf("alias %s = %q, want %q", from, got[from], to)
		}
	}
}

// A mount refresh may still be reading system aliases when the next fixture
// starts. Its system paths and the fixture's paths remain independent.
func TestSystemRootAliasesFixtureDuringSystemRead(t *testing.T) {
	start := make(chan struct{})
	done := make(chan error, 1)
	go func() {
		<-start
		_, err := systemRootAliases()
		done <- err
	}()
	close(start)
	t.Run("fixture", TestSystemRootAliasesReadsFirmlinksAndRootLinks)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

// [ID-F1] On this Mac, /Users and the temporary folder count against the
// data volume, and /home against its automount when it is one.
func TestMountOfOnThisMac(t *testing.T) {
	forgetMountTable()
	if got := mountName("/Users/nobody/file"); got != dataVolume {
		t.Errorf("mountOf(/Users/...) = %q, want %q", got, dataVolume)
	}
	if got := mountName(filepath.Join(t.TempDir(), "x")); got != dataVolume {
		t.Errorf("mountOf(temporary folder) = %q, want %q", got, dataVolume)
	}
	if got := mountName("/usr/bin/true"); got != "/" {
		t.Errorf("mountOf(/usr/bin/true) = %q, want /", got)
	}
	t.Logf("/home/u counts against %q", mountName("/home/u"))
}

// [ID-F1] Paths on the boot volume are local, including ones not created yet.
func TestLocalPathAdmitsLocalVolumes(t *testing.T) {
	dir := t.TempDir()
	for _, p := range []string{"/", dir, filepath.Join(dir, "not", "yet", "created.bin"), "/System/Applications/Calculator.app/Contents/MacOS/Calculator", "relative/name"} {
		if err := LocalPath(p); err != nil {
			t.Errorf("LocalPath(%q) = %v", p, err)
		}
	}
	if LocalPath("") == nil {
		t.Error("empty path admitted")
	}
}

// [ID-F1] A volume without MNT_LOCAL (SMB, NFS, AFP, WebDAV) is refused with
// the typed error, for an existing path and for one still to be created.
func TestLocalPathRefusesNetworkVolumes(t *testing.T) {
	stubStatfs(t, func(path string, st *unix.Statfs_t) error {
		if path == "/Volumes/share/new" {
			return unix.ENOENT
		}
		st.Flags = unix.MNT_NOSUID | unix.MNT_NODEV // a typical smbfs mount: no MNT_LOCAL
		return nil
	})
	for _, p := range []string{"/Volumes/share/Editor.app/Contents/MacOS/Editor", "/Volumes/share/new"} {
		err := LocalPath(p)
		var typed *NotLocalPathError
		if !errors.Is(err, ErrNotLocalPath) || !errors.As(err, &typed) || typed.Path != p || typed.Reason == "" {
			t.Errorf("LocalPath(%q) = %v, want a NotLocalPathError", p, err)
		}
		if ok, err := SameFile(p, p); ok || !errors.Is(err, ErrNotLocalPath) {
			t.Errorf("SameFile(%q) = %t, %v", p, ok, err)
		}
	}
}

// A local disk image mounted under /Volumes is local. Opt-in, since it
// attaches and detaches an image: OA_IDENTITY_DISK_IMAGE=1.
func TestLocalPathAdmitsAttachedDiskImage(t *testing.T) {
	if os.Getenv("OA_IDENTITY_DISK_IMAGE") != "1" {
		t.Skip("OA_IDENTITY_DISK_IMAGE=1 attaches a scratch disk image under /Volumes")
	}
	image := filepath.Join(t.TempDir(), "oa-localpath.dmg")
	if out, err := exec.Command("hdiutil", "create", "-size", "4m", "-fs", "APFS", "-volname", "OALocalPathTest", image).CombinedOutput(); err != nil {
		t.Fatalf("hdiutil create: %v %s", err, out)
	}
	out, err := exec.Command("hdiutil", "attach", "-nobrowse", "-mountrandom", "/Volumes", image).CombinedOutput()
	if err != nil {
		t.Fatalf("hdiutil attach: %v %s", err, out)
	}
	fields := strings.Fields(strings.TrimSpace(string(out)))
	mount := ""
	for i, f := range fields {
		if strings.HasPrefix(f, "/Volumes/") {
			mount = strings.Join(fields[i:], " ")
			break
		}
	}
	if mount == "" {
		t.Fatalf("no mount point in %q", out)
	}
	t.Cleanup(func() { _ = exec.Command("hdiutil", "detach", "-force", mount).Run() })
	for _, p := range []string{mount, filepath.Join(mount, "new", "file")} {
		if err := LocalPath(p); err != nil {
			t.Errorf("LocalPath(%q) on an attached disk image = %v", p, err)
		}
	}
	t.Logf("disk image mounted at %s is local", mount)
}

// A real network mount is refused. Opt-in: OA_IDENTITY_NETWORK_PATH names a
// path on an SMB, NFS or AFP volume.
func TestLocalPathRefusesRealNetworkMount(t *testing.T) {
	p := os.Getenv("OA_IDENTITY_NETWORK_PATH")
	if p == "" {
		t.Skip("OA_IDENTITY_NETWORK_PATH=<path on a network volume> checks a real mount")
	}
	if err := LocalPath(p); !errors.Is(err, ErrNotLocalPath) {
		t.Fatalf("LocalPath(%q) = %v on a network volume", p, err)
	}
}
