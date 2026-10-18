//go:build linux

package identity

import (
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// stubMounts replaces the device-number stat and the mount table, which
// also supplies the mount points the probe cap is kept by.
func stubMounts(t *testing.T, dev uint64, mountinfo string, readErr error) {
	t.Helper()
	previousStat, previousRead := statDevice, readMountInfo
	statDevice = func(string) (uint64, error) { return dev, nil }
	readMountInfo = func() ([]byte, error) { return []byte(mountinfo), readErr }
	t.Cleanup(func() { statDevice, readMountInfo = previousStat, previousRead })
	t.Cleanup(setMountReaders(func() ([]string, error) { return mountPointsOf([]byte(mountinfo)), readErr }, nil))
}

// setFSType stores a magic number in Statfs_t.Type, which is int64, int32 or
// uint32 by architecture; volumeAnswer reads it back as uint32.
func setFSType[T int32 | int64 | uint32 | uint64](field *T, magic uint32) { *field = T(magic) }

// markLocal makes a stubbed statfs answer a local volume (ext4).
func markLocal(st *unix.Statfs_t) { setFSType(&st.Type, 0xef53) }

func wantRefused(t *testing.T, p string) {
	t.Helper()
	err := LocalPath(p)
	var typed *NotLocalPathError
	if !errors.Is(err, ErrNotLocalPath) || !errors.As(err, &typed) || typed.Path != p || typed.Reason == "" {
		t.Errorf("LocalPath(%q) = %v, want a NotLocalPathError", p, err)
	}
}

// [ID-F1] Paths on local file systems are local, including ones not created
// yet. The test binary, its temporary folder and /proc are local on any
// Linux; a relative path resolves against a local working folder.
func TestLocalPathAdmitsLocalVolumes(t *testing.T) {
	dir := t.TempDir()
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{"/", dir, filepath.Join(dir, "not", "yet", "created.bin"), exe, "/proc/self/status"} {
		if err := LocalPath(p); err != nil {
			t.Errorf("LocalPath(%q) = %v", p, err)
		}
	}
	t.Chdir(dir)
	if err := LocalPath("relative/name"); err != nil {
		t.Errorf("LocalPath(relative/name) in %s = %v", dir, err)
	}
	if LocalPath("") == nil {
		t.Error("empty path admitted")
	}
}

// [ID-F1] A network file system (NFS, SMB, CIFS, SMB2, Ceph, AFS, 9P, ...) is
// refused with the typed error, for an existing path and for one still to be
// created, and SameFile refuses it before any open.
func TestLocalPathRefusesNetworkFileSystems(t *testing.T) {
	for magic, name := range networkFileSystems {
		t.Run(name+"-"+strconv.FormatUint(uint64(magic), 16), func(t *testing.T) {
			stubStatfs(t, func(path string, st *unix.Statfs_t) error {
				if path == "/mnt/share/new" {
					return unix.ENOENT
				}
				setFSType(&st.Type, magic)
				return nil
			})
			for _, p := range []string{"/mnt/share/Editor/editor", "/mnt/share/new"} {
				wantRefused(t, p)
				if ok, err := SameFile(p, p); ok || !errors.Is(err, ErrNotLocalPath) {
					t.Errorf("SameFile(%q) = %t, %v", p, ok, err)
				}
			}
		})
	}
	// Local file systems are admitted: ext4, xfs, btrfs, tmpfs, overlayfs.
	for _, magic := range []uint32{0xef53, 0x58465342, 0x9123683e, 0x01021994, 0x794c7630} {
		stubStatfs(t, func(_ string, st *unix.Statfs_t) error { setFSType(&st.Type, magic); return nil })
		if err := LocalPath("/data/model.bin"); err != nil {
			t.Errorf("f_type %#x refused: %v", magic, err)
		}
	}
}

// The table agrees with the kernel's values where x/sys/unix names them.
func TestNetworkFileSystemMagicsMatchTheKernel(t *testing.T) {
	for magic, name := range map[uint32]string{
		unix.NFS_SUPER_MAGIC: "nfs", unix.SMB_SUPER_MAGIC: "smb", unix.CIFS_SUPER_MAGIC: "cifs",
		unix.SMB2_SUPER_MAGIC: "smb2", unix.CEPH_SUPER_MAGIC: "ceph", unix.AFS_SUPER_MAGIC: "afs",
		unix.AFS_FS_MAGIC: "afs", unix.V9FS_MAGIC: "9p", unix.CODA_SUPER_MAGIC: "coda",
		unix.NCP_SUPER_MAGIC: "ncp", unix.OCFS2_SUPER_MAGIC: "ocfs2", unix.AUTOFS_SUPER_MAGIC: "autofs",
	} {
		if networkFileSystems[magic] != name {
			t.Errorf("f_type %#x is %q, want %q", magic, networkFileSystems[magic], name)
		}
	}
	if fuseSuperMagic != unix.FUSE_SUPER_MAGIC {
		t.Errorf("fuseSuperMagic %#x, kernel %#x", fuseSuperMagic, unix.FUSE_SUPER_MAGIC)
	}
}

// [ID-F1] statfs reports FUSE for every FUSE mount, so the mount's own type
// in /proc/self/mountinfo, found by the path's device number, decides: sshfs
// and other network FUSE types, an unknown subtype, a plain "fuse" and a
// mount that cannot be found are refused; fuseblk and the other known local
// types are admitted.
func TestLocalPathDecidesFUSEByMountType(t *testing.T) {
	stubStatfs(t, func(_ string, st *unix.Statfs_t) error { setFSType(&st.Type, fuseSuperMagic); return nil })
	dev := unix.Mkdev(0, 52)
	line := func(devno, fstype string) string {
		return "61 29 " + devno + " / /home/u/mnt\\040share rw,nosuid,nodev,relatime shared:33 - " + fstype + " host:/srv rw,user_id=1000,group_id=1000\n"
	}
	const root = "22 1 8:2 / / rw,relatime shared:1 - ext4 /dev/sda2 rw\n"
	for _, c := range []struct {
		mountinfo string
		local     bool
	}{
		{root + line("0:52", "fuse.sshfs"), false},
		{root + line("0:52", "fuse.rclone"), false},
		{root + line("0:52", "fuse.gvfsd-fuse"), false},
		{root + line("0:52", "fuse.my-new-fs"), false},
		{root + line("0:52", "fuse"), false},
		{root + line("0:52", "virtiofs"), false},
		{root + line("0:53", "fuseblk"), false},                              // no entry for 0:52
		{root + line("0:52", "fuseblk") + line("0:52", "fuse.sshfs"), false}, // one device, conflicting types
		{root + line("0:52", "fuseblk"), true},
		{root + line("0:52", "fuse.lxcfs"), true},
		{root + line("0:52", "fuse.squashfuse"), true},
		{root + line("0:52", "fuse.fuse-overlayfs"), true},
	} {
		stubMounts(t, dev, c.mountinfo, nil)
		err := LocalPath("/home/u/mnt share/file")
		if c.local && err != nil {
			t.Errorf("refused with mountinfo %q: %v", c.mountinfo, err)
		}
		if !c.local && !errors.Is(err, ErrNotLocalPath) {
			t.Errorf("admitted with mountinfo %q: %v", c.mountinfo, err)
		}
	}
	stubMounts(t, dev, "", errors.New("permission denied"))
	wantRefused(t, "/home/u/mnt share/file")
	previous := statDevice
	statDevice = func(string) (uint64, error) { return 0, unix.EIO }
	defer func() { statDevice = previous }()
	wantRefused(t, "/home/u/mnt share/file")
}

// [ID-F1] A FUSE path whose device-number stat blocks (a dead sshfs daemon)
// is refused within the deadline, its probe stays counted while the stat is
// outstanding, and the slot is released once the stat returns.
func TestLocalPathBoundsABlockedFUSEStat(t *testing.T) {
	stubMountPoints(t, "/", "/home/u/fuse")
	stubStatfs(t, func(_ string, st *unix.Statfs_t) error { setFSType(&st.Type, fuseSuperMagic); return nil })
	release := make(chan struct{})
	returned := make(chan struct{})
	previous := statDevice
	statDevice = func(string) (uint64, error) {
		<-release
		defer close(returned)
		return unix.Mkdev(0, 52), nil
	}
	released := false
	t.Cleanup(func() {
		if !released {
			close(release)
		}
		waitProbesDrained()
		statDevice = previous
	})
	begun := time.Now()
	wantRefused(t, "/home/u/fuse/model.bin")
	if elapsed := time.Since(begun); elapsed > localVolumeDeadline+time.Second {
		t.Fatalf("LocalPath waited %v on a blocked FUSE stat", elapsed)
	}
	if n := outstandingProbes(); n != 1 {
		t.Fatalf("%d probes outstanding while the stat blocks, want 1", n)
	}
	released = true
	close(release)
	<-returned
	waitProbesDrained()
	if n := outstandingProbes(); n != 0 {
		t.Fatalf("%d probes still counted after the stat returned", n)
	}
}

// [ID-F1] A stacked file system is judged by its top layer, the volume statfs
// reports for the path; the layers below are never probed. An overlayfs
// container root, fuse-overlayfs, squashfuse and file systems on loop images
// (ext4, squashfs) are local, even when a lower layer lies on NFS.
func TestLocalPathJudgesStackedFileSystemsByTopLayer(t *testing.T) {
	const overlayMagic, squashfsMagic, ext4Magic = 0x794c7630, 0x73717368, 0xef53
	const table = "22 1 0:31 / / rw,relatime - overlay overlay rw,lowerdir=/mnt/nfs/layers/l1:/mnt/nfs/layers/l2,upperdir=/var/lib/c/upper,workdir=/var/lib/c/work\n" +
		"40 22 0:52 / /opt/tool rw,nosuid,nodev - fuse.squashfuse /mnt/nfs/tool.squashfs ro\n" +
		"41 22 0:53 / /run/podman rw - fuse.fuse-overlayfs fuse-overlayfs rw,lowerdir=/mnt/nfs/l\n" +
		"42 22 7:0 / /snap/app/1 ro - squashfs /dev/loop0 ro\n" +
		"43 22 7:1 / /srv/image rw - ext4 /dev/loop1 rw\n" +
		"50 22 0:60 / /mnt/nfs rw - nfs4 host:/export rw\n"
	devs := map[string]uint64{"/opt/tool": unix.Mkdev(0, 52), "/run/podman": unix.Mkdev(0, 53)}
	types := map[string]uint32{"/": overlayMagic, "/opt/tool": fuseSuperMagic, "/run/podman": fuseSuperMagic, "/snap/app/1": squashfsMagic, "/srv/image": ext4Magic, "/mnt/nfs": 0x6969}
	stubMounts(t, 0, table, nil)
	statDevice = func(p string) (uint64, error) { return devs[mountName(p)], nil }
	var mu sync.Mutex
	var probed []string
	stubStatfs(t, func(p string, st *unix.Statfs_t) error {
		mu.Lock()
		probed = append(probed, p)
		mu.Unlock()
		setFSType(&st.Type, types[mountName(p)])
		return nil
	})
	forgetMountTable()
	for _, p := range []string{"/usr/bin/tool", "/opt/tool/bin/tool", "/run/podman/rootfs/app", "/snap/app/1/bin/app", "/srv/image/models/m.bin"} {
		if err := LocalPath(p); err != nil {
			t.Errorf("LocalPath(%q) on a stacked file system = %v", p, err)
		}
	}
	wantRefused(t, "/mnt/nfs/layers/l1/file")
	mu.Lock()
	defer mu.Unlock()
	for _, p := range probed {
		if strings.HasPrefix(p, "/mnt/nfs") && p != "/mnt/nfs/layers/l1/file" {
			t.Errorf("a lower layer was probed: %s", p)
		}
	}
}

// mountTypes reads the type after the "-" separator, past any number of
// optional fields.
func TestMountTypesSkipsOptionalFields(t *testing.T) {
	info := "36 35 98:0 /mnt1 /mnt/parent rw,noatime master:1 - ext3 /dev/root rw,errors=continue\n" +
		"37 35 98:0 /mnt2 /mnt/other rw,noatime shared:2 master:1 propagate_from:3 - ext3 /dev/root rw\n" +
		"38 35 0:40 / /mnt/nfs rw - nfs4 host:/x rw\n"
	if got := mountTypes([]byte(info), 98, 0); strings.Join(got, ",") != "ext3,ext3" {
		t.Errorf("98:0 types %v", got)
	}
	if got := mountTypes([]byte(info), 0, 40); strings.Join(got, ",") != "nfs4" {
		t.Errorf("0:40 types %v", got)
	}
	if got := mountTypes([]byte(info), 1, 1); got != nil {
		t.Errorf("1:1 types %v", got)
	}
}

// [ID-F1] Every network mount this machine already has is refused, read from
// the real /proc/self/mountinfo with the real statfs; in WSL that includes
// the Windows drives under /mnt, which are 9P. Nothing is mounted for the
// test; it skips when the machine has no network mount.
func TestLocalPathRefusesThisMachinesNetworkMounts(t *testing.T) {
	info, err := os.ReadFile("/proc/self/mountinfo")
	if err != nil {
		t.Skip(err)
	}
	network := map[string]bool{"nfs": true, "nfs4": true, "cifs": true, "smb3": true, "smbfs": true, "9p": true, "ceph": true, "afs": true, "fuse.sshfs": true, "fuse.rclone": true}
	checked := 0
	for _, line := range strings.Split(string(info), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 9 {
			continue
		}
		fstype := ""
		for i := 6; i+1 < len(fields); i++ {
			if fields[i] == "-" {
				fstype = fields[i+1]
				break
			}
		}
		if !network[fstype] {
			continue
		}
		mount := unescapeMountPath(fields[4])
		err := LocalPath(mount)
		if !errors.Is(err, ErrNotLocalPath) {
			t.Errorf("LocalPath(%q) on %s = %v", mount, fstype, err)
		}
		t.Logf("%s (%s): %v", mount, fstype, err)
		checked++
	}
	if checked == 0 {
		t.Skip("no network mount on this machine")
	}
}

// A real network mount is refused. Opt-in: OA_IDENTITY_NETWORK_PATH names a
// path on an NFS, SMB or sshfs mount.
func TestLocalPathRefusesRealNetworkMount(t *testing.T) {
	p := os.Getenv("OA_IDENTITY_NETWORK_PATH")
	if p == "" {
		t.Skip("OA_IDENTITY_NETWORK_PATH=<path on a network mount> checks a real mount")
	}
	if err := LocalPath(p); !errors.Is(err, ErrNotLocalPath) {
		t.Fatalf("LocalPath(%q) = %v on a network mount", p, err)
	}
}
