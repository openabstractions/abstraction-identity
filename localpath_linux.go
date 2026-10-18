//go:build linux

package identity

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

// networkFileSystems names, by statfs f_type, the Linux file systems whose
// files live on another host or on storage other hosts share (values from
// linux/magic.h and coreutils' stat). A path on one is refused. autofs is
// here because statfs reports it only for an automount point whose mount
// did not happen, typically a network share.
var networkFileSystems = map[uint32]string{
	0x6969:     "nfs",
	0x517b:     "smb",
	0xff534d42: "cifs",
	0xfe534d42: "smb2",
	0x00c36400: "ceph",
	0x5346414f: "afs",
	0x6b414653: "afs",
	0x01021997: "9p",
	0x73757245: "coda",
	0x564c:     "ncp",
	0x0bd00bd0: "lustre",
	0x47504653: "gpfs",
	0x19830326: "beegfs",
	0x01161970: "gfs2",
	0x7461636f: "ocfs2",
	0xaad7aaea: "panfs",
	0xbeefdead: "snfs",
	0x013111a8: "ibrix",
	0x61636673: "acfs",
	0x786f4256: "vboxsf",
	0xbacbacbc: "vmhgfs",
	0x7c7c6673: "prl_fs",
	0x0187:     "autofs",
}

// fuseSuperMagic is the f_type of every FUSE mount, local or remote; the
// mount's own type in /proc/self/mountinfo tells them apart.
const fuseSuperMagic = 0x65735546

// localFUSE names the FUSE mount types known to hold only local data: a
// block-device mount (fuseblk, as ntfs-3g and exfat-fuse mount), a
// file system synthesized by its daemon from the kernel (lxcfs), and local
// image and overlay mounts. Every other FUSE type, sshfs, rclone, s3fs,
// gvfsd-fuse, glusterfs and virtiofs among them, is refused.
var localFUSE = map[string]bool{
	"fuseblk":             true,
	"fuse.lxcfs":          true,
	"fuse.squashfuse":     true,
	"fuse.squashfuse_ll":  true,
	"fuse.fuse-overlayfs": true,
}

var (
	// statDevice reads the device number of the file at a path, following
	// links as statfs does; tests replace it.
	statDevice = func(path string) (uint64, error) {
		var st unix.Stat_t
		if err := unix.Stat(path, &st); err != nil {
			return 0, err
		}
		return uint64(st.Dev), nil
	}
	// readMountInfo reads this process's mount table; tests replace it.
	readMountInfo = func() ([]byte, error) { return os.ReadFile("/proc/self/mountinfo") }
)

// volumeAnswer is the Linux answer for the volume statfs read at p: a
// network file system (networkFileSystems) is refused; a FUSE mount is local
// only when its mount type, read from /proc/self/mountinfo by p's device
// number, is in localFUSE; every other file system is local.
func volumeAnswer(p string, st *unix.Statfs_t) error {
	magic := uint32(st.Type)
	if name, ok := networkFileSystems[magic]; ok {
		return fmt.Errorf("its volume is not a local file system (%s)", name)
	}
	if magic != fuseSuperMagic {
		return nil
	}
	dev, err := statDevice(p)
	if err != nil {
		return err
	}
	info, err := readMountInfo()
	if err != nil {
		return fmt.Errorf("its FUSE volume's type could not be read: %v", err)
	}
	types := mountTypes(info, unix.Major(dev), unix.Minor(dev))
	if len(types) == 0 {
		return errors.New("its FUSE volume is not in /proc/self/mountinfo")
	}
	for _, t := range types {
		if !localFUSE[t] {
			return fmt.Errorf("its volume is not a local file system (%s)", t)
		}
	}
	return nil
}

// systemMountPoints lists the mount points in /proc/self/mountinfo (field
// 5), which procfs writes without asking any mounted volume.
func systemMountPoints() ([]string, error) {
	info, err := os.ReadFile("/proc/self/mountinfo")
	if err != nil {
		return nil, err
	}
	return mountPointsOf(info), nil
}

// mountPointsOf lists the mount points (field 5) of a mountinfo table.
func mountPointsOf(info []byte) []string {
	var points []string
	for _, line := range strings.Split(string(info), "\n") {
		if fields := strings.Fields(line); len(fields) >= 9 {
			points = append(points, unescapeMountPath(fields[4]))
		}
	}
	return points
}

// systemRootAliases is empty on Linux, which has no firmlinks; a path through
// a symbolic link counts against the mount its spelling names.
func systemRootAliases() ([]alias, error) { return nil, nil }

// unescapeMountPath undoes mountinfo's octal escapes (\040 for a space,
// \011, \012, \134).
func unescapeMountPath(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+3 < len(s) {
			if n, err := strconv.ParseUint(s[i+1:i+4], 8, 8); err == nil {
				b.WriteByte(byte(n))
				i += 3
				continue
			}
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

// mountTypes returns the file system type of every /proc/self/mountinfo
// entry whose device is major:minor (field 3; the type follows the "-"
// separator after the optional fields).
func mountTypes(mountinfo []byte, major, minor uint32) []string {
	want := strconv.FormatUint(uint64(major), 10) + ":" + strconv.FormatUint(uint64(minor), 10)
	var types []string
	for _, line := range strings.Split(string(mountinfo), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 9 || fields[2] != want {
			continue
		}
		for i := 6; i+1 < len(fields); i++ {
			if fields[i] == "-" {
				types = append(types, fields[i+1])
				break
			}
		}
	}
	return types
}
