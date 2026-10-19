package fileid

import (
	"errors"
	"os"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

// withoutStream returns abs: Linux names no data stream by path, and a colon
// is an ordinary byte of a name.
func withoutStream(abs string) (string, error) { return abs, nil }

// stillAt reads the path the kernel keeps for h's descriptor
// (/proc/self/fd) and reports whether it is the path the walk spelled.
func stillAt(h Handle) (bool, error) {
	now, err := fdPath(fdOf(h))
	if err != nil {
		return false, &pathError{op: "name", path: h.id.path, err: err}
	}
	return now == h.id.path, nil
}

func fdPath(fd int) (string, error) {
	return os.Readlink("/proc/self/fd/" + strconv.Itoa(fd))
}

func validateDescriptorName(fd int, name string) error {
	if !strings.HasSuffix(name, " (deleted)") {
		return nil
	}
	// d_path appends this diagnostic suffix for an unlinked dentry. It is
	// also a legal filename, so require a live literal locator for this ID.
	var held unix.Stat_t
	if err := unix.Fstat(fd, &held); err != nil {
		return err
	}
	if held.Nlink == 0 || !strings.HasPrefix(name, "/") {
		return errors.New("descriptor has no live locator")
	}
	parent, err := unix.Open("/", unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	defer func() { unix.Close(parent) }()
	for _, component := range strings.Split(strings.TrimPrefix(name, "/"), "/") {
		if component == "" || component == "." || component == ".." {
			return errors.New("descriptor locator has no literal component")
		}
		var volume unix.Statfs_t
		if err := unix.Fstatfs(parent, &volume); err != nil {
			return err
		}
		if err := descriptorVolumeAnswer(parent, &volume); err != nil {
			return err
		}
		next, err := unix.Openat(parent, component, unix.O_PATH|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		if err != nil {
			return err
		}
		unix.Close(parent)
		parent = next
	}
	var found unix.Stat_t
	if err := unix.Fstat(parent, &found); err != nil {
		return err
	}
	if found.Dev != held.Dev || found.Ino != held.Ino {
		return errors.New("descriptor locator names a different object")
	}
	return nil
}

// openFlags opens a component for its identity alone (O_PATH, which needs no
// read access and opens a FIFO or device without blocking or running a
// driver), or for reading.
func openFlags(read bool) int {
	if read {
		return unix.O_RDONLY | unix.O_NONBLOCK
	}
	return unix.O_PATH
}

// persistentTypes are the statfs f_type values of Linux file systems whose
// inode numbers name one file until it is deleted and survive a remount.
var persistentTypes = map[int64]bool{
	0xEF53:     true, // ext2, ext3, ext4
	0x58465342: true, // XFS
	0x9123683E: true, // Btrfs
	0xF2F52010: true, // F2FS
	0x2FC12FC1: true, // ZFS
	0x3153464A: true, // JFS
	0x52654973: true, // ReiserFS
}

// durabilityOf uses the bounded descriptor filesystem observation: a key is persistent on the file
// systems above and volatile on every other, FAT and exFAT (whose inode
// numbers are made up per mount), tmpfs and network or FUSE file systems
// included.
func durabilityOf(sfs *unix.Statfs_t) Durability {
	if persistentTypes[int64(sfs.Type)] {
		return Persistent
	}
	return Volatile
}
