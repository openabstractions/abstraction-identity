package fileid

import (
	"context"
	"fmt"
	"strings"
	"unsafe"

	"golang.org/x/sys/unix"
)

// stillAt resolves h's path again with every link refused and reports
// whether it still names h's file. The kernel's own name for a descriptor
// (F_GETPATH) may spell a firmlinked folder differently from the walk.
func stillAt(h Handle) (bool, error) {
	id, err := Resolve(context.Background(), Self, h.id.path, Options{Links: RefuseLinks})
	if err != nil {
		return false, nil
	}
	return id.Equal(h.id), nil
}

func fdPath(fd int) (string, error) {
	buf := make([]byte, unix.PathMax)
	_, _, err := unix.Syscall(unix.SYS_FCNTL, uintptr(fd), unix.F_GETPATH, uintptr(unsafe.Pointer(&buf[0])))
	if err != 0 {
		return "", err
	}
	return unix.ByteSliceToString(buf), nil
}

// F_GETPATH can retain an unlinked vnode's former spelling. Require the
// observed literal locator to name this held object before returning it.
// This runs inside descriptorLocal's bounded worker.
func validateDescriptorName(fd int, name string) error {
	var held unix.Stat_t
	if err := unix.Fstat(fd, &held); err != nil {
		return err
	}
	if held.Nlink == 0 {
		return fmt.Errorf("descriptor has no live locator")
	}
	parent, err := unix.Open("/", openFlags(false)|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	defer func() { unix.Close(parent) }()
	for _, component := range splitPath(name) {
		var volume unix.Statfs_t
		if err := unix.Fstatfs(parent, &volume); err != nil {
			return err
		}
		if err := descriptorVolumeAnswer(parent, &volume); err != nil {
			return err
		}
		next, err := unix.Openat(parent, component, openFlags(false)|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
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
		return fmt.Errorf("descriptor locator names a different object")
	}
	return nil
}

// withoutStream refuses a path with a "..namedfork" component, which names a
// file's resource fork, a data stream of its own under the file's FileID
// (ID-F4).
func withoutStream(abs string) (string, error) {
	for _, name := range strings.Split(abs, "/") {
		if name == "..namedfork" {
			return "", fmt.Errorf("%w: %q names a resource fork", ErrUnsafeName, abs)
		}
	}
	return abs, nil
}

// openFlags opens a component read-only without blocking on a FIFO; macOS
// has no O_PATH, so a file this account cannot read cannot be resolved.
func openFlags(bool) int { return unix.O_RDONLY | unix.O_NONBLOCK }

// durabilityOf uses the bounded descriptor filesystem observation: APFS and HFS+ keep file IDs
// across a reboot; every other file system is volatile.
func durabilityOf(sfs *unix.Statfs_t) Durability {
	switch unix.ByteSliceToString(sfs.Fstypename[:]) {
	case "apfs", "hfs":
		return Persistent
	}
	return Volatile
}
