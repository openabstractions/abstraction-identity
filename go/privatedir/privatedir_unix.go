//go:build unix

package privatedir

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"syscall"

	"golang.org/x/sys/unix"
)

// check refuses dir unless it is a directory reached through no link, owned
// by this account, with mode 0700.
func check(dir string) error {
	info, err := os.Lstat(dir)
	if err != nil {
		return err
	}
	return checkInfo(info, os.Getuid(), true)
}

// OwnerOnly reports whether info, a folder found by following links, is a
// directory of this account open to no group or other, in any owner-only
// mode: the test a per-user base folder such as $XDG_RUNTIME_DIR passes
// before a private folder is made in it.
func OwnerOnly(info fs.FileInfo) error {
	return checkInfo(info, os.Getuid(), false)
}

// checkInfo is check's rule on a file's information: a directory, not a
// link, owned by uid, open to no group or other. exact asks for mode 0700
// itself.
func checkInfo(info fs.FileInfo, uid int, exact bool) error {
	if info.Mode()&fs.ModeSymlink != 0 {
		return errors.New("it is a link")
	}
	if !info.IsDir() {
		return errors.New("it is not a directory")
	}
	if err := checkOwnerMode(info, uid); err != nil {
		return err
	}
	if exact && info.Mode().Perm() != 0o700 {
		return fmt.Errorf("its mode is %#o, not 0700", info.Mode().Perm())
	}
	return nil
}

const privateFileRead = false // O_PATH identity/stat access avoids opening FIFOs.

func checkFileHandle(_ *os.File, info fs.FileInfo) error {
	return checkOwnerMode(info, os.Getuid())
}

func checkOwnerMode(info fs.FileInfo, uid int) error {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return errors.New("its owner cannot be read")
	}
	if int(stat.Uid) != uid {
		return fmt.Errorf("it is owned by uid %d, not %d", stat.Uid, uid)
	}
	if info.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("its mode is %#o, not 0700", info.Mode().Perm())
	}
	return nil
}

// tighten opens dir as itself (O_NOFOLLOW refuses a link, O_DIRECTORY a
// file) and gives it mode 0700 through that descriptor.
func tighten(dir string) error {
	fd, err := unix.Open(dir, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return &fs.PathError{Op: "open", Path: dir, Err: err}
	}
	//unchecked: the descriptor is read-only; a failed close changes nothing
	defer unix.Close(fd)
	if err := unix.Fchmod(fd, 0o700); err != nil {
		return &fs.PathError{Op: "fchmod", Path: dir, Err: err}
	}
	return nil
}
