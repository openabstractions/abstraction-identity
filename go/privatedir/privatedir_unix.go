//go:build unix

package privatedir

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"syscall"
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
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return errors.New("its owner cannot be read")
	}
	if int(stat.Uid) != uid {
		return fmt.Errorf("it is owned by uid %d, not %d", stat.Uid, uid)
	}
	if info.Mode().Perm()&0o077 != 0 || (exact && info.Mode().Perm() != 0o700) {
		return fmt.Errorf("its mode is %#o, not 0700", info.Mode().Perm())
	}
	return nil
}
