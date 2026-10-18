//go:build unix

package identity

import (
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

// resolveLinks resolves an existing path through symbolic links.
func resolveLinks(path string) (string, error) { return filepath.EvalSymlinks(path) }

// fileKey reads the device and inode numbers of path, following links as
// os.Stat follows them.
func fileKey(path string) (string, error) {
	info, err := os.Stat(path)
	if err != nil {
		return "", err
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return "", fmt.Errorf("identity: %s has no device and inode", path)
	}
	return fmt.Sprintf("%x-%x", uint64(st.Dev), uint64(st.Ino)), nil
}

// pathExists reports whether path names an existing file, folder or link,
// as os.Lstat finds one.
func pathExists(path string) bool {
	_, err := os.Lstat(path)
	return err == nil
}
