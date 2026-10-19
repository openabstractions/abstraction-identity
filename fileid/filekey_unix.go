//go:build unix

package fileid

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
	return fileKeyInfo(info)
}

// FileKeyOf reads device and inode identity from the passed open descriptor.
// It neither reopens its name nor establishes locality or prevents mutation.
// Rename, unlink and replacement of that name leave the held identity intact.
func FileKeyOf(file *os.File) (string, error) {
	if file == nil {
		return "", fmt.Errorf("identity: no file handle")
	}
	info, err := file.Stat()
	if err != nil {
		return "", err
	}
	return fileKeyInfo(info)
}

func fileKeyInfo(info os.FileInfo) (string, error) {
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return "", fmt.Errorf("identity: file has no device and inode")
	}
	return deviceInodeKey(uint64(st.Dev), uint64(st.Ino)), nil
}

func deviceInodeKey(device, inode uint64) string { return fmt.Sprintf("%x-%x", device, inode) }

// pathExists reports whether path names an existing file, folder or link,
// as os.Lstat finds one.
func pathExists(path string) bool {
	_, err := os.Lstat(path)
	return err == nil
}
