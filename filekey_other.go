//go:build !unix && !windows

package identity

import (
	"errors"
	"os"
	"path/filepath"
)

// resolveLinks resolves an existing path through symbolic links.
func resolveLinks(path string) (string, error) { return filepath.EvalSymlinks(path) }

// fileKey has no file identity to read on this platform.
func fileKey(path string) (string, error) {
	return "", errors.New("identity: no file identity on this platform for " + path)
}

// pathExists reports whether path names an existing file, folder or link,
// as os.Lstat finds one.
func pathExists(path string) bool {
	_, err := os.Lstat(path)
	return err == nil
}
