// Package privatetest gives tests a temporary folder privatedir accepts as
// private to this account.
package privatetest

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// Dir is t.TempDir() made private on Unix. The testing package creates each
// TempDir with mode 0777 less the umask (0755 under umask 022), which
// privatedir refuses; Windows folders inherit the per-user temp ACL.
func Dir(t testing.TB) string {
	t.Helper()
	dir := t.TempDir()
	if runtime.GOOS != "windows" {
		if err := os.Chmod(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

// SocketDir is a private folder short enough for a Unix socket path: a
// TempDir named after a long test, or macOS's per-user TMPDIR, exceeds the
// 104 (macOS) or 108 (Linux) bytes sun_path holds. On Windows it is Dir.
func SocketDir(t testing.TB) string {
	t.Helper()
	if runtime.GOOS == "windows" {
		return Dir(t)
	}
	dir, err := os.MkdirTemp("/tmp", "oa")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	if dir, err = filepath.EvalSymlinks(dir); err != nil {
		t.Fatal(err)
	}
	return dir
}
