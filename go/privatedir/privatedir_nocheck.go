//go:build !windows && !unix

package privatedir

import (
	"fmt"
	"io/fs"
	"os"
	"runtime"
)

// check has no owner check on this platform.
func check(string) error {
	return fmt.Errorf("no owner check on %s", runtime.GOOS)
}

const privateFileRead = false

func checkFileHandle(*os.File, fs.FileInfo) error {
	return fmt.Errorf("no file owner check on %s", runtime.GOOS)
}

// tighten gives dir mode 0700 by its path; this platform has no descriptor
// call that refuses a link.
func tighten(dir string) error { return os.Chmod(dir, 0o700) }
