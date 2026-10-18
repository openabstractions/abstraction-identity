//go:build !windows

package privatedir

import (
	"fmt"
	"os"
)

// Make creates dir with mode 0700 whatever the umask. Mkdir refuses an
// existing path, a link included (fs.ErrExist).
func Make(dir string) error {
	if err := os.Mkdir(dir, 0o700); err != nil {
		return err
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		//unchecked: the directory was just created empty; the chmod failure is the error returned
		os.Remove(dir)
		return err
	}
	info, err := os.Lstat(dir)
	if err != nil || !info.IsDir() || info.Mode().Perm() != 0o700 {
		//unchecked: the directory is refused; the mode error is returned
		os.Remove(dir)
		return fmt.Errorf("%s is not a 0700 directory after creation", dir)
	}
	return nil
}
