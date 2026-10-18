// Package privatedir makes and checks folders private to this account
// (identity CONTRACT.md ID-D1): the one helper OA uses for every folder only
// this account may write, the engine socket root and its launch directories
// (inference CONTRACT.md INF-EL2), the span record folder (INF-MS7), the
// Lemonade provider's state and package folders, and the storage reader's
// digest record (storage-over-local-stores LS-12).
//
// On Windows a private folder is owned by this account and carries a
// protected DACL that allows only this account and SYSTEM; Make sets it at
// CreateDirectory, so the folder never holds its parent's inherited
// entries. Elsewhere it is a directory of this account with mode 0700. A
// link, a junction or a file is never a private folder.
package privatedir

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
)

// ErrNotPrivate reports a folder CheckDir or Ensure refuses: a file, a link,
// another owner, or access beyond this account (and SYSTEM on Windows).
var ErrNotPrivate = errors.New("privatedir: folder is not private to this account")

// Ensure makes dir, an absolute path, private to this account if it is
// absent, then refuses it unless it is a private folder. Its parent is
// created as an ordinary folder.
func Ensure(dir string) error {
	if !filepath.IsAbs(dir) {
		return fmt.Errorf("%w: %q is not absolute", ErrNotPrivate, dir)
	}
	dir = filepath.Clean(dir)
	if _, err := os.Lstat(dir); errors.Is(err, fs.ErrNotExist) {
		if err := os.MkdirAll(filepath.Dir(dir), 0o700); err != nil {
			return err
		}
		// Another process may create it between the two calls; CheckDir
		// judges whichever directory stands there.
		if err := Make(dir); err != nil && !errors.Is(err, fs.ErrExist) {
			return err
		}
	} else if err != nil {
		return err
	}
	return CheckDir(dir)
}

// CheckDir refuses dir unless it is a private folder of this account
// (ErrNotPrivate).
func CheckDir(dir string) error {
	if err := check(dir); err != nil {
		return fmt.Errorf("%w: %s: %v", ErrNotPrivate, dir, err)
	}
	return nil
}
