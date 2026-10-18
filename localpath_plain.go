//go:build !windows && !darwin && !linux

package identity

import "errors"

// localPath is LocalPath on systems other than Windows, macOS and Linux:
// every nonempty path is local. Telling an NFS, SMB or CIFS mount apart is
// not done there.
func localPath(path string) error {
	if path == "" {
		return errors.New("identity: empty path")
	}
	return nil
}
