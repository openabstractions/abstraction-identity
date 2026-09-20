//go:build !windows

package identity

import "errors"

func packagePathByFullName(string) (string, error) {
	return "", errors.New("identity: MSIX packages are Windows only")
}
