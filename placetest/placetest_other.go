//go:build !windows

package placetest

import (
	"errors"
	"os"
)

var errWindowsOnly = errors.New("placetest: Windows only")

// ShortName has no answer outside Windows.
func ShortName(string) (string, error) { return "", errWindowsOnly }

// LongPath has no answer outside Windows.
func LongPath(string) (string, error) { return "", errWindowsOnly }

// SameSID has no answer outside Windows.
func SameSID(string, string) (bool, error) { return false, errWindowsOnly }

// MachineAdministratorSID has no answer outside Windows.
func MachineAdministratorSID() (string, error) { return "", errWindowsOnly }

// Junction has no answer outside Windows.
func Junction(string, string) error { return errWindowsOnly }

// CaseSensitive has no answer outside Windows.
func CaseSensitive(string) error { return errWindowsOnly }

// ShareJunction has no answer outside Windows.
func ShareJunction(string) error { return errWindowsOnly }

// MountPoint has no answer outside Windows.
func MountPoint(string, string, string) error { return errWindowsOnly }

// VolumeMountPoint has no answer outside Windows.
func VolumeMountPoint(string, string) (string, error) { return "", errWindowsOnly }

// Compact has no answer outside Windows.
func Compact(string) error { return errWindowsOnly }

// TestNetShare spells a Windows share of TestNetHost on every platform; it
// names nothing a POSIX path function opens.
func TestNetShare(rest string, extended bool) string {
	if extended {
		return `\\?\UNC\` + TestNetHost + `\share\` + rest
	}
	return `\\` + TestNetHost + `\share\` + rest
}

// FolderSymlink makes link a symbolic link to the folder target.
func FolderSymlink(link, target string) error { return os.Symlink(target, link) }
