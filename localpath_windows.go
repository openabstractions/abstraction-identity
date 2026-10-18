package identity

import (
	"errors"
	"path/filepath"
	"strings"
	"sync/atomic"

	"golang.org/x/sys/windows"
)

// localPath is LocalPath on Windows. It reads the spelling, the full path
// GetFullPathName makes of it (which reads no file), and the drive's type.
func localPath(path string) error {
	refuse := func(reason string) error { return &NotLocalPathError{Path: path, Reason: reason} }
	if path == "" {
		return errors.New("identity: empty path")
	}
	if strings.ContainsRune(path, 0) {
		return refuse("it holds a NUL")
	}
	s := strings.ReplaceAll(path, "/", `\`)
	switch {
	case strings.HasPrefix(s, `\??\`):
		return refuse("an NT object path")
	case strings.HasPrefix(s, `\\?\`):
		// A \\?\ path skips Win32 normalization; only a local drive letter's
		// is allowed, and it is read as written.
		rest := s[len(`\\?\`):]
		if !driveAbsolute(rest) {
			return refuse(`a \\?\ path naming no drive letter`)
		}
		s = rest
	case strings.HasPrefix(s, `\\`):
		return refuse(`a UNC or \\.\ device path`)
	default:
		abs, err := filepath.Abs(s)
		if err != nil {
			return refuse("it has no full path: " + err.Error())
		}
		s = strings.ReplaceAll(abs, "/", `\`)
		if strings.HasPrefix(s, `\\`) {
			// A relative path under a UNC working folder, or a device name
			// GetFullPathName turned into \\.\CON.
			return refuse(`its full path is a UNC or \\.\ device path`)
		}
	}
	if !driveAbsolute(s) {
		return refuse("it names no drive letter")
	}
	for _, part := range strings.Split(s[3:], `\`) {
		if reservedDeviceName(part) {
			return refuse("it names the device " + part)
		}
	}
	if pathDriveType(s[:3]) == windows.DRIVE_REMOTE {
		return refuse("a network drive")
	}
	return nil
}

// pathDriveType is GetDriveType of a drive root such as `C:\`, or
// DRIVE_REMOTE for a letter TreatDriveAsNetwork marks; tests stand in a
// mapped network drive without mapping one.
var pathDriveType = func(root string) uint32 {
	if letter := root[0] | 0x20; letter >= 'a' && letter <= 'z' && networkDrives.Load()&(1<<(letter-'a')) != 0 {
		return windows.DRIVE_REMOTE
	}
	p, err := windows.UTF16PtrFromString(root)
	if err != nil {
		return windows.DRIVE_UNKNOWN
	}
	return windows.GetDriveType(p)
}

// networkDrives holds one bit per drive letter TreatDriveAsNetwork marks.
var networkDrives atomic.Uint32

// TreatDriveAsNetwork is for tests, in this module and in its consumers:
// until restore is called, LocalPath refuses the drive letter as a network
// drive, as it refuses a letter mapped to a share, so a test can show a
// refusal opens nothing without mapping a drive. It only ever refuses more.
func TreatDriveAsNetwork(letter byte) (restore func()) {
	l := letter | 0x20
	if l < 'a' || l > 'z' {
		return func() {}
	}
	bit := uint32(1) << (l - 'a')
	networkDrives.Or(bit)
	return func() { networkDrives.And(^bit) }
}

// driveAbsolute reports whether s begins with a drive letter, a colon and a
// backslash.
func driveAbsolute(s string) bool {
	return len(s) >= 3 && (s[0]|0x20 >= 'a' && s[0]|0x20 <= 'z') && s[1] == ':' && s[2] == '\\'
}

// deviceNames are the DOS device names Win32 reads in any folder.
var deviceNames = func() []string {
	names := []string{"CON", "PRN", "AUX", "NUL", "CONIN$", "CONOUT$"}
	for _, port := range []string{"COM", "LPT"} {
		for _, n := range []string{"0", "1", "2", "3", "4", "5", "6", "7", "8", "9", "¹", "²", "³"} {
			names = append(names, port+n)
		}
	}
	return names
}()

// reservedDeviceName reports whether a path component names a DOS device in
// any folder: CON, PRN, AUX, NUL, COM0-9 and LPT0-9 (also with a superscript
// 1, 2 or 3), CONIN$ and CONOUT$, in any letter case as the file system's
// name rule compares (SamePathName), with any extension or stream, and with
// trailing spaces before either.
func reservedDeviceName(part string) bool {
	name := part
	if i := strings.IndexAny(name, ".:"); i >= 0 {
		name = name[:i]
	}
	name = strings.TrimRight(name, " ")
	// Every device name begins with one of these letters and is three to
	// seven bytes long; any other name asks no comparison.
	if len(name) < 3 || len(name) > 7 || !strings.ContainsRune("CcPpAaNnLl", rune(name[0])) {
		return false
	}
	for _, device := range deviceNames {
		if samePathName(name, device) {
			return true
		}
	}
	return false
}

// trimCreatedNames removes the trailing dots and spaces Windows strips from a
// name when it creates it, in every component of a path Win32 normalizes:
// the folder `new. ` is created as `new`, and a path through it keys as the
// path through `new`. A component of only dots and spaces, and a \\?\ path,
// which Windows reads as written, keep their spelling.
func trimCreatedNames(path string) string {
	if strings.HasPrefix(strings.ReplaceAll(path, "/", `\`), `\\?\`) {
		return path
	}
	volume := filepath.VolumeName(path)
	parts := strings.FieldsFunc(path[len(volume):], func(r rune) bool { return r == '/' || r == '\\' })
	for i, part := range parts {
		if trimmed := strings.TrimRight(part, ". "); trimmed != "" {
			parts[i] = trimmed
		}
	}
	rest := strings.Join(parts, `\`)
	if strings.HasPrefix(path[len(volume):], `\`) || strings.HasPrefix(path[len(volume):], "/") {
		rest = `\` + rest
	}
	return volume + rest
}
