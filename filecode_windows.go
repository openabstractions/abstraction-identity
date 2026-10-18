//go:build windows

package identity

import (
	"fmt"
	"path/filepath"
	"strings"

	"golang.org/x/sys/windows"
)

// verifyFileShare is the share mode VerifyFile holds its file with. It omits
// FILE_SHARE_WRITE: no one can open the file for writing during the
// verification, and a file someone already holds open for writing is refused
// at the open with a sharing violation. A running image has the same property
// from its mapped image section. FILE_SHARE_DELETE stays, so a rename or
// delete is still allowed and stillSameFile sees it.
const verifyFileShare = windows.FILE_SHARE_READ | windows.FILE_SHARE_DELETE

// verifyPathFile runs the same Authenticode policy and signer read verifyImage
// uses. WinVerifyTrust reads the handle this function holds open; the signer
// read goes by path, so afterwards the handle's final path must still be the
// verified path (stillSameFile), as it must for a peer's image.
func verifyPathFile(path string, opts *Options) (Code, Proof, error) {
	if !localDrivePath(path) || !localDrive(path, driveType) {
		return Code{}, ProofNone, ErrNotLocalFile
	}
	long, err := longImagePath(path)
	if err != nil {
		return Code{}, ProofNone, fmt.Errorf("the file could not be named: %w", err)
	}
	pathW, err := windows.UTF16PtrFromString(long)
	if err != nil {
		return Code{}, ProofNone, ErrNotLocalFile
	}
	file, err := windows.CreateFile(pathW, windows.GENERIC_READ, verifyFileShare,
		nil, windows.OPEN_EXISTING, windows.FILE_ATTRIBUTE_NORMAL, 0)
	if err != nil {
		return Code{}, ProofNone, fmt.Errorf("the file could not be opened: %w", err)
	}
	defer windows.CloseHandle(file)
	// A junction or symbolic link can lead a local path to a network share.
	final, err := handleFinalPath(file)
	if err != nil {
		return Code{}, ProofNone, err
	}
	if !localDrivePath(final) || !localDrive(final, driveType) {
		return Code{}, ProofNone, ErrNotLocalFile
	}

	code, verdict, err := verifyHeld(file, pathW, opts.checkRevocation())
	if err != nil {
		return Code{}, ProofNone, fmt.Errorf("verification abandoned: %w", err)
	}
	if err := stillSameFile(file, long); err != nil {
		return Code{}, ProofNone, fmt.Errorf("verification abandoned: %w", err)
	}
	return code, verdict, nil
}

// localDrivePath accepts only an absolute, clean path on a lettered drive.
func localDrivePath(path string) bool {
	if len(path) < 4 || path[1] != ':' || path[2] != '\\' || strings.HasPrefix(path, `\\`) {
		return false
	}
	letter := path[0] | 0x20
	if letter < 'a' || letter > 'z' {
		return false
	}
	return filepath.IsAbs(path) && filepath.Clean(path) == path
}

// localDrive refuses a path whose drive root the system reports as remote (a
// mapped network drive) or as absent. kind is GetDriveType for a root.
func localDrive(path string, kind func(root string) uint32) bool {
	switch kind(path[:3]) {
	case windows.DRIVE_REMOTE, windows.DRIVE_NO_ROOT_DIR, windows.DRIVE_UNKNOWN:
		return false
	}
	return true
}

func driveType(root string) uint32 {
	rootW, err := windows.UTF16PtrFromString(root)
	if err != nil {
		return windows.DRIVE_UNKNOWN
	}
	return windows.GetDriveType(rootW)
}
