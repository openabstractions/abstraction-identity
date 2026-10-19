//go:build windows

package identity

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/windows"
)

// verifyFileShare is the share mode VerifyFile holds its file with. It omits
// FILE_SHARE_WRITE: no one can open the file for writing during the
// verification, and a file someone already holds open for writing is refused
// at the open with a sharing violation. A running image has the same property
// from its mapped image section. VerifyFile's own handle keeps
// FILE_SHARE_DELETE, and stillSameFile sees a rename or delete. The private
// interpreter reader uses the same share mode and verifies its original
// handle across a rename.
const verifyFileShare = windows.FILE_SHARE_READ | windows.FILE_SHARE_DELETE

// openSignatureFile permits an updater's rename while excluding writers.
// openStampedWith owns local path, regular file and stamp admission.
func openSignatureFile(path string) (*os.File, error) {
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, err
	}
	h, err := windows.CreateFile(p, windows.GENERIC_READ, verifyFileShare,
		nil, windows.OPEN_EXISTING, windows.FILE_ATTRIBUTE_NORMAL, 0)
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(h), path), nil
}

// verifyOpenFile verifies the signature opener's actual held regular file.
// path is its already-observed final name, a native policy hint. The file may
// move during verification; all signature/resource facts come from its handle
// and the accepted native trust state. The exported path API retains its own
// final same-file check.
func verifyOpenFile(f *os.File, path string, opts *Options) (Code, Proof, error) {
	if !localDrivePath(path) || !localDrive(path, driveType) {
		return Code{}, ProofNone, ErrNotLocalFile
	}
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return Code{}, ProofNone, ErrNotLocalFile
	}
	return verifyHeld(windows.Handle(f.Fd()), p, opts.checkRevocation())
}

// verifyPathFile runs the same Authenticode policy and signer read verifyImage
// uses. WinVerifyTrust reads the handle this function holds open and its
// accepted provider state supplies the signer. This path API also requires
// its original path to keep naming the held file (stillSameFile).
func verifyPathFile(path string, opts *Options) (Code, Proof, error) {
	return verifyPathFileCaptured(path, opts, nil)
}

func verifyPathFileCaptured(path string, opts *Options, publisherKey *string) (Code, Proof, error) {
	if publisherKey != nil {
		*publisherKey = ""
	}
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

	code, verdict, err := verifyHeldCaptured(file, pathW, opts.checkRevocation(), publisherKey)
	if err != nil {
		if publisherKey != nil {
			*publisherKey = ""
		}
		return Code{}, ProofNone, fmt.Errorf("verification abandoned: %w", err)
	}
	if err := stillSameFile(file, long); err != nil {
		if publisherKey != nil {
			*publisherKey = ""
		}
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
