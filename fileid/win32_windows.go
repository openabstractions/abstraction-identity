//go:build windows

package fileid

// Win32 entry points the path functions need that golang.org/x/sys/windows
// does not already wrap, and the Windows spelling rules they apply.

import (
	"fmt"
	"path/filepath"
	"strings"

	"golang.org/x/sys/windows"
)

var modkernel32 = windows.NewLazySystemDLL("kernel32.dll")

const (
	// GetFinalPathNameByHandle flags: the normalized DOS-drive form, which
	// is what QueryFullProcessImageName also returns, so the two are
	// comparable.
	fileNameNormalized = 0x0
	volumeNameDOS      = 0x0
)

// handleFinalPath is the normalized DOS path the kernel reports for an open
// handle, after junctions and symbolic links, without its \\?\ prefix. A file
// on a network share reads UNC\server\share\... in this form.
func handleFinalPath(file windows.Handle) (string, error) {
	buf := make([]uint16, windows.MAX_LONG_PATH)
	n, err := windows.GetFinalPathNameByHandle(file, &buf[0], uint32(len(buf)), fileNameNormalized|volumeNameDOS)
	if err != nil {
		return "", fmt.Errorf("the verified file could no longer be named: %w", err)
	}
	if n == 0 || n >= uint32(len(buf)) {
		return "", fmt.Errorf("the verified file path exceeds the buffer")
	}
	return strings.TrimPrefix(windows.UTF16ToString(buf[:n]), `\\?\`), nil
}

// longImagePath expands short DOS components of an existing path. Failure
// refuses rather than guessing.
func longImagePath(path string) (string, error) {
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return "", err
	}
	buf := make([]uint16, windows.MAX_LONG_PATH)
	n, err := windows.GetLongPathName(p, &buf[0], uint32(len(buf)))
	if err != nil {
		return "", err
	}
	if n == 0 || n >= uint32(len(buf)) {
		return "", fmt.Errorf("image path exceeds the buffer")
	}
	return strings.TrimPrefix(windows.UTF16ToString(buf[:n]), `\\?\`), nil
}

func init() {
	// A short DOS 8.3 name component and its long-form spelling name the
	// same file. This concept exists only on Windows; this is the one
	// platform where canonicalProgramPath does more than return its argument.
	canonicalProgramPath = func(path string) string {
		if !HasShortNameComponent(path) || localPath(path) != nil {
			// A path with no component shaped like a short alias has none
			// to expand, and a program on a share or a device name is never
			// read here.
			return path
		}
		observeOpen(path)
		if long, err := longImagePath(path); err == nil {
			return long
		}
		// A file that does not exist yet keeps its own spelling, below the
		// deepest folder that exists, which reads in its long form: a short
		// alias in an existing part of the path never survives into a stored
		// spelling (UnresolvedShortName covers the part that does not exist).
		dir, rest := filepath.Dir(path), filepath.Base(path)
		for dir != filepath.Dir(dir) {
			if long, err := longImagePath(dir); err == nil {
				return filepath.Join(long, rest)
			}
			rest = filepath.Join(filepath.Base(dir), rest)
			dir = filepath.Dir(dir)
		}
		return path
	}
}
