//go:build windows

package identity

import (
	"os"

	"golang.org/x/sys/windows"
)

// heldFilePath is the path a check by path reads to reach the file f holds:
// the kernel's final path of f's handle (handleFinalPath), after junctions,
// symbolic links and 8.3 aliases, which names no link. The opener decides
// whether rename is allowed. Signature verification uses this name as a
// native policy hint and reads evidence from the held file and trust state.
// ok is false when the handle cannot be named.
func heldFilePath(f *os.File, _ string) (path string, ok bool) {
	final, err := handleFinalPath(windows.Handle(f.Fd()))
	if err != nil {
		return "", false
	}
	return final, true
}
