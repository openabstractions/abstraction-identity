//go:build !windows && !unix

package privatedir

import (
	"fmt"
	"runtime"

	"github.com/openabstractions/abstraction-identity/fileid"
)

// protectModels has no owner rule on this platform.
func protectModelsAt(fileid.Handle, []fileid.Handle) error {
	return fmt.Errorf("no owner rule on %s", runtime.GOOS)
}

func modelKnownFolders() []string { return []string{""} }

// checkModels has no owner check on this platform.
func checkModelsAt(fileid.Handle) error {
	return fmt.Errorf("no owner check on %s", runtime.GOOS)
}
