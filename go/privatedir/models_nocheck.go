//go:build !windows && !unix

package privatedir

import (
	"fmt"
	"runtime"
)

// protectModels has no owner rule on this platform.
func protectModels(string, []string) error {
	return fmt.Errorf("no owner rule on %s", runtime.GOOS)
}

// checkModels has no owner check on this platform.
func checkModels(string) error {
	return fmt.Errorf("no owner check on %s", runtime.GOOS)
}

// checkRoot has no root rule on this platform.
func checkRoot(string) error {
	return fmt.Errorf("no models root rule on %s", runtime.GOOS)
}
