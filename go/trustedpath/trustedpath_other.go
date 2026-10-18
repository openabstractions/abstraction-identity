//go:build !windows

package trustedpath

import (
	"fmt"
	"runtime"
)

// CheckFile has no owner and access rule outside Windows yet; every path is
// refused.
func CheckFile(path string, owners Owners) error {
	return fmt.Errorf("%w: %s: no owner and access check on %s", ErrUntrusted, path, runtime.GOOS)
}

// CheckExecutable refuses every path outside Windows too.
func CheckExecutable(path string, owners Owners) error { return CheckFile(path, owners) }
