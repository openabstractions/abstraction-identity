//go:build !windows && !unix

package privatedir

import (
	"fmt"
	"runtime"
)

// check has no owner check on this platform.
func check(string) error {
	return fmt.Errorf("no owner check on %s", runtime.GOOS)
}
