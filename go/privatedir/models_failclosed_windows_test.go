//go:build windows

package privatedir

import "testing"

// refusedFolder is a folder identity.LocalPath refuses: a UNC share, which is
// never opened.
func refusedFolder(t *testing.T) string {
	t.Helper()
	return `\\oa-test-host.invalid\share\OA-models`
}
