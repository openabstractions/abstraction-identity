//go:build darwin || linux

package privatedir

import (
	"os"
	"path/filepath"
	"testing"

	identity "github.com/openabstractions/abstraction-identity"
)

// refusedFolder is an existing folder identity.LocalPath refuses as a
// network volume (TreatVolumeAsNetwork stands in for a mounted share).
func refusedFolder(t *testing.T) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "share", "OA-models")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(identity.TreatVolumeAsNetwork(filepath.Dir(dir)))
	return dir
}
