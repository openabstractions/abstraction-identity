//go:build windows

package identity

import (
	"errors"
	"path/filepath"
	"testing"
)

// [ID-F1] InsideRel returns ErrNotLocalPath for a refused path, even one
// spelled below a folder that does not exist.
func TestInsideRelRefusedPathReturnsItsError(t *testing.T) {
	restore := TreatDriveAsNetwork('Y')
	defer restore()
	local := t.TempDir()
	for _, c := range [][2]string{
		{`Y:\root\a`, `Y:\root`},
		{`Y:\x`, local},
		{filepath.Join(local, "a"), `Y:\root`},
	} {
		if _, in, err := InsideRel(c[0], c[1]); in || !errors.Is(err, ErrNotLocalPath) {
			t.Errorf("InsideRel(%q, %q) = %v, %v; want false, ErrNotLocalPath", c[0], c[1], in, err)
		}
	}
}
