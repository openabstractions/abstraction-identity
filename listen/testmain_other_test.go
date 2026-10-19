//go:build !windows

package listen

import (
	"os"
	"testing"

	"github.com/openabstractions/abstraction-identity/internal/personfolders"
)

// TestMain runs this package's tests with the person's per-user folders
// inside a temporary folder (personfolders.Main); on Windows the TestMain
// of listen_attack_windows_test.go does.
func TestMain(m *testing.M) { os.Exit(personfolders.Main(m)) }
