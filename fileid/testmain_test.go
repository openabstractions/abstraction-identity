package fileid

import (
	"os"
	"testing"

	"github.com/openabstractions/abstraction-identity/internal/personfolders"
)

// TestMain runs this package's tests with the person's per-user folders
// inside a temporary folder (personfolders.Main); the junction, case and WOF
// fixtures start cmd, fsutil and compact, which inherit them.
func TestMain(m *testing.M) { os.Exit(personfolders.Main(m)) }
