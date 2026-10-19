package identity

import (
	"os"

	"github.com/openabstractions/abstraction-identity/fileid"
)

// FileKeyOf is fileid.FileKeyOf.
func FileKeyOf(f *os.File) (string, error) { return fileid.FileKeyOf(f) }
