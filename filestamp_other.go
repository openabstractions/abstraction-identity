//go:build !unix && !windows

package identity

import (
	"errors"
	"os"
)

// readStampInputs has no file identity to read on this platform, so no
// fact about a program file is read or cached.
func readStampInputs(f *os.File, _ os.FileInfo) (stampInputs, error) {
	return stampInputs{}, errors.New("identity: no file identity on this platform for " + f.Name())
}
