// Package trustedpath decides whether a file may be read as content only
// trusted principals can have written (identity CONTRACT.md ID-D2): the
// file and every folder above it up to the volume root are owned by a
// trusted principal, no other principal can write, append to, change the
// attributes or access of, or delete the file, or delete, rename or change
// the access of any folder on its path, and no reparse point (link,
// junction or mount point) stands on the path. It reads security
// descriptors and attributes only, never content.
//
// Callers: the storage reader's pinned ASUS files (storage-over-local-stores
// LS-12) and the video provider's in-place model files.
package trustedpath

import "errors"

// ErrUntrusted reports a path CheckFile refuses.
var ErrUntrusted = errors.New("trustedpath: path is not trusted")

// Owners names the principals trusted to own and change a path.
type Owners struct {
	// SIDs are the trusted principals' security identifiers in string form
	// (S-1-5-18). MachineOwners fills them.
	SIDs []string
	// Account trusts the account of the calling process as well: a folder
	// OA keeps for itself.
	Account bool
}

// SIDs of the principals Windows services and installers run as.
const (
	system           = "S-1-5-18"
	administrators   = "S-1-5-32-544"
	trustedInstaller = "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464"
)

// MachineOwners trusts SYSTEM, Administrators and TrustedInstaller: the owners of
// files a machine-wide installer or service writes. Set Account on the
// result to trust the calling account as well.
func MachineOwners() Owners {
	return Owners{SIDs: []string{system, administrators, trustedInstaller}}
}
