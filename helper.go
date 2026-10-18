package identity

import (
	"errors"
	"fmt"
)

// ErrNotHelper is a peer CheckElevatedHelper refuses.
var ErrNotHelper = errors.New("identity: peer is not this account's elevated helper")

// highIntegrityRID is the mandatory label RID of an elevated token
// (SECURITY_MANDATORY_HIGH_RID).
const highIntegrityRID = 0x3000

// CheckElevatedHelper reports whether peer is program running elevated as the
// account self names [ID-H1]: a Windows user read at kernel with self's SID,
// elevated, at high integrity or above; a process read at kernel; an image
// read at bound that SameSubjectProgram names program. It reads no file: the
// caller decides first that program is a path only administrators can change
// (ID-D2). A different account, the administrator a standard user's prompt
// asked for included, is refused, and so is every peer outside Windows.
func CheckElevatedHelper(peer *Peer, self User, program string) error {
	if peer == nil {
		return fmt.Errorf("%w: no peer", ErrNotHelper)
	}
	u, err := peer.User.AtLeast(ProofKernel)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrNotHelper, err)
	}
	if u.Kind != "windows" || self.Kind != "windows" || u.SID == "" || u.SID != self.SID {
		return fmt.Errorf("%w: another account", ErrNotHelper)
	}
	if !u.Elevated || u.IntegrityRID < highIntegrityRID {
		return fmt.Errorf("%w: the token is not elevated at high integrity", ErrNotHelper)
	}
	if _, err := peer.Process.AtLeast(ProofKernel); err != nil {
		return fmt.Errorf("%w: %w", ErrNotHelper, err)
	}
	path, err := peer.Path.AtLeast(ProofBound)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrNotHelper, err)
	}
	if !SameSubjectProgram(path, program) {
		return fmt.Errorf("%w: another program", ErrNotHelper)
	}
	return nil
}
