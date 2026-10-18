package identity

import "errors"

// ErrNotLocalFile is VerifyFile's refusal of a path it will not verify: a
// relative, unclean, UNC or device path, a mapped network drive, or a local
// path whose junction or link leads to one. Opening a network path to show a
// publisher could reach another machine.
var ErrNotLocalFile = errors.New("identity: not an absolute path on a local drive")

// VerifyFile verifies the code signature of the program file at path, as it
// is now, and reports who signed it (ID-W4). It is display and policy
// evidence about a file; a Peer's Code is the evidence about the program a
// connection is running.
//
// On Windows the path must be an absolute, clean path on a lettered drive
// that is neither remote nor absent, or VerifyFile returns ErrNotLocalFile
// without opening it; a junction or link leading off such a drive returns
// ErrNotLocalFile after the open and before verification. The file is held
// without write sharing for the verification, so a file another handle holds
// open for writing returns a sharing violation. The signer is read by path, and the file the handle names
// must still be at path afterwards, or VerifyFile returns an error. Code and Proof
// follow a peer's Authenticode rungs: a file Windows accepted is ProofBound
// with Trusted set, Subject and Issuer name an embedded signer, and Catalog
// is set when the signature came from a system catalog. Every other platform
// returns ErrUnimplemented (ID-E4).
func VerifyFile(path string, opts *Options) (Code, Proof, error) {
	return verifyPathFile(path, opts)
}
