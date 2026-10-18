//go:build !windows

package identity

func verifyPathFile(string, *Options) (Code, Proof, error) {
	return Code{}, ProofNone, ErrUnimplemented
}
