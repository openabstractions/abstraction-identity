//go:build !windows

package identity

import "os"

var openSignatureFile = os.Open

func verifyOpenFile(*os.File, string, *Options) (Code, Proof, error) {
	return Code{}, ProofNone, ErrUnimplemented
}

func verifyPathFile(string, *Options) (Code, Proof, error) {
	return Code{}, ProofNone, ErrUnimplemented
}

func verifyPathFileCaptured(string, *Options, *string) (Code, Proof, error) {
	return Code{}, ProofNone, ErrUnimplemented
}
