//go:build darwin && !cgo

package identity

// A macOS build with CGO_ENABLED=0 cannot reach the Security framework, and
// therefore cannot verify a code signature at all. That is a property of the
// build, not of the machine it runs on, so it belongs in Ceiling(): a service
// built this way will be told at startup that its policy is unenforceable here,
// rather than discovering per connection that Code is empty.
//
// The uid, the pid and the path are unaffected. Everything in identity_darwin.go
// still works; what is missing is the one thing macOS does better than the other
// two platforms.

import "errors"

const whyNoCgo = "this binary was built with CGO_ENABLED=0, and verifying a code signature needs the Security framework; rebuild with cgo enabled to get a code identity on macOS at all"

var errNoCgo = errors.New("identity: " + whyNoCgo)

func codeCeiling() (Proof, string) { return ProofNone, whyNoCgo }

func verifyAuditToken(token auditToken, opts *Options) (Code, string, string, error) {
	return Code{Status: whyNoCgo}, "", "", errNoCgo
}
