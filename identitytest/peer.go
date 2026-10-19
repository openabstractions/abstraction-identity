//go:build oa_identitytest

// Package identitytest supplies explicitly synthetic User/Path/Package facts
// to tagged receiving-service tests. Ordinary builds cannot import this package.
package identitytest

import (
	identity "github.com/openabstractions/abstraction-identity"
	"testing"
)

type Facts = identity.IdentityTestFacts

func New(t testing.TB, facts ...Facts) []*identity.Peer {
	t.Helper()
	return identity.IdentityTestPeers(t, facts...)
}
