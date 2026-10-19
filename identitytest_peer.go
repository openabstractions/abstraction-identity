//go:build oa_identitytest

package identity

import (
	"errors"
	"path/filepath"
	"sync"
	"testing"
)

// IdentityTestFacts supplies synthetic facts only to explicitly tagged tests.
// Process, Code, native bindings and ordinary production constructors stay absent.
type IdentityTestFacts struct {
	User        User
	Path        string
	Package     string
	PackageRoot string
}

var identityTestPackageMu sync.Mutex

// IdentityTestPeers exists only with oa_identitytest. Use identitytest.New in
// tagged service tests; no ordinary receiving path can construct these facts.
// Package fixtures hold the package resolver until cleanup. Overlapping package
// acquisitions, including a repeated call in one test, refuse promptly.
func IdentityTestPeers(t testing.TB, facts ...IdentityTestFacts) []*Peer {
	t.Helper()
	roots := map[string]string{}
	for _, f := range facts {
		if f.Package == "" {
			continue
		}
		if !filepath.IsAbs(f.PackageRoot) {
			t.Fatal("identitytest: absolute package root required")
		}
		if old, ok := roots[f.Package]; ok && old != f.PackageRoot {
			t.Fatal("identitytest: conflicting package roots")
		}
		roots[f.Package] = f.PackageRoot
	}
	if len(roots) != 0 {
		if !identityTestPackageMu.TryLock() {
			t.Fatal("identitytest: package resolver already in use")
			return nil
		}
		prior := packageInstallPath
		packageInstallPath = func(full string) (string, error) {
			if root, ok := roots[full]; ok {
				return root, nil
			}
			return "", errors.New("identitytest: undeclared package")
		}
		t.Cleanup(func() { packageInstallPath = prior; identityTestPackageMu.Unlock() })
	}
	peers := make([]*Peer, len(facts))
	for i, f := range facts {
		p := &Peer{Platform: "identitytest", Transport: "fixture"}
		p.User = attr("user", f.User, ProofKernel, "oa_identitytest synthetic user")
		if f.Path != "" {
			p.Path = attr("path", f.Path, ProofBound, "oa_identitytest synthetic image")
		}
		if f.Package != "" {
			p.Package = attr("package", f.Package, ProofSigned, "oa_identitytest synthetic package")
		}
		peers[i] = p
	}
	return peers
}
