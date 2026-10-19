package identity

import (
	"errors"
	"path/filepath"
)

// packageInstallPath is the folder an installed package's files live in;
// tests replace it.
var packageInstallPath = packagePathByFullName

// SubjectProgram names the program a service's rights, credentials and
// inference decisions are about. A Windows caller whose package identity is
// proven at ProofSigned, and whose image lies inside that package's installed
// folder, is msix:<package family name>: the image path of a packaged app
// changes with every package version, and the family does not. The folder check
// is needed because any process of the account can start an arbitrary program
// with an installed package's identity (Invoke-CommandInDesktopPackage), while
// it cannot write into the package's folder under WindowsApps. Every other
// caller, including a descendant of a packaged app, which has no identity of its
// own, is its clean absolute image path at pathProof or better, canonicalized:
// a peer launched through a short DOS 8.3 alias names the same subject as one
// launched through the long spelling of the same file (CanonicalProgramPath).
func SubjectProgram(p *Peer, pathProof Proof) (string, error) {
	if p == nil {
		return "", errors.New("identity: no peer")
	}
	path, err := p.Path.AtLeast(pathProof)
	if err != nil {
		return "", err
	}
	if !filepath.IsAbs(path) {
		return "", errors.New("identity: the program path is not absolute")
	}
	path = filepath.Clean(path)
	if full, err := p.Package.AtLeast(ProofSigned); err == nil {
		if family, ok := PackageFamily(full); ok {
			if root, err := packageInstallPath(full); err == nil && within(path, filepath.Clean(root)) {
				return PackagedProgramPrefix + family, nil
			}
		}
	}
	return CanonicalProgramPath(path), nil
}

// within reports whether path lies inside folder, by file identity (Within).
func within(path, folder string) bool {
	ok, _ := Within(path, folder)
	return ok
}
