package identity

import (
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
)

// PackagedProgramPrefix begins the subject program of a caller with MSIX
// package identity: msix:<package family name>.
const PackagedProgramPrefix = "msix:"

// A package family name is <Name>_<PublisherId>: a 3-50 character package name
// of letters, digits, '.' and '-', and the 13-character publisher id Windows
// derives from the signing certificate.
var packageFamily = regexp.MustCompile(`^[A-Za-z0-9.-]{3,50}_[a-z0-9]{13}$`)

// PackageFamily returns the family name of an MSIX package full name,
// <Name>_<Version>_<Architecture>_<ResourceId>_<PublisherId>, where ResourceId
// may be empty.
func PackageFamily(fullName string) (string, bool) {
	parts := strings.Split(fullName, "_")
	if len(parts) != 5 {
		return "", false
	}
	family := parts[0] + "_" + parts[4]
	return family, packageFamily.MatchString(family)
}

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

// within reports whether path lies inside folder, comparing case-insensitively
// as Windows paths compare.
func within(path, folder string) bool {
	return len(path) > len(folder)+1 && strings.EqualFold(path[:len(folder)], folder) && os.IsPathSeparator(path[len(folder)])
}

// canonicalProgramPath resolves a platform-specific alternate spelling of an
// existing path to the one spelling the OS reports for it. Every platform
// starts with the identity function here; win32_windows.go replaces it with
// one that expands a Windows short DOS 8.3 name.
var canonicalProgramPath = func(path string) string { return path }

// CanonicalProgramPath resolves path to the one spelling it treats as the
// true name of the file it names: on Windows, a short DOS 8.3 name component
// expands to its long form. A short-name spelling and a long-name spelling of
// the same program compare equal under CanonicalProgramPath. A path this
// cannot resolve, including one that names no existing file, comes back
// unchanged: an exact comparison against it still refuses exactly what it
// refused before.
func CanonicalProgramPath(path string) string {
	return canonicalProgramPath(path)
}

// NormalizeSubjectProgram gives an ordinary image path the spelling used for
// caller subjects. MSIX package identities retain their stable family name.
// Validation remains the caller's responsibility; an unresolvable path keeps
// its cleaned spelling and does not prove that a file exists.
func NormalizeSubjectProgram(program string) string {
	if strings.HasPrefix(program, PackagedProgramPrefix) {
		return program
	}
	return CanonicalProgramPath(filepath.Clean(program))
}

// SameSubjectProgram compares two subject program names. Invalid or relative
// input never matches, even when both inputs have the same spelling.
func SameSubjectProgram(a, b string) bool {
	if !comparableSubjectProgram(a) || !comparableSubjectProgram(b) {
		return false
	}
	a, b = NormalizeSubjectProgram(a), NormalizeSubjectProgram(b)
	if !ValidSubjectProgram(a) || !ValidSubjectProgram(b) {
		return false
	}
	if runtime.GOOS == "windows" {
		return strings.EqualFold(a, b)
	}
	return a == b
}

func comparableSubjectProgram(program string) bool {
	if strings.HasPrefix(program, PackagedProgramPrefix) {
		return ValidSubjectProgram(program)
	}
	return len(program) > 0 && len(program) <= 4096 && filepath.IsAbs(program) && !strings.ContainsAny(program, "\x00\r\n")
}

// ValidSubjectProgram reports whether program is a subject program as
// SubjectProgram names one: msix:<package family name>, or a clean absolute
// path of at most 4096 bytes without NUL, CR or LF.
func ValidSubjectProgram(program string) bool {
	if family, ok := strings.CutPrefix(program, PackagedProgramPrefix); ok {
		return packageFamily.MatchString(family)
	}
	return len(program) > 0 && len(program) <= 4096 && filepath.IsAbs(program) && filepath.Clean(program) == program &&
		!strings.ContainsAny(program, "\x00\r\n")
}
