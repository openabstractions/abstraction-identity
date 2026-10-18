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

// within reports whether path lies inside folder, by file identity (Within).
func within(path, folder string) bool {
	ok, _ := Within(path, folder)
	return ok
}

// canonicalProgramPath resolves a platform-specific alternate spelling of an
// existing path to the one spelling the OS reports for it. Every platform
// starts with the identity function here; win32_windows.go replaces it with
// one that expands a Windows short DOS 8.3 name.
var canonicalProgramPath = func(path string) string { return path }

// SamePathName reports whether a and b are one name for a file that may not
// exist, under the rule the platform's file system compares names by: on
// Windows ordinal comparison ignoring case through the system uppercase table
// (CompareStringOrdinal with bIgnoreCase), the rule NTFS applies; elsewhere
// the bytes must be equal. Unicode case folding is looser (it folds KELVIN
// SIGN to k and LONG S to s, which NTFS keeps apart) and decides no name here.
//
// It answers a name question, never "same file": SameFile and Within answer
// that by file identity, which also sees a junction and an 8.3 alias. It has
// exactly these uses:
//   - a rights rule naming a program not yet installed, matched after
//     CanonicalProgramPath (SameSubjectProgram uses SameFile when both exist);
//   - a collision check before placement, when two names are about to become
//     files and cannot be created exclusively instead;
//   - a fixed or pinned file name, such as lemond.exe or a pin's program.
func SamePathName(a, b string) bool { return samePathName(a, b) }

// PathNameWithin reports whether the name path lies below the name folder,
// comparing folder's components with path's first components as SamePathName
// compares names, for the same uses as SamePathName: a path that may not
// exist yet. Either separator separates components, so a Windows path reads
// alike on every platform. An existing file's containment is Within's.
func PathNameWithin(path, folder string) bool {
	split := func(p string) []string {
		return strings.FieldsFunc(p, func(r rune) bool { return r == '/' || r == '\\' })
	}
	ps, fs := split(path), split(folder)
	if len(fs) == 0 || len(ps) <= len(fs) {
		return false
	}
	return SamePathName(strings.Join(ps[:len(fs)], "/"), strings.Join(fs, "/"))
}

// PathNameKey keys a set of names for files that may not exist, for the
// collision checks before placement SamePathName serves: two names have one
// key exactly when SamePathName reports them one name. A set of existing
// files keys by FileKey.
func PathNameKey(p string) string { return pathNameKey(p) }

var samePathName = func(a, b string) bool { return a == b }

var pathNameKey = func(p string) string { return p }

// shortNameComponent matches a path component spelled like a Windows short
// (8.3) alias: one to six characters, a tilde and digits, and an optional
// extension of one to three characters, such as PROGRA~1 or SUBJEC~2.EXE.
var shortNameComponent = regexp.MustCompile(`^[^~.\\/]{1,6}~[0-9]{1,6}(\.[^.\\/]{1,3})?$`)

func pathComponents(path string) []string {
	return strings.FieldsFunc(path[len(filepath.VolumeName(path)):], func(r rune) bool { return r == '/' || r == os.PathSeparator })
}

// HasShortNameComponent reports, from the spelling alone, whether a component
// of path is shaped like a Windows short (8.3) alias. It reads no filesystem.
// A long name can have that shape too, so true means only that the spelling
// may read differently once resolved.
func HasShortNameComponent(path string) bool {
	if strings.HasPrefix(path, PackagedProgramPrefix) {
		return false
	}
	for _, part := range pathComponents(path) {
		if shortNameComponent.MatchString(part) {
			return true
		}
	}
	return false
}

// UnresolvedShortName reports whether the canonical spelling of path still
// holds a component shaped like a short (8.3) alias that names no existing
// file or folder. A store refuses to write such a spelling: once a file
// appears there, its canonical spelling differs, and a rule stored under the
// alias would match nothing. Always false off Windows and for a package
// family.
func UnresolvedShortName(path string) bool {
	if runtime.GOOS != "windows" || strings.HasPrefix(path, PackagedProgramPrefix) || !filepath.IsAbs(path) {
		return false
	}
	canonical := CanonicalProgramPath(filepath.Clean(path))
	if !HasShortNameComponent(canonical) {
		return false
	}
	if LocalPath(canonical) != nil {
		// A short-shaped name on a share is never resolved: identity opens
		// nothing there.
		return true
	}
	prefix := filepath.VolumeName(canonical) + string(os.PathSeparator)
	for _, part := range pathComponents(canonical) {
		prefix = filepath.Join(prefix, part)
		if shortNameComponent.MatchString(part) {
			observeOpen(prefix)
			if _, err := os.Lstat(prefix); err != nil {
				return true
			}
		}
	}
	return false
}

// CanonicalProgramPath resolves path to the one spelling it treats as the
// true name of the file it names: on Windows, a short DOS 8.3 name component
// expands to its long form. A short-name spelling and a long-name spelling of
// the same program compare equal under CanonicalProgramPath. A path this
// cannot resolve, including one that names no existing file and one LocalPath
// refuses, which is never read, comes back unchanged: an exact comparison
// against it still refuses exactly what it refused before.
func CanonicalProgramPath(path string) string {
	return canonicalProgramPath(path)
}

// NormalizeSubjectProgram gives an ordinary image path the spelling used for
// caller subjects. MSIX package identities retain their stable family name.
// Validation remains the caller's responsibility; an unresolvable path keeps
// its cleaned spelling and does not prove that a file exists. It resolves the
// path against the filesystem: a store normalizes a subject once, when it
// writes it, and checks a stored subject on read with ValidSubjectProgram,
// which reads no filesystem.
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
	return SameNormalizedSubjectProgram(NormalizeSubjectProgram(a), NormalizeSubjectProgram(b))
}

// SameNormalizedSubjectProgram compares two subject programs that are already
// in the spelling NormalizeSubjectProgram gives. Byte-equal names are one
// program, and a package family is a name and compares only by SamePathName.
// When both programs exist on a local drive, file identity decides
// (ProgramKey): a junction and its target, and an 8.3 alias and its long
// name, are one program, and two files whose names differ only in case, as
// a case-sensitive folder holds them, are two. When either does not exist,
// or LocalPath refuses it, such as a program run from a share, the names
// decide (SamePathName), and nothing is opened for a refused one. Invalid
// input never matches.
func SameNormalizedSubjectProgram(a, b string) bool {
	return SameNormalizedSubjectProgramKeyed(a, b, func() string { return ProgramKey(a) }, func() string { return ProgramKey(b) })
}

// SameNormalizedSubjectProgramKeyed is SameNormalizedSubjectProgram with each
// side's ProgramKey supplied by the caller, so a caller comparing one program
// with many reads each file identity once. keyA and keyB are called only when
// the names are not byte-equal.
func SameNormalizedSubjectProgramKeyed(a, b string, keyA, keyB func() string) bool {
	if !ValidSubjectProgram(a) || !ValidSubjectProgram(b) {
		return false
	}
	if a == b {
		return true
	}
	if strings.HasPrefix(a, PackagedProgramPrefix) || strings.HasPrefix(b, PackagedProgramPrefix) {
		return SamePathName(a, b)
	}
	ka := keyA()
	if ka == "" {
		return SamePathName(a, b)
	}
	kb := keyB()
	if kb == "" {
		return SamePathName(a, b)
	}
	return ka == kb
}

// ProgramKey is the file identity a subject program compares by: FileKey of
// a path program that exists on a local drive, and "" for a package family,
// a program that does not exist and one LocalPath refuses, which compare by
// name alone.
func ProgramKey(program string) string {
	if strings.HasPrefix(program, PackagedProgramPrefix) {
		return ""
	}
	key, err := FileKey(program)
	if err != nil {
		return ""
	}
	return key
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
