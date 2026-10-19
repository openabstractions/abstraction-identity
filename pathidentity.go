package identity

import "github.com/openabstractions/abstraction-identity/fileid"

// File identity has one owner, the fileid package (ID-F1; PLAN 0.8.0 T12).
// The path functions identity exported before it are kept here, each one a
// wrapper that answers exactly what fileid's function of the same name
// answers, until their consumers move to fileid (PT-3b). New code calls
// fileid: Resolve and Open for an existing file, Pending for a name that may
// not exist yet, and the leaf and stored-key forms for locks and stores.

// ErrNotLocalPath is fileid.ErrNotLocalPath.
var ErrNotLocalPath = fileid.ErrNotLocalPath

// NotLocalPathError is fileid.NotLocalPathError.
type NotLocalPathError = fileid.NotLocalPathError

// PackagedProgramPrefix is fileid.PackagedProgramPrefix.
const PackagedProgramPrefix = fileid.PackagedProgramPrefix

// LocalPath is fileid.LocalPath.
func LocalPath(path string) error { return fileid.LocalPath(path) }

// SameFile is fileid.SameFile.
func SameFile(a, b string) (bool, error) { return fileid.SameFile(a, b) }

// Within is fileid.Within.
func Within(path, folder string) (bool, error) { return fileid.Within(path, folder) }

// WithinRel is fileid.WithinRel.
func WithinRel(path, folder string) (string, bool, error) { return fileid.WithinRel(path, folder) }

// Inside is fileid.Inside.
func Inside(path, folder string) bool { return fileid.Inside(path, folder) }

// InsideRel is fileid.InsideRel.
func InsideRel(path, folder string) (string, bool, error) { return fileid.InsideRel(path, folder) }

// FileKey is fileid.FileKey.
func FileKey(path string) (string, error) { return fileid.FileKey(path) }

// PlaceKey is fileid.PlaceKey.
func PlaceKey(path string) (string, error) { return fileid.PlaceKey(path) }

// PackageFamily is fileid.PackageFamily.
func PackageFamily(fullName string) (string, bool) { return fileid.PackageFamily(fullName) }

// SamePathName is fileid.SamePathName.
func SamePathName(a, b string) bool { return fileid.SamePathName(a, b) }

// PathNameWithin is fileid.PathNameWithin.
func PathNameWithin(path, folder string) bool { return fileid.PathNameWithin(path, folder) }

// PathNameKey is fileid.PathNameKey.
func PathNameKey(p string) string { return fileid.PathNameKey(p) }

// HasShortNameComponent is fileid.HasShortNameComponent.
func HasShortNameComponent(path string) bool { return fileid.HasShortNameComponent(path) }

// UnresolvedShortName is fileid.UnresolvedShortName.
func UnresolvedShortName(path string) bool { return fileid.UnresolvedShortName(path) }

// CanonicalProgramPath is fileid.CanonicalProgramPath.
func CanonicalProgramPath(path string) string { return fileid.CanonicalProgramPath(path) }

// NormalizeSubjectProgram is fileid.NormalizeSubjectProgram.
func NormalizeSubjectProgram(program string) string { return fileid.NormalizeSubjectProgram(program) }

// SameSubjectProgram is fileid.SameSubjectProgram.
func SameSubjectProgram(a, b string) bool { return fileid.SameSubjectProgram(a, b) }

// SameNormalizedSubjectProgram is fileid.SameNormalizedSubjectProgram.
func SameNormalizedSubjectProgram(a, b string) bool { return fileid.SameNormalizedSubjectProgram(a, b) }

// SameNormalizedSubjectProgramKeyed is fileid.SameNormalizedSubjectProgramKeyed.
func SameNormalizedSubjectProgramKeyed(a, b string, keyA, keyB func() string) bool {
	return fileid.SameNormalizedSubjectProgramKeyed(a, b, keyA, keyB)
}

// ProgramKey is fileid.ProgramKey.
func ProgramKey(program string) string { return fileid.ProgramKey(program) }

// ValidSubjectProgram is fileid.ValidSubjectProgram.
func ValidSubjectProgram(program string) bool { return fileid.ValidSubjectProgram(program) }

// ObserveOpens is fileid.ObserveOpens.
func ObserveOpens(observe func(path string)) (stop func(), ok bool) {
	return fileid.ObserveOpens(observe)
}

// TreatDriveAsNetwork is fileid.TreatDriveAsNetwork.
func TreatDriveAsNetwork(letter byte) (restore func()) { return fileid.TreatDriveAsNetwork(letter) }
