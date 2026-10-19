//go:build !windows

package fileid

// TreatDriveAsNetwork is for tests: off Windows there are no drive letters,
// and it marks nothing.
func TreatDriveAsNetwork(letter byte) (restore func()) { return func() {} }

// streamSpelling is false off Windows: a colon is a byte of a name, and a
// macOS resource fork is the walk's ..namedfork refusal.
func streamSpelling(string) bool { return false }

// trimCreatedNames keeps the spelling: only Windows strips trailing dots and
// spaces from a name it creates.
func trimCreatedNames(path string) string { return path }
