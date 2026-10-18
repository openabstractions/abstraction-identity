//go:build !windows

package identity

// observeOpen has no observer off Windows.
func observeOpen(string) {}

// TreatDriveAsNetwork is for tests: off Windows there are no drive letters,
// and it marks nothing.
func TreatDriveAsNetwork(letter byte) (restore func()) { return func() {} }

// ObserveOpens is for tests: off Windows observe is never told of an open.
// On macOS and Linux a refused path is decided by statfs, which opens
// nothing; Linux reads /proc/self/mountinfo for a FUSE mount's type.
func ObserveOpens(observe func(path string)) (stop func(), ok bool) { return func() {}, true }

// trimCreatedNames keeps the spelling: only Windows strips trailing dots and
// spaces from a name it creates.
func trimCreatedNames(path string) string { return path }
