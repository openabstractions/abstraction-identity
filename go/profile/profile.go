package profile

import "sync"

// View is how this process sees the account's profile folders. A process
// descended from an MSIX packaged app with file virtualization on sees a
// per-package copy of new files under AppData: a runtime started there, or a
// state file written there, is private to that package
// (research/packaged-activation/DECISION.md, section 3).
type View struct {
	// Virtualized reports that new files under AppData land in a package's
	// private copy.
	Virtualized bool
	// Family is that package's family name when Virtualized.
	Family string
}

// String is "real" or "virtualized(<family>)", as status reports it.
func (v View) String() string {
	if v.Virtualized {
		return "virtualized(" + v.Family + ")"
	}
	return "real"
}

var profileView struct {
	once sync.Once
	view View
	err  error
}

// Current probes this process's profile view once and returns the
// same answer afterwards. On Windows the probe creates and deletes one empty
// file under %LOCALAPPDATA%; elsewhere the view is always real. An error means
// the view is unknown, and a caller about to write state or activate a runtime
// treats it as a refusal.
func Current() (View, error) {
	profileView.once.Do(func() { profileView.view, profileView.err = probeView() })
	return profileView.view, profileView.err
}
