package identity

import "strings"

// Sandbox is the sandbox a Linux peer runs in, in the shape Wayland's
// security-context-v1 names: the engine, the application id it gives, and
// the instance where it names one (identity corpus N2). Package carries the
// same Linux answer as "<engine>:<app id>" until it keeps its MSIX meaning
// alone (CONTRACT.md, Linux, and Not built).
type Sandbox struct {
	// Engine is "flatpak", "snap" or "firejail".
	Engine string
	// AppID is the application the engine names: Flatpak's
	// [Application] name, Snap's "<snap>.<app>"; empty for Firejail, which
	// names none.
	AppID string
	// Instance is a Snap instance key ("<snap>_<key>"); empty otherwise.
	// Flatpak's own instance id is not read.
	Instance string
}

// sandboxOf reads the Sandbox a Linux package answer names: "flatpak:<app>",
// "snap:<snap>.<app>" or "firejail:". ok is false for any other answer.
func sandboxOf(pkg string) (Sandbox, bool) {
	engine, app, found := strings.Cut(pkg, ":")
	switch {
	case !found:
		return Sandbox{}, false
	case engine == "flatpak", engine == "firejail":
		return Sandbox{Engine: engine, AppID: app}, true
	case engine == "snap":
		s := Sandbox{Engine: engine, AppID: app}
		if name, _, ok := strings.Cut(app, "."); ok {
			if _, key, ok := strings.Cut(name, "_"); ok {
				s.Instance = key
			}
		}
		return s, true
	}
	return Sandbox{}, false
}
