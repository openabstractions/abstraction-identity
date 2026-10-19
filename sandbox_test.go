package identity

import "testing"

// N2: a Linux package answer reads as the sandbox engine, the application id
// and, for a Snap instance key, the instance.
func TestSandboxOfReadsEngineAppAndInstance(t *testing.T) {
	cases := []struct {
		pkg  string
		want Sandbox
		ok   bool
	}{
		{"flatpak:org.gnome.Calculator", Sandbox{Engine: "flatpak", AppID: "org.gnome.Calculator"}, true},
		{"flatpak:", Sandbox{Engine: "flatpak"}, true},
		{"snap:chromium.chromium", Sandbox{Engine: "snap", AppID: "chromium.chromium"}, true},
		{"snap:firefox_beta.firefox", Sandbox{Engine: "snap", AppID: "firefox_beta.firefox", Instance: "beta"}, true},
		{"firejail:", Sandbox{Engine: "firejail"}, true},
		{"Contoso.Notes_1.0.0.0_x64__8wekyb3d8bbwe", Sandbox{}, false},
		{"msix:Contoso.Notes_8wekyb3d8bbwe", Sandbox{}, false},
		{"", Sandbox{}, false},
	}
	for _, c := range cases {
		got, ok := sandboxOf(c.pkg)
		if got != c.want || ok != c.ok {
			t.Errorf("sandboxOf(%q) = %+v, %v; want %+v, %v", c.pkg, got, ok, c.want, c.ok)
		}
	}
}
