package hostfixture_test

import (
	"bytes"
	"debug/macho"
	"debug/pe"
	"os"
	"runtime"
	"testing"

	"github.com/openabstractions/abstraction-identity/hostfixture"
)

// The probe the classifier's rows rest on: each fixture is built from the
// test-built executable (or, for Mach-O, from bytes) without any Electron,
// Bun, Node or Python installation, and carries the marker the classifier
// reads in the place a real program carries it.
func TestFixturesCarryTheirMarkers(t *testing.T) {
	dir := t.TempDir()
	plain := hostfixture.Plain(t, dir, "plain.exe")
	electron := hostfixture.Electron(t, dir, "electron.exe", true)
	bun := hostfixture.Bun(t, dir, "opencode.exe", true)
	for _, path := range []string{plain, electron, bun} {
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if runtime.GOOS == "windows" {
			f, err := pe.NewFile(bytes.NewReader(data))
			if err != nil {
				t.Fatalf("%s no longer parses as PE: %v", path, err)
			}
			if path == bun && (f.Section(".bun") == nil || f.Section(".bunrt") == nil) {
				t.Fatalf("the Bun fixture has no .bun or runtime section")
			}
		}
	}
	image, err := os.ReadFile(hostfixture.MachO(t, dir, "image", true, "com.apple.security.cs.disable-library-validation"))
	if err != nil {
		t.Fatal(err)
	}
	m, err := macho.NewFile(bytes.NewReader(image))
	if err != nil {
		t.Fatalf("the Mach-O fixture does not parse: %v", err)
	}
	if m.Segment("__BUN") == nil {
		t.Fatal("the Mach-O fixture has no __BUN segment")
	}
}
