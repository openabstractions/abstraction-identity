package identity_test

import (
	"bytes"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	identity "github.com/openabstractions/abstraction-identity"
	"github.com/openabstractions/abstraction-identity/hostfixture"
)

// beBun is the variable's name, assembled here so this test executable does
// not carry it and its copies stay unmarked.
func beBun() string { return strings.ReplaceAll("BUN_BE_B#N", "#", "U") }

func classify(program string, code identity.Code) identity.Code {
	return identity.ClassifyProgram(program, code)
}

func requireFacts(t *testing.T, name string, got identity.Code, shared, foreign bool, evidence string) {
	t.Helper()
	if got.SharedInterpreter != shared || got.RunsForeignCode != foreign || got.ForeignCode != evidence {
		t.Errorf("%s: SharedInterpreter %t RunsForeignCode %t ForeignCode %q, want %t %t %q",
			name, got.SharedInterpreter, got.RunsForeignCode, got.ForeignCode, shared, foreign, evidence)
	}
}

func writeFile(t *testing.T, path, content string) string {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o755); err != nil {
		t.Fatal(err)
	}
	return path
}

// ID-I1, TD83: the shared-interpreter name table, by file name, by trusted
// signed OriginalName and by package family. A shared interpreter also runs
// foreign code; untrusted evidence names nothing.
func TestClassifyProgramSharedInterpreters(t *testing.T) {
	dir := t.TempDir()
	for _, name := range []string{"python.exe", "dotnet.exe", "java.exe", "deno.exe", "node.exe", "InstallUtil.exe", "python3.12"} {
		program := writeFile(t, filepath.Join(dir, name), "an interpreter by name")
		requireFacts(t, name, classify(program, identity.Code{}), true, true, identity.ForeignCodeSharedInterpreter)
	}
	renamed := writeFile(t, filepath.Join(dir, "renamed.exe"), "a renamed host")
	requireFacts(t, "trusted evidence dotnet.exe", classify(renamed, identity.Code{Trusted: true, OriginalName: "DOTNET.EXE"}), true, true, identity.ForeignCodeSharedInterpreter)
	requireFacts(t, "untrusted evidence", classify(renamed, identity.Code{OriginalName: "dotnet.exe"}), false, false, "")
	requireFacts(t, "msix Python", classify("msix:PythonSoftwareFoundation.Python.3.12_qbz5n2kfra8p0", identity.Code{}), true, true, identity.ForeignCodeSharedInterpreter)
	requireFacts(t, "msix Calculator", classify("msix:Microsoft.WindowsCalculator_8wekyb3d8bbwe", identity.Code{}), false, false, "")
	app := writeFile(t, filepath.Join(dir, "editor.exe"), "an app")
	requireFacts(t, "an app", classify(app, identity.Code{}), false, false, "")
	if identity.SharedInterpreterProgram(app, identity.Code{}) || !identity.SharedInterpreterProgram(filepath.Join(dir, "python.exe"), identity.Code{}) {
		t.Error("SharedInterpreterProgram disagrees with ClassifyProgram")
	}
}

// ID-I1: a venv python.exe that is the same file as its pyvenv.cfg home's
// interpreter is that shared interpreter, under any name; a copy beside its
// own pyvenv.cfg is the application's own interpreter, which runs foreign
// code and is no shared interpreter.
func TestClassifyProgramVenvHome(t *testing.T) {
	dir := t.TempDir()
	home := filepath.Join(dir, "Python312")
	shared := writeFile(t, filepath.Join(home, "python.exe"), "the shared interpreter")
	venv := filepath.Join(dir, "app", "venv")
	writeFile(t, filepath.Join(venv, "pyvenv.cfg"), "Home = "+home+"\nversion = 3.12.4\n")
	scripts := filepath.Join(venv, "Scripts")
	if err := os.MkdirAll(scripts, 0o755); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(scripts, "python.exe")
	if err := os.Link(shared, link); err != nil {
		t.Skipf("no hard links here: %v", err)
	}
	requireFacts(t, "a hard-linked venv python.exe", classify(link, identity.Code{}), true, true, identity.ForeignCodeSharedInterpreter)
	renamedLink := filepath.Join(scripts, "comfyui.exe")
	if err := os.Link(shared, renamedLink); err != nil {
		t.Fatal(err)
	}
	requireFacts(t, "a renamed hard link", classify(renamedLink, identity.Code{}), true, true, identity.ForeignCodeSharedInterpreter)

	own := filepath.Join(dir, "own", "host")
	ownPython := writeFile(t, filepath.Join(own, "python.exe"), "a copy with its own bytes")
	writeFile(t, filepath.Join(own, "pyvenv.cfg"), "home = "+home+"\n")
	requireFacts(t, "an application's own interpreter copy", classify(ownPython, identity.Code{}), false, true, identity.ForeignCodeAppInterpreter)
	signedCopy := writeFile(t, filepath.Join(own, "comfyui.exe"), "a copy under the application's name")
	requireFacts(t, "a host-kit copy named for its app", classify(signedCopy, identity.Code{Trusted: true, OriginalName: "python.exe"}), false, true, identity.ForeignCodeAppInterpreter)

	missing := filepath.Join(dir, "gone")
	writeFile(t, filepath.Join(dir, "stray", "pyvenv.cfg"), "home = "+missing+"\n")
	stray := writeFile(t, filepath.Join(dir, "stray", "python.exe"), "a copy whose home is gone")
	requireFacts(t, "a copy whose home is missing reads by its name", classify(stray, identity.Code{}), true, true, identity.ForeignCodeSharedInterpreter)
}

// ID-I1, security-5: an Electron program with RunAsNode on and a Bun
// standalone executable whose runtime honours BUN_BE_BUN run foreign code and
// are no shared interpreters; the same images without the marker carry
// nothing. Each fixture is the test-built executable with the marker added.
func TestClassifyProgramImageMarkers(t *testing.T) {
	dir := t.TempDir()
	requireFacts(t, "a plain program", classify(hostfixture.Plain(t, dir, "plain.exe"), identity.Code{}), false, false, "")
	requireFacts(t, "Electron with RunAsNode on", classify(hostfixture.Electron(t, dir, "Code.exe", true), identity.Code{}), false, true, identity.ForeignCodeElectronRunAsNode)
	requireFacts(t, "Electron with RunAsNode off", classify(hostfixture.Electron(t, dir, "Signal.exe", false), identity.Code{}), false, false, "")
	requireFacts(t, "Bun standalone, an old runtime", classify(hostfixture.Bun(t, dir, "old-cli.exe", false), identity.Code{}), false, false, "")
	// Stock OpenCode 1.18.31 on Windows is signed by its publisher and keeps
	// Bun's version resource: OriginalFilename bun.exe, FileDescription Bun.
	bunResource := identity.Code{Trusted: true, Subject: "Anomaly Innovations, Inc", OriginalName: "bun.exe", Description: "Bun"}
	opencode := classify(hostfixture.Bun(t, dir, "opencode.exe", true), bunResource)
	requireFacts(t, "the stock OpenCode binary", opencode, false, true, identity.ForeignCodeBunBeBun)
	if identity.SharedInterpreterProgram(filepath.Join(dir, "opencode.exe"), bunResource) {
		t.Error("SharedInterpreterProgram names the stock OpenCode binary a shared interpreter")
	}
	requireFacts(t, "an old Bun standalone executable with Bun's resource", classify(filepath.Join(dir, "old-cli.exe"), bunResource), false, false, "")
	requireFacts(t, "the bun runtime itself", classify(hostfixture.Plain(t, dir, "bun.exe"), bunResource), true, true, identity.ForeignCodeSharedInterpreter)
	refusal := opencode.PublisherPermitRefusal()
	if !strings.Contains(refusal, beBun()) || !strings.Contains(refusal, "The developer builds it without") {
		t.Errorf("the publisher-permit refusal names no remedy: %q", refusal)
	}
	electron := classify(filepath.Join(dir, "Code.exe"), identity.Code{})
	if r := electron.PublisherPermitRefusal(); !strings.Contains(r, "turns the RunAsNode fuse off") {
		t.Errorf("the Electron refusal names no remedy: %q", r)
	}
	if r := classify(filepath.Join(dir, "plain.exe"), identity.Code{}).PublisherPermitRefusal(); r != "" {
		t.Errorf("a plain program has a refusal: %q", r)
	}
}

// ID-I1: only Bun's own name evidence (bun.exe, or the file name bun) earns
// the Bun module-graph exception. Another interpreter's name carrying a Bun
// graph, with or without the BUN_BE_BUN name, stays a shared interpreter.
func TestABunGraphUnderAnotherInterpretersNameStaysShared(t *testing.T) {
	dir := t.TempDir()
	for _, c := range []struct {
		name  string
		beBun bool
	}{{"python.exe", false}, {"node.exe", false}, {"powershell.exe", true}} {
		program := hostfixture.Bun(t, filepath.Join(dir, c.name+"-graph"), c.name, c.beBun)
		requireFacts(t, c.name+" with a Bun graph", classify(program, identity.Code{}), true, true, identity.ForeignCodeSharedInterpreter)
		if !identity.SharedInterpreterProgram(program, identity.Code{}) {
			t.Errorf("SharedInterpreterProgram passes %s with a Bun graph", c.name)
		}
	}
	renamed := hostfixture.Bun(t, dir, "tool.exe", false)
	requireFacts(t, "a graph under python.exe's signed name", classify(renamed, identity.Code{Trusted: true, OriginalName: "python.exe"}), true, true, identity.ForeignCodeSharedInterpreter)
	requireFacts(t, "bun.exe carrying its own graph", classify(hostfixture.Bun(t, filepath.Join(dir, "own"), "bun.exe", true), identity.Code{}), false, true, identity.ForeignCodeBunBeBun)
}

// ID-I1: a pyvenv.cfg that cannot be verified reads as the shared
// interpreter, whatever the program's name, and SharedInterpreterVenv says
// why; the application registration reads the same rule.
func TestAnUnverifiedVenvReadsAsTheSharedInterpreter(t *testing.T) {
	dir := t.TempDir()
	home := filepath.Join(dir, "Python312")
	writeFile(t, filepath.Join(home, "python.exe"), "the shared interpreter")
	for name, c := range map[string]struct {
		config func(folder string)
		reason string
	}{
		"a relative home": {func(folder string) {
			writeFile(t, filepath.Join(folder, "pyvenv.cfg"), "home = Python312\n")
		}, "not an absolute path"},
		"a config that is a folder": {func(folder string) {
			if err := os.MkdirAll(filepath.Join(folder, "pyvenv.cfg"), 0o755); err != nil {
				t.Fatal(err)
			}
		}, "not a file"},
	} {
		folder := filepath.Join(dir, strings.ReplaceAll(name, " ", "-"))
		program := writeFile(t, filepath.Join(folder, "editor.exe"), "an app")
		c.config(folder)
		requireFacts(t, name, classify(program, identity.Code{}), true, true, identity.ForeignCodeSharedInterpreter)
		if err := identity.SharedInterpreterVenv(program); err == nil || !strings.Contains(err.Error(), c.reason) {
			t.Errorf("%s: SharedInterpreterVenv = %v, want %q", name, err, c.reason)
		}
	}
	plain := writeFile(t, filepath.Join(dir, "plain", "editor.exe"), "an app")
	if err := identity.SharedInterpreterVenv(plain); err != nil {
		t.Errorf("a program without a pyvenv.cfg: %v", err)
	}
	if err := identity.SharedInterpreterVenv("editor.exe"); err == nil {
		t.Error("a relative program passes the venv rule")
	}
}

// TD88, security-5: a Mach-O code signature whose entitlements allow DYLD
// variables, disable library validation or allow task access marks the
// image; a __BUN segment marks a Bun standalone executable. These rows read
// synthetic images on any platform; the rows on signed macOS programs need
// the owner's Mac (TestMacSignedEntitlementRows).
func TestImageForeignCodeMachO(t *testing.T) {
	for _, entitlement := range []string{
		"com.apple.security.cs.allow-dyld-environment-variables",
		"com.apple.security.cs.disable-library-validation",
		"com.apple.security.get-task-allow",
	} {
		image := machoImage(t, false, "com.apple.security.network.client", entitlement)
		got, err := identity.ImageForeignCode(bytes.NewReader(image), int64(len(image)))
		if err != nil || got != identity.ForeignCodeEntitlementPrefix+entitlement {
			t.Errorf("%s: %q %v", entitlement, got, err)
		}
	}
	for name, image := range map[string][]byte{
		"an unrelated entitlement": machoImage(t, false, "com.apple.security.network.client"),
		"no signature":             machoImage(t, false),
	} {
		if got, err := identity.ImageForeignCode(bytes.NewReader(image), int64(len(image))); err != nil || got != "" {
			t.Errorf("%s: %q %v", name, got, err)
		}
	}
	image := machoImage(t, true)
	if got, err := identity.ImageForeignCode(bytes.NewReader(image), int64(len(image))); err != nil || got != identity.ForeignCodeBunBeBun {
		t.Errorf("a Mach-O Bun standalone executable: %q %v", got, err)
	}
	dir := t.TempDir()
	program := hostfixture.MachO(t, dir, "Blender", false, "com.apple.security.cs.disable-library-validation")
	got := classify(program, identity.Code{})
	requireFacts(t, "a Mach-O plugin host", got, false, true, identity.ForeignCodeEntitlementPrefix+"com.apple.security.cs.disable-library-validation")
	if r := got.PublisherPermitRefusal(); !strings.Contains(r, "signs it without that entitlement") {
		t.Errorf("the entitlement refusal names no remedy: %q", r)
	}
}

// The rows on signed macOS programs (security-5's entitlements on a real
// signature, and an Electron app whose fuse wire lives in its Electron
// Framework rather than its main executable) need the owner's Mac.
func TestMacSignedEntitlementRows(t *testing.T) {
	t.Skip("needs the owner's Mac: signed programs carrying each entitlement, and an Electron app bundle (W1-14 Mac rows stay open)")
}

// A fuse wire split across the scanner's chunk boundary is read whole.
func TestImageForeignCodeAcrossChunks(t *testing.T) {
	sentinel := []byte(strings.ReplaceAll("dL7pKGdnNz796Pbb#QWNKmHXBZaB9tsX", "#", "j"))
	for _, before := range []int{4<<20 - 10, 4<<20 - len(sentinel), 4<<20 - len(sentinel) - 1, 4<<20 - len(sentinel) - 2} {
		image := append(make([]byte, before), sentinel...)
		image = append(image, 1, 9, '1', '0')
		image = append(image, make([]byte, 64)...)
		got, err := identity.ImageForeignCode(bytes.NewReader(image), int64(len(image)))
		if err != nil || got != identity.ForeignCodeElectronRunAsNode {
			t.Errorf("sentinel at %d: %q %v", before, got, err)
		}
	}
	image := append(make([]byte, 4<<20-5), sentinel...)
	image = append(image, 1, 9, 'r')
	if got, _ := identity.ImageForeignCode(bytes.NewReader(image), int64(len(image))); got != "" {
		t.Errorf("a removed RunAsNode fuse reads %q", got)
	}
}

// The stock OpenCode binary itself, read only, when a path to one is given:
// OA_TEST_STOCK_OPENCODE names an official opencode executable.
func TestStockOpenCodeBinary(t *testing.T) {
	path := os.Getenv("OA_TEST_STOCK_OPENCODE")
	if path == "" {
		t.Skip("OA_TEST_STOCK_OPENCODE names no stock OpenCode binary")
	}
	requireFacts(t, path, classify(path, identity.Code{}), false, true, identity.ForeignCodeBunBeBun)
}

// The fixture rows above read a copy of this test executable, which must
// carry no marker of its own.
func TestThisExecutableCarriesNoMarker(t *testing.T) {
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS == "js" {
		t.Skip("no executable file")
	}
	data, err := os.ReadFile(self)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := identity.ImageForeignCode(bytes.NewReader(data), int64(len(data))); err != nil || got != "" {
		t.Fatalf("the test executable reads %q %v", got, err)
	}
	if bytes.Contains(data, []byte(beBun())) {
		t.Fatal("the test executable carries the Bun variable's name, so its copies read as a current Bun runtime")
	}
}

// machoImage is the bytes of a synthetic Mach-O image hostfixture writes.
func machoImage(t *testing.T, bun bool, entitlements ...string) []byte {
	t.Helper()
	data, err := os.ReadFile(hostfixture.MachO(t, t.TempDir(), "image", bun, entitlements...))
	if err != nil {
		t.Fatal(err)
	}
	return data
}
