package identity

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"
)

// sharedNameCases checks SharedInterpreterFileName and SharedInterpreterProgram
// with no evidence over one platform's names, so each group runs anywhere.
func sharedNameCases(t *testing.T, cases map[string]bool) {
	t.Helper()
	for program, host := range cases {
		if got := SharedInterpreterFileName(program); got != host {
			t.Errorf("SharedInterpreterFileName(%q) = %t, want %t", program, got, host)
		}
		if got := SharedInterpreterProgram(program, Code{}); got != host {
			t.Errorf("SharedInterpreterProgram(%q) = %t, want %t", program, got, host)
		}
	}
}

// ID-I1: Windows file names, any case, a versioned python3.12.exe and the
// LOLBAS .NET tools included.
func TestSharedInterpreterNamesWindows(t *testing.T) {
	sharedNameCases(t, map[string]bool{
		`C:\Windows\System32\WindowsPowerShell\v1.0\PowerShell.EXE`: true, `C:\Windows\System32\cmd.exe`: true,
		`C:\Python312\python.exe`: true, `C:\Python312\pythonw.exe`: true, `C:\py\python3.12.exe`: true,
		`C:\nodejs\node.exe`: true, `C:\Program Files\Git\bin\bash.exe`: true, `mshta.exe`: true,
		`C:\Program Files\dotnet\dotnet.exe`: true, `C:\jdk\bin\javaw.exe`: true, `C:\jdk\bin\java.exe`: true,
		`C:\deno\deno.exe`: true, `C:\Julia-1.11\bin\julia.exe`: true,
		`C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe`: true,
		`C:\Windows\Microsoft.NET\Framework64\v4.0.30319\RegAsm.exe`:      true,
		`C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe`:         true,
		`C:\R\R-4.4.1\bin\Rscript.exe`:                                    true, `C:\Program Files\PowerShell\7\pwsh.dll`: true,
		`C:\Program Files\Editor\editor.exe`: false, `C:\Windows\notepad.exe`: false,
		`C:\Users\a\AppData\Local\Programs\opencode\opencode.exe`: false, "": false,
	})
}

// ID-I1: macOS shells, osascript, interpreters and Python.app's bundle
// executable.
func TestSharedInterpreterNamesMac(t *testing.T) {
	sharedNameCases(t, map[string]bool{
		"/bin/zsh": true, "/bin/sh": true, "/bin/bash": true, "/bin/ksh": true, "/usr/bin/osascript": true,
		"/usr/bin/python3": true, "/opt/homebrew/bin/python3.12": true,
		"/Library/Frameworks/Python.framework/Versions/3.12/Resources/Python.app/Contents/MacOS/Python": true,
		"/usr/bin/perl5.34": true, "/usr/bin/ruby": true, "/opt/homebrew/bin/node": true,
		"/Users/a/.bun/bin/bun": true, "/opt/homebrew/bin/deno": true, "/opt/homebrew/bin/fish": true,
		"/Applications/OpenCode.app/Contents/MacOS/opencode":     false,
		"/Applications/Calculator.app/Contents/MacOS/Calculator": false,
	})
}

// ID-I1: Linux shells and versioned interpreters.
func TestSharedInterpreterNamesLinux(t *testing.T) {
	sharedNameCases(t, map[string]bool{
		"/bin/dash": true, "/usr/bin/bash": true, "/usr/bin/fish": true, "/bin/busybox": true,
		"/usr/bin/python3.11": true, "/usr/bin/perl5.36.0": true, "/usr/bin/php8.2": true,
		"/usr/bin/lua5.4": true, "/usr/bin/nodejs": true, "/usr/bin/tclsh8.6": true, "/usr/bin/gawk": true,
		"/usr/bin/dotnet": true, "/usr/local/bin/julia": true, "/usr/bin/Rscript": true,
		"/usr/bin/opencode": false, "/usr/bin/vim": false, "/usr/bin/shellcheck": false,
	})
}

// Every signed Windows name also reads as a shared interpreter by file name,
// so the two lists cannot drift apart.
func TestSharedInterpreterListsAgree(t *testing.T) {
	for name := range sharedInterpreterNames {
		if !SharedInterpreterFileName(name) {
			t.Errorf("%s is a signed shared interpreter but not one by file name", name)
		}
	}
	for _, name := range []string{"PowerShell.EXE", "pwsh.exe", "pwsh.dll", "Cmd.Exe", "wscript.exe", "cscript.exe", "MSHTA.EXE",
		"RUNDLL32.EXE", "REGSVR32.EXE", "MSBuild.exe", "wsl.exe", "bash.exe", "python.exe", "pythonw.exe", "node.exe", "bun.exe",
		"git.exe", "dotnet.exe", "java.exe", "deno.exe", "InstallUtil.exe"} {
		if !SharedInterpreterName(name) {
			t.Errorf("%s must be a shared interpreter", name)
		}
	}
	if SharedInterpreterName("PowerShell.EXE.MUI") || SharedInterpreterName("NOTEPAD.EXE") {
		t.Error("a resource file or an app reads as a shared interpreter")
	}
}

func TestTheFirstHomeLineIsTheOnePythonReads(t *testing.T) {
	for text, want := range map[string]string{
		"home = C:\\A\nhome = C:\\B\n":      `C:\A`,
		"\xef\xbb\xbf HOME\t=  C:\\A  \r\n": `C:\A`,
		"version = 3.12\n":                  "",
		"homes = C:\\A\nhome=\n":            "",
		"include-system-site-packages = no": "",
	} {
		if got := venvConfigHome([]byte(text)); got != want {
			t.Errorf("%q: %q, want %q", text, got, want)
		}
	}
}

// A venv home is listed once per program file, home folder and home
// modification time: the next check reads the cache, and a link added to
// the home makes the check list it again and find the link.
func TestVenvHomeScanIsCached(t *testing.T) {
	dir := t.TempDir()
	home := filepath.Join(dir, "Python312")
	own := filepath.Join(dir, "app", "host")
	for path, content := range map[string]string{filepath.Join(home, "python.exe"): "shared", filepath.Join(own, "python.exe"): "own copy"} {
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(content), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(own, "pyvenv.cfg"), []byte("home = "+home+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	program := filepath.Join(own, "python.exe")
	if ProgramKey(program) == "" {
		t.Skip("no file identity on this platform")
	}
	scans, saved := 0, venvHomeScan
	venvHomeScan = func(home, key string) (venvScan, error) { scans++; return saved(home, key) }
	t.Cleanup(func() { venvHomeScan = saved })
	for range 3 {
		if state, err := readVenv(program); state != venvOwnCopy || err != nil {
			t.Fatal(state, err)
		}
	}
	if scans != 1 {
		t.Fatalf("the home was listed %d times for one program", scans)
	}
	before, err := os.Stat(home)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Link(program, filepath.Join(home, "python3.exe")); err != nil {
		t.Skipf("no hard links here: %v", err)
	}
	if after, err := os.Stat(home); err != nil || after.ModTime().Equal(before.ModTime()) {
		t.Skipf("this file system keeps the folder's time on a new link: %v", err)
	}
	if state, err := readVenv(program); state != venvHomeFile || err == nil || scans != 2 {
		t.Fatalf("after a link into the home: %v %v, %d listings", state, err, scans)
	}
}

// A Bun graph read is remembered by file stamp; a rewritten file is read
// again.
func TestBunGraphReadIsCached(t *testing.T) {
	program := filepath.Join(t.TempDir(), "bun.exe")
	if err := os.WriteFile(program, []byte("no graph"), 0o755); err != nil {
		t.Fatal(err)
	}
	if ProgramKey(program) == "" {
		t.Skip("no file identity on this platform")
	}
	reads, saved := 0, bunGraphRead
	bunGraphRead = func(r io.ReaderAt, size int64) bool { reads++; return saved(r, size) }
	t.Cleanup(func() { bunGraphRead = saved })
	for range 3 {
		if bunStandaloneFile(program) {
			t.Fatal("a file without a graph reads as Bun standalone")
		}
	}
	if reads != 1 {
		t.Fatalf("one file was read %d times", reads)
	}
	if err := os.WriteFile(program, []byte("no graph, rewritten"), 0o755); err != nil {
		t.Fatal(err)
	}
	bunStandaloneFile(program)
	if reads != 2 {
		t.Fatalf("a rewritten file was not read again: %d reads", reads)
	}
}

// A signature read that fails is no evidence and is not remembered: the next
// check of the same file reads it again. A successful read is remembered by
// file identity.
func TestSignedSharedInterpreterFileRetriesAFailedRead(t *testing.T) {
	program := filepath.Join(t.TempDir(), "renamed-tool.exe")
	if err := os.WriteFile(program, []byte("copy"), 0o600); err != nil {
		t.Fatal(err)
	}
	if ProgramKey(program) == "" {
		t.Skip("no file identity on this platform")
	}
	reads, failing := 0, true
	saved := verifyProgramFile
	verifyProgramFile = func(*os.File, string, *Options) (Code, Proof, error) {
		reads++
		if failing {
			return Code{}, 0, errors.New("file busy")
		}
		return Code{Trusted: true, OriginalName: "powershell.exe"}, 0, nil
	}
	t.Cleanup(func() { verifyProgramFile = saved })
	if signedSharedInterpreterFile(program) {
		t.Fatal("a failed read reads as a shared interpreter")
	}
	failing = false
	if !signedSharedInterpreterFile(program) || reads != 2 {
		t.Fatalf("after a failed read the file was not read again: reads=%d", reads)
	}
	if !signedSharedInterpreterFile(program) || reads != 2 {
		t.Fatalf("a successful read is not remembered: reads=%d", reads)
	}
}
