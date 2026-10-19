package fileid

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// The functions identity exported before fileid refuse a stream spelling on
// Windows (ID-F9; coordinator ruling D3, 2026-10-21): a colon after the
// volume name, a named stream or ::$DATA, answers their refusal, a
// *NotLocalPathError, and ValidSubjectProgram answers false. Code in
// p.exe:evil.exe is never the program p.exe.
func TestTheOlderFunctionsRefuseAStreamSpelling(t *testing.T) {
	dir := t.TempDir()
	p := writeFile(t, filepath.Join(dir, "p.exe"), "program")
	if err := os.WriteFile(p+":evil.exe", []byte("other code"), 0o644); err != nil {
		t.Skip("this volume keeps no alternate streams:", err)
	}
	if same, err := SameFile(p, p); !same || err != nil || !ValidSubjectProgram(p) || !SameSubjectProgram(p, p) {
		t.Fatalf("p.exe against itself: SameFile %v, %v; valid %v", same, err, ValidSubjectProgram(p))
	}
	refused := func(what, s string, err error) {
		t.Helper()
		var nl *NotLocalPathError
		if !errors.Is(err, ErrNotLocalPath) || !errors.As(err, &nl) {
			t.Errorf("%s %s: %v, want a *NotLocalPathError", what, s, err)
		}
	}
	for _, s := range []string{p + ":evil.exe", p + ":evil.exe:$DATA", p + "::$DATA", `\\?\` + p + ":evil.exe", dir + `:x\p.exe`} {
		same, err := SameFile(s, p)
		refused("SameFile", s, err)
		if same {
			t.Errorf("SameFile %s, p.exe = true", s)
		}
		_, err = SameFile(p, s)
		refused("SameFile p.exe,", s, err)
		_, err = FileKey(s)
		refused("FileKey", s, err)
		_, err = PlaceKey(s)
		refused("PlaceKey", s, err)
		_, in, err := WithinRel(s, dir)
		refused("WithinRel", s, err)
		_, _, err = WithinRel(p, s)
		refused("WithinRel into", s, err)
		_, inside, err := InsideRel(s, dir)
		refused("InsideRel", s, err)
		if in || inside || Inside(s, dir) {
			t.Errorf("%s lies inside %s", s, dir)
		}
		if ValidSubjectProgram(s) || SameSubjectProgram(s, p) || SameSubjectProgram(p, s) || ProgramKey(s) != "" {
			t.Errorf("%s: valid %v, same program as p.exe %v, key %q", s, ValidSubjectProgram(s), SameSubjectProgram(s, p), ProgramKey(s))
		}
	}
}
