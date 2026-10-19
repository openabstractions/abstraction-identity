package identity

import (
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// changeTimeTick is longer than the clock tick a file system takes its
// change time from: up to 15.6 ms on NTFS, a few milliseconds on ext4 and
// APFS. A test waits this long before a change it expects the change time
// to show.
const changeTimeTick = 100 * time.Millisecond

func TestExportedFileStampUsesHeldHandleAndRefusesClosedFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "stamp")
	writeProgramFile(t, path, "first")
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	stamp, info, err := FileStamp(f)
	if err != nil || stamp == "" || info.Size() != 5 {
		t.Fatal(stamp, info, err)
	}
	if private, _, err := fileStamp(f); err != nil || private != stamp {
		t.Fatal("private and exported stamp differ", err)
	}
	if again, _, err := FileStamp(f); err != nil || again != stamp {
		t.Fatal("unchanged handle differs", err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	if key, _, err := FileStamp(f); err == nil || key != "" {
		t.Fatal("closed handle became evidence", key, err)
	}
}

// countBunGraphReads counts the image reads bunStandaloneFile makes until
// the test ends.
func countBunGraphReads(t *testing.T) *int {
	t.Helper()
	reads, saved := 0, bunGraphRead
	bunGraphRead = func(r io.ReaderAt, size int64) bool { reads++; return saved(r, size) }
	t.Cleanup(func() { bunGraphRead = saved })
	return &reads
}

// writeProgramFile writes content to path and fails t on an error.
func writeProgramFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o755); err != nil {
		t.Fatal(err)
	}
}

// rewriteKeepingSizeAndTime rewrites the file at path in place with content
// of the same length and sets its modification time back, as a tool that
// preserves times does. It fails t unless the file keeps its identity, size
// and modification time.
func rewriteKeepingSizeAndTime(t *testing.T, path, content string) {
	t.Helper()
	before, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	key := ProgramKey(path)
	time.Sleep(changeTimeTick)
	writeProgramFile(t, path, content)
	if err := os.Chtimes(path, before.ModTime(), before.ModTime()); err != nil {
		t.Fatal(err)
	}
	after, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if ProgramKey(path) != key || after.Size() != before.Size() || !after.ModTime().Equal(before.ModTime()) {
		t.Fatalf("the rewrite changed what it keeps: identity %t, size %d to %d, time %v to %v",
			ProgramKey(path) == key, before.Size(), after.Size(), before.ModTime(), after.ModTime())
	}
}

// A file rewritten in place with its size and modification time kept is
// another file's content under the same identity: its Bun graph is read
// again.
func TestAnInPlaceRewriteReadsTheBunGraphAgain(t *testing.T) {
	program := filepath.Join(t.TempDir(), "bun.exe")
	writeProgramFile(t, program, "no graph, first")
	if ProgramKey(program) == "" {
		t.Skip("no file identity on this platform")
	}
	reads := countBunGraphReads(t)
	bunStandaloneFile(program)
	bunStandaloneFile(program)
	if *reads != 1 {
		t.Fatalf("one file was read %d times", *reads)
	}
	rewriteKeepingSizeAndTime(t, program, "no graph, again")
	bunStandaloneFile(program)
	if *reads != 2 {
		t.Fatalf("a file rewritten in place with its size and time kept was not read again: %d reads", *reads)
	}
}

// A signed verdict is remembered for the file as it was verified: a file
// rewritten in place with its size and modification time kept is verified
// again, so a shared interpreter written over an ordinary program is caught.
func TestAnInPlaceRewriteVerifiesTheSignatureAgain(t *testing.T) {
	program := filepath.Join(t.TempDir(), "renamed-tool.exe")
	writeProgramFile(t, program, "a tool")
	if ProgramKey(program) == "" {
		t.Skip("no file identity on this platform")
	}
	verifications, saved := 0, verifyProgramFile
	verifyProgramFile = func(_ *os.File, path string, _ *Options) (Code, Proof, error) {
		verifications++
		data, err := os.ReadFile(path)
		if err != nil {
			return Code{}, ProofNone, err
		}
		if string(data) == "python" {
			return Code{Trusted: true, OriginalName: "python.exe"}, ProofBound, nil
		}
		return Code{Trusted: true, OriginalName: "tool.exe"}, ProofBound, nil
	}
	t.Cleanup(func() { verifyProgramFile = saved })
	if signedSharedInterpreterFile(program) || signedSharedInterpreterFile(program) || verifications != 1 {
		t.Fatalf("an ordinary program: %d verifications", verifications)
	}
	rewriteKeepingSizeAndTime(t, program, "python")
	if !signedSharedInterpreterFile(program) || verifications != 2 {
		t.Fatalf("a shared interpreter written in place over a program keeps the old verdict: %d verifications", verifications)
	}
}

// The stamp a fact is cached by comes from the file that was opened: a file
// put in place of the program just before the open, with the old file's
// size and modification time, is read as itself.
func TestTheStampComesFromTheOpenedFile(t *testing.T) {
	dir := t.TempDir()
	program := filepath.Join(dir, "bun.exe")
	replacement := filepath.Join(dir, "replacement.exe")
	writeProgramFile(t, program, "no graph, first")
	writeProgramFile(t, replacement, "no graph, again")
	if ProgramKey(program) == "" {
		t.Skip("no file identity on this platform")
	}
	before, err := os.Stat(program)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(replacement, before.ModTime(), before.ModTime()); err != nil {
		t.Fatal(err)
	}
	reads := countBunGraphReads(t)
	bunStandaloneFile(program)
	if *reads != 1 {
		t.Fatalf("one file was read %d times", *reads)
	}
	saved := openProgram
	openProgram = func(name string) (*os.File, error) {
		openProgram = saved
		if err := os.Rename(replacement, name); err != nil {
			t.Errorf("replace the program: %v", err)
		}
		return saved(name)
	}
	t.Cleanup(func() { openProgram = saved })
	bunStandaloneFile(program)
	if *reads != 2 {
		t.Fatalf("a file put in place of the program before the open read as the old file: %d reads", *reads)
	}
}

// Every input of a stamp changes it; two files that differ only in change
// time have different stamps.
func TestStampInputsEachChangeTheStamp(t *testing.T) {
	base := stampInputs{identity: "0000000000000001-2a", size: 15, modified: 1000, changed: 2000, born: 500}
	seen := map[string]string{base.stamp(): "base"}
	for name, in := range map[string]stampInputs{
		"identity": {identity: "0000000000000001-2b", size: 15, modified: 1000, changed: 2000, born: 500},
		"size":     {identity: "0000000000000001-2a", size: 16, modified: 1000, changed: 2000, born: 500},
		"modified": {identity: "0000000000000001-2a", size: 15, modified: 1001, changed: 2000, born: 500},
		"changed":  {identity: "0000000000000001-2a", size: 15, modified: 1000, changed: 2001, born: 500},
		"born":     {identity: "0000000000000001-2a", size: 15, modified: 1000, changed: 2000, born: 501},
	} {
		if other, ok := seen[in.stamp()]; ok {
			t.Errorf("a different %s gives the stamp of %s: %q", name, other, in.stamp())
		}
		seen[in.stamp()] = name
	}
}

// fileStamp reads the stamp of the file the handle names: the same file
// opened twice has one stamp, and a rewrite in place with its size and
// modification time kept changes it.
func TestFileStampFollowsTheChangeTime(t *testing.T) {
	program := filepath.Join(t.TempDir(), "tool.exe")
	writeProgramFile(t, program, "no graph, first")
	if ProgramKey(program) == "" {
		t.Skip("no file identity on this platform")
	}
	first := stampOf(t, program)
	if again := stampOf(t, program); again != first {
		t.Fatalf("one unchanged file has two stamps: %q and %q", first, again)
	}
	rewriteKeepingSizeAndTime(t, program, "no graph, again")
	if after := stampOf(t, program); after == first {
		t.Fatalf("a rewrite in place with its size and time kept keeps the stamp %q", first)
	}
}

// stampOf is the stamp of the file at path, read through a handle of it.
func stampOf(t *testing.T, path string) string {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	stamp, _, err := fileStamp(f)
	if err != nil {
		t.Fatal(err)
	}
	return stamp
}

// A Bun graph read while the file was rewritten is returned and not
// remembered under the stamp taken before the read: the next check reads
// the file again, and the one after that uses the cache.
func TestABunGraphReadDuringARewriteIsNotKept(t *testing.T) {
	program := filepath.Join(t.TempDir(), "bun.exe")
	writeProgramFile(t, program, "no graph, first")
	if ProgramKey(program) == "" {
		t.Skip("no file identity on this platform")
	}
	before := stampOf(t, program)
	reads, saved := 0, bunGraphRead
	bunGraphRead = func(r io.ReaderAt, size int64) bool {
		reads++
		if reads == 1 {
			rewriteKeepingSizeAndTime(t, program, "no graph, again")
		}
		return saved(r, size)
	}
	t.Cleanup(func() { bunGraphRead = saved })
	bunStandaloneFile(program)
	if _, kept := bunImages.get(before); kept {
		t.Fatal("a read during a rewrite was kept under the stamp taken before it")
	}
	bunStandaloneFile(program)
	bunStandaloneFile(program)
	if reads != 2 {
		t.Fatalf("a read during a rewrite: %d reads in three checks, want 2", reads)
	}
}

// A signed verdict read while the held file is moved and replaced is returned
// and not remembered under the stamp taken before verification. The next check
// verifies the replacement. Signature handles exclude concurrent writers.
func TestASignedVerdictReadDuringARewriteIsNotKept(t *testing.T) {
	program := filepath.Join(t.TempDir(), "renamed-tool.exe")
	writeProgramFile(t, program, "a tool")
	if ProgramKey(program) == "" {
		t.Skip("no file identity on this platform")
	}
	before := stampOf(t, program)
	verifications, saved := 0, verifyProgramFile
	verifyProgramFile = func(*os.File, string, *Options) (Code, Proof, error) {
		verifications++
		if verifications == 1 {
			if err := os.Rename(program, program+".held"); err != nil {
				t.Fatal(err)
			}
			writeProgramFile(t, program, "python")
			return Code{Trusted: true, OriginalName: "tool.exe"}, ProofBound, nil
		}
		return Code{Trusted: true, OriginalName: "python.exe"}, ProofBound, nil
	}
	t.Cleanup(func() { verifyProgramFile = saved })
	if signedSharedInterpreterFile(program) {
		t.Fatal("the first verdict reads as a shared interpreter")
	}
	if _, kept := signedInterpreters.get(before); kept {
		t.Fatal("a verdict read during a rewrite was kept under the stamp taken before it")
	}
	if !signedSharedInterpreterFile(program) || !signedSharedInterpreterFile(program) || verifications != 2 {
		t.Fatalf("a verdict read during a rewrite was kept: %d verifications, want 2", verifications)
	}
}
