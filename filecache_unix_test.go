//go:build unix

package identity

import (
	"fmt"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

// inodeOf is the inode number of the file at path.
func inodeOf(t *testing.T, path string) uint64 {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	return uint64(info.Sys().(*syscall.Stat_t).Ino)
}

// A file created after another was deleted can take the deleted file's
// inode on ext4, which hands a freed inode out again. With the deleted
// file's size and modification time, it is still read as itself. A file
// system that does not reuse the inode within the tries skips the test with
// the try count: tmpfs does not reuse it, and APFS takes file IDs from an
// increasing counter (next_obj_id), so the test is expected to skip on
// macOS, where it has not been run.
func TestAReusedInodeReadsTheBunGraphAgain(t *testing.T) {
	const tries = 200
	dir := t.TempDir()
	first := filepath.Join(dir, "first")
	writeProgramFile(t, first, "no graph, first")
	reads := countBunGraphReads(t)
	bunStandaloneFile(first)
	if *reads != 1 {
		t.Fatalf("one file was read %d times", *reads)
	}
	info, err := os.Stat(first)
	if err != nil {
		t.Fatal(err)
	}
	inode := inodeOf(t, first)
	time.Sleep(changeTimeTick)
	if err := os.Remove(first); err != nil {
		t.Fatal(err)
	}
	for try := range tries {
		next := filepath.Join(dir, fmt.Sprintf("next-%d", try))
		writeProgramFile(t, next, "no graph, again")
		if inodeOf(t, next) != inode {
			continue
		}
		if err := os.Chtimes(next, info.ModTime(), info.ModTime()); err != nil {
			t.Fatal(err)
		}
		bunStandaloneFile(next)
		if *reads != 2 {
			t.Fatalf("a file on the deleted file's inode %d with its size and time read as the deleted file: %d reads", inode, *reads)
		}
		t.Logf("inode %d reused at try %d", inode, try)
		return
	}
	t.Skipf("this file system did not reuse inode %d in %d tries", inode, tries)
}
