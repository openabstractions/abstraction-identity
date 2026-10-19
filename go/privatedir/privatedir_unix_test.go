//go:build unix

package privatedir

import (
	"io/fs"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

type rootInfo struct {
	mode fs.FileMode
	uid  uint32
}

func (r rootInfo) Name() string       { return "root" }
func (r rootInfo) Size() int64        { return 0 }
func (r rootInfo) Mode() fs.FileMode  { return r.mode }
func (r rootInfo) ModTime() time.Time { return time.Time{} }
func (r rootInfo) IsDir() bool        { return r.mode.IsDir() }
func (r rootInfo) Sys() any           { return &syscall.Stat_t{Uid: r.uid} }

// INF-EL2, INF-MS7 elsewhere: a private folder passes only as a directory of this
// account with mode 0700. Another owner is judged on file information,
// since a test cannot make a folder another account owns.
func TestThePrivateFolderOwnerAndModeRule(t *testing.T) {
	uid := uint32(os.Getuid())
	for name, c := range map[string]struct {
		info rootInfo
		pass bool
	}{
		"private":         {rootInfo{fs.ModeDir | 0o700, uid}, true},
		"another owner":   {rootInfo{fs.ModeDir | 0o700, uid + 1}, false},
		"group readable":  {rootInfo{fs.ModeDir | 0o750, uid}, false},
		"world open":      {rootInfo{fs.ModeDir | 0o777, uid}, false},
		"owner only 0500": {rootInfo{fs.ModeDir | 0o500, uid}, false},
		"a link":          {rootInfo{fs.ModeSymlink | 0o700, uid}, false},
		"a file":          {rootInfo{0o600, uid}, false},
	} {
		if err := checkInfo(c.info, int(uid), true); (err == nil) != c.pass {
			t.Fatalf("%s: %v, wanted pass=%v", name, err, c.pass)
		}
	}
}

// ID-D1, storage STO-L9: Tighten writes the mode of the folder it opens as
// itself. A link to a folder is refused and the folder it names keeps its
// mode; a file is refused.
func TestTightenRefusesALinkAndAFile(t *testing.T) {
	base := t.TempDir()
	target := filepath.Join(base, "target")
	if err := os.Mkdir(target, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(target, 0o755); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(base, "link")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if err := Tighten(link); err == nil {
		t.Fatal("Tighten followed a link")
	}
	if info, err := os.Stat(target); err != nil || info.Mode().Perm() != 0o755 {
		t.Fatalf("the folder a link names: %v %v", info.Mode(), err)
	}
	file := filepath.Join(base, "file")
	if err := os.WriteFile(file, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := Tighten(file); err == nil {
		t.Fatal("Tighten accepted a file")
	}
	if err := Tighten(target); err != nil {
		t.Fatal(err)
	}
	if err := CheckDir(target); err != nil {
		t.Fatalf("a tightened folder: %v", err)
	}
}

func TestCheckFileUnixOwnerModesAndSpecial(t *testing.T) {
	uid := os.Getuid()
	if err := checkOwnerMode(rootInfo{mode: 0600, uid: uint32(uid + 1)}, uid); err == nil {
		t.Fatal("foreign UID accepted")
	}
	root := t.TempDir()
	path := filepath.Join(root, "key")
	if err := os.WriteFile(path, nil, 0600); err != nil {
		t.Fatal(err)
	}
	if err := CheckFile(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0640); err != nil {
		t.Fatal(err)
	}
	if err := CheckFile(path); err == nil {
		t.Fatal("group-readable file accepted")
	}
	link := filepath.Join(root, "link")
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	if err := CheckFile(link); err == nil {
		t.Fatal("symlink accepted")
	}
	fifo := filepath.Join(root, "fifo")
	if err := syscall.Mkfifo(fifo, 0600); err != nil {
		t.Fatal(err)
	}
	if err := CheckFile(fifo); err == nil {
		t.Fatal("FIFO accepted")
	}
}
