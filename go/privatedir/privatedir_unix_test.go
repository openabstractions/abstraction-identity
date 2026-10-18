//go:build unix

package privatedir

import (
	"io/fs"
	"os"
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
