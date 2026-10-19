package identity

import (
	"os"
	"path/filepath"
	"strconv"
	"sync"

	"github.com/openabstractions/abstraction-identity/fileid"
)

// fileCache caches one fact about a program file by the file's stamp
// (fileStamp). The stamp is read from the open handle of the file the fact
// was read from: its file identity, size, modification time and change time,
// and its birth time where the platform reports one. A file rewritten in
// place gets a new change time, and a new file gets a new identity or a new
// change time, so either is read again.
//
// Two cases keep a stamp. A rewrite or a delete and recreate with equal size
// and modification time inside one tick of the clock the change time comes
// from: at most about 16 milliseconds on NTFS, APFS and ext4 with 256-byte
// inodes, one second on ext3 and ext4 with 128-byte inodes. A file on FAT or exFAT, which keep
// no change time of their own, replaced by one of equal size and
// modification time. On Unix only a change of the system clock sets a change
// time back. On Windows any caller allowed to write the file's attributes
// can set its ChangeTime (SetFileInformationByHandle, FileBasicInfo); there
// the NTFS file ID tells a new file from a deleted one (filestamp_windows.go).
//
// A cache holds at most maxFileCache facts, and a full cache starts over.
type fileCache[V any] struct {
	mu   sync.Mutex
	seen map[string]V
}

// maxFileCache bounds each fileCache.
const maxFileCache = 512

func (c *fileCache[V]) get(stamp string) (V, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	v, ok := c.seen[stamp]
	return v, ok
}

func (c *fileCache[V]) put(stamp string, v V) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.seen == nil || len(c.seen) >= maxFileCache {
		c.seen = map[string]V{}
	}
	c.seen[stamp] = v
}

// keep caches v, read from f after f was stamped stamp, when f's stamp is
// still stamp. A fact read while the file changed is returned to its caller
// and read again next time.
func (c *fileCache[V]) keep(f *os.File, stamp string, v V) {
	if now, _, err := fileStamp(f); err == nil && now == stamp {
		c.put(stamp, v)
	}
}

// stampInputs are the parts of a file stamp, all read from one open handle.
type stampInputs struct {
	// identity is the file identity: device and inode on Unix, volume serial
	// number and file ID on Windows.
	identity string
	size     int64
	// modified is the modification time, which anyone who may write the
	// file can set.
	modified int64
	// changed is the change time the system sets on every write and every
	// change to the file's metadata (Unix st_ctime, Windows ChangeTime).
	changed int64
	// born is the birth time where the platform reports one, and 0 elsewhere.
	born int64
}

// stamp is the cache key the inputs make.
func (in stampInputs) stamp() string {
	return in.identity + "|" + strconv.FormatInt(in.size, 10) + "|" + strconv.FormatInt(in.modified, 10) +
		"|" + strconv.FormatInt(in.changed, 10) + "|" + strconv.FormatInt(in.born, 10)
}

// fileStamp is the cache key of the open file f and f's FileInfo. Every part
// comes from the handle, so the stamp names the file f reads, whatever the
// path names now.
func fileStamp(f *os.File) (string, os.FileInfo, error) {
	return FileStamp(f)
}

// FileStamp reads an opaque cache-invalidation key and FileInfo from f's
// held handle. Compare stamps only for equality; their representation is not
// stable storage or an identity/authorization proof. The key includes the file
// identity, size and available modification, change and birth times.
//
// A stamp is metadata, not a digest or an unchanged-bytes guarantee. Writes
// inside the change clock's granularity, filesystems without change times,
// and Windows callers restoring ChangeTime retain the limitations described
// by ID-I1. A caller reading a fact must sample this same handle before and
// after its read and retain the fact only when both successful stamps match.
// The caller owns f's lifetime and regular-file/read policy. Errors establish
// no unchanged fact.
func FileStamp(f *os.File) (string, os.FileInfo, error) {
	info, err := f.Stat()
	if err != nil {
		return "", nil, err
	}
	in, err := readStampInputs(f, info)
	if err != nil {
		return "", nil, err
	}
	return in.stamp(), info, nil
}

// openProgram opens a program file for openStamped; tests replace it.
var openProgram = os.Open

// openStamped opens the local regular file at program and returns it with
// its stamp; ok is false for a relative path, a path the older path
// functions refuse (fileid.OlderPath: one off a local drive, and on Windows
// one naming a data stream, whose bytes are not its file's although its
// stamp is), a missing file, a failed read and a platform without file
// identity, which are no evidence. On Windows the handle shares reading and
// writing only (os.Open), so the file cannot be renamed or deleted while it
// is open.
func openStamped(program string) (f *os.File, info os.FileInfo, stamp string, ok bool) {
	return openStampedWith(program, openProgram)
}

// openStampedWith keeps local/regular/stamp admission shared with the
// signature-specific opener, whose Windows handle also allows rename.
func openStampedWith(program string, open func(string) (*os.File, error)) (f *os.File, info os.FileInfo, stamp string, ok bool) {
	if !filepath.IsAbs(program) || fileid.OlderPath(program) != nil {
		return nil, nil, "", false
	}
	f, err := open(program)
	if err != nil {
		return nil, nil, "", false
	}
	stamp, info, err = fileStamp(f)
	if err != nil || !info.Mode().IsRegular() {
		f.Close()
		return nil, nil, "", false
	}
	return f, info, stamp, true
}
