//go:build darwin || linux

package identity

import (
	"errors"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"golang.org/x/sys/unix"
)

// localVolumeDeadline bounds how long LocalPath waits for a volume to report
// what it is. A dead NFS or SMB mount can block statfs indefinitely; a
// volume that does not answer in time is treated as not local.
const localVolumeDeadline = 500 * time.Millisecond

// maxStuckVolumeProbes bounds the volume probes outstanding at once on one
// mount, counted from the start of each until it returns, so a dead mount
// holds at most that many threads. A call that finds a mount's probes all
// outstanding refuses at once when one of them has outlived its caller's
// deadline (the mount is not answering), and otherwise waits for a slot
// within its own deadline, so a burst on a healthy mount is probed in turn.
// Paths on other mounts are probed regardless.
const maxStuckVolumeProbes = 8

// localPath is LocalPath on macOS and Linux: a path is local when the volume
// holding it, or holding its deepest existing folder, is a local file system
// (volumeAnswer: MNT_LOCAL on macOS, the file system type on Linux). A
// network volume, a volume that cannot be read, and one that does not answer
// within localVolumeDeadline are refused. statfs reads the volume by path
// lookup and opens nothing.
func localPath(path string) error {
	if path == "" {
		return errors.New("identity: empty path")
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return &NotLocalPathError{Path: path, Reason: err.Error()}
	}
	abs = filepath.Clean(abs)
	if markedNetwork(abs) {
		return &NotLocalPathError{Path: path, Reason: "a network volume"}
	}
	timer := time.NewTimer(localVolumeDeadline)
	defer timer.Stop()
	// Each probe is counted against the mount its spelling lies on, from its
	// start until it returns. Choosing the mount shares the deadline.
	mount, ok := mountOf(abs, timer.C)
	if !ok {
		return &NotLocalPathError{Path: path, Reason: errVolumeNoAnswer.Error()}
	}
	p := startProbe(mount, timer.C)
	if p == nil {
		return &NotLocalPathError{Path: path, Reason: errVolumeNoAnswer.Error()}
	}
	done := make(chan error, 1)
	go func() {
		err := volumeLocal(abs)
		endProbe(mount, p)
		done <- err
	}()
	select {
	case err := <-done:
		if err != nil {
			return &NotLocalPathError{Path: path, Reason: err.Error()}
		}
		return nil
	case <-timer.C:
		markStuck(mount, p)
		return &NotLocalPathError{Path: path, Reason: errVolumeNoAnswer.Error()}
	}
}

// probe is one outstanding volume probe; stuck is set when its caller's
// deadline passed before it returned.
type probe struct{ stuck, done bool }

// mountProbes counts one mount's outstanding probes and those of them that
// are stuck. freed is closed when a probe returns, waking waiting callers.
type mountProbes struct {
	outstanding, stuck int
	freed              chan struct{}
}

var probes struct {
	sync.Mutex
	mounts map[string]*mountProbes
}

// startProbe counts a new probe against mount. When maxStuckVolumeProbes are
// outstanding there it answers nil at once if one of them is stuck, and
// otherwise waits for one to return until deadline fires (nil).
func startProbe(mount string, deadline <-chan time.Time) *probe {
	for {
		probes.Lock()
		if probes.mounts == nil {
			probes.mounts = map[string]*mountProbes{}
		}
		m := probes.mounts[mount]
		if m == nil {
			m = &mountProbes{}
			probes.mounts[mount] = m
		}
		if m.outstanding < maxStuckVolumeProbes {
			m.outstanding++
			probes.Unlock()
			return &probe{}
		}
		if m.stuck > 0 {
			probes.Unlock()
			return nil
		}
		if m.freed == nil {
			m.freed = make(chan struct{})
		}
		freed := m.freed
		probes.Unlock()
		select {
		case <-freed:
		case <-deadline:
			return nil
		}
	}
}

// endProbe uncounts p, which has returned, and wakes callers waiting for a
// slot on mount.
func endProbe(mount string, p *probe) {
	probes.Lock()
	defer probes.Unlock()
	m := probes.mounts[mount]
	p.done = true
	m.outstanding--
	if p.stuck {
		m.stuck--
	}
	if m.freed != nil {
		close(m.freed)
		m.freed = nil
	}
	if m.outstanding == 0 {
		delete(probes.mounts, mount)
	}
}

// markStuck records that p outlived its caller's deadline, unless it has
// returned meanwhile.
func markStuck(mount string, p *probe) {
	probes.Lock()
	defer probes.Unlock()
	if !p.done && !p.stuck {
		p.stuck = true
		probes.mounts[mount].stuck++
	}
}

// outstandingProbes is the number of probes not yet returned, on every mount.
func outstandingProbes() int {
	probes.Lock()
	defer probes.Unlock()
	n := 0
	for _, m := range probes.mounts {
		n += m.outstanding
	}
	return n
}

// mountTableTTL is how long a read of the mount table is reused for choosing
// a path's mount. A stale table only moves a probe between counters; the
// answer for the path still comes from statfs.
const mountTableTTL = time.Second

var (
	// statfsVolume reads a path's volume; tests replace it.
	statfsVolume       = unix.Statfs
	errVolumeNoAnswer  = errors.New("its volume did not answer in time")
	errVolumeUnreached = errors.New("no part of it could be read")
)

// alias says that a path at or below from is the same as the path at or below
// to: a macOS firmlink (/Users is /System/Volumes/Data/Users) or a symbolic
// link in the root folder (/home, /var).
type alias struct{ from, to string }

// mountTable is the last read of the mount table. loaded is set once a read
// has finished; refreshing is closed when the read in flight finishes; gen
// discards a read started before forgetMountTable. readPoints lists the
// mount points without touching any mounted volume (systemMountPoints), and
// readAliases the other spellings of paths below the root (systemRootAliases:
// macOS firmlinks and the root's symbolic links); tests replace both with
// setMountReaders.
var mountTable = struct {
	sync.Mutex
	loaded      bool
	read        time.Time
	points      []string
	aliases     []alias
	refreshing  chan struct{}
	gen         int
	readPoints  func() ([]string, error)
	readAliases func() ([]alias, error)
}{readPoints: systemMountPoints, readAliases: systemRootAliases}

// mountOf names the mount whose mount point is the longest prefix of abs's
// spelling, both rewritten through the root aliases, from the mount table. It reads
// the table, never the volumes. The table is read by one goroutine at a time,
// never under a caller's lock: a stale table is used while a fresh one is
// read in the background, and before the first read finishes a caller waits
// for it only until deadline (false). A path that reaches a mount through a
// symbolic link below the root folder, or on macOS through a spelling
// differing in case from the table's, is counted against the mount its
// spelling names. With no table, every path shares the counter "".
func mountOf(abs string, deadline <-chan time.Time) (string, bool) {
	mountTable.Lock()
	stale := !mountTable.loaded || time.Since(mountTable.read) > mountTableTTL
	if stale && mountTable.refreshing == nil {
		mountTable.refreshing = make(chan struct{})
		go refreshMountTable(mountTable.refreshing, mountTable.gen, mountTable.readPoints, mountTable.readAliases)
	}
	if !mountTable.loaded {
		refreshing := mountTable.refreshing
		mountTable.Unlock()
		select {
		case <-refreshing:
		case <-deadline:
			return "", false
		}
		mountTable.Lock()
	}
	points, aliases := mountTable.points, mountTable.aliases
	mountTable.Unlock()
	abs = unalias(abs, aliases)
	best := ""
	for _, m := range points {
		if len(m) > len(best) && spelledWithin(abs, m) {
			best = m
		}
	}
	return best, true
}

// refreshMountTable reads the mount table and the root aliases and stores
// them unless forgetMountTable ran meanwhile. A failed read stores an empty
// table, so every path shares one counter until the next read.
func refreshMountTable(done chan struct{}, gen int, readPoints func() ([]string, error), readAliases func() ([]alias, error)) {
	points, err := readPoints()
	if err != nil {
		points = nil
	}
	aliases, err := readAliases()
	if err != nil {
		aliases = nil
	}
	// Mount points are spelled through aliases too (/Volumes/share is
	// /System/Volumes/Data/Volumes/share), so both sides compare in one
	// spelling.
	points = append([]string(nil), points...)
	for i, m := range points {
		points[i] = unalias(m, aliases)
	}
	mountTable.Lock()
	if mountTable.gen == gen {
		mountTable.points, mountTable.aliases = points, aliases
		mountTable.read, mountTable.loaded = time.Now(), true
	}
	if mountTable.refreshing == done {
		mountTable.refreshing = nil
	}
	mountTable.Unlock()
	close(done)
}

// unalias rewrites abs through the longest matching alias, again for the
// result, at most four times.
func unalias(abs string, aliases []alias) string {
	for range 4 {
		var best *alias
		for i := range aliases {
			if spelledWithin(abs, aliases[i].from) && (best == nil || len(aliases[i].from) > len(best.from)) {
				best = &aliases[i]
			}
		}
		if best == nil {
			return abs
		}
		abs = best.to + strings.TrimPrefix(abs, best.from)
	}
	return abs
}

// spelledWithin reports whether abs is folder or lies below it, by spelling.
func spelledWithin(abs, folder string) bool {
	return abs == folder || folder == "/" || strings.HasPrefix(abs, folder+"/")
}

// forgetMountTable makes the next mountOf read the table again and discards
// a read in flight.
func forgetMountTable() {
	mountTable.Lock()
	defer mountTable.Unlock()
	forgetMountTableLocked()
}

func forgetMountTableLocked() {
	mountTable.gen++
	mountTable.loaded = false
	mountTable.read = time.Time{}
	mountTable.points, mountTable.aliases = nil, nil
	mountTable.refreshing = nil
}

// setMountReaders is for tests: it replaces the mount table's readers (nil
// keeps one), forgets the table, and returns a function restoring both.
func setMountReaders(points func() ([]string, error), aliases func() ([]alias, error)) (restore func()) {
	mountTable.Lock()
	defer mountTable.Unlock()
	previousPoints, previousAliases := mountTable.readPoints, mountTable.readAliases
	if points != nil {
		mountTable.readPoints = points
	}
	if aliases != nil {
		mountTable.readAliases = aliases
	}
	forgetMountTableLocked()
	return func() {
		mountTable.Lock()
		defer mountTable.Unlock()
		mountTable.readPoints, mountTable.readAliases = previousPoints, previousAliases
		forgetMountTableLocked()
	}
}

var networkVolumes struct {
	sync.Mutex
	prefixes []string
}

// TreatVolumeAsNetwork is for tests, in this module and in its consumers:
// until restore is called, LocalPath refuses folder and every path below it
// as a network volume, as it refuses a volume without MNT_LOCAL on macOS and
// a network file system on Linux, so a test can show a refusal without
// mounting a share. It only ever refuses more.
func TreatVolumeAsNetwork(folder string) (restore func()) {
	abs, err := filepath.Abs(folder)
	if err != nil {
		return func() {}
	}
	abs = filepath.Clean(abs)
	networkVolumes.Lock()
	networkVolumes.prefixes = append(networkVolumes.prefixes, abs)
	networkVolumes.Unlock()
	return func() {
		networkVolumes.Lock()
		defer networkVolumes.Unlock()
		for i, p := range networkVolumes.prefixes {
			if p == abs {
				networkVolumes.prefixes = append(networkVolumes.prefixes[:i], networkVolumes.prefixes[i+1:]...)
				return
			}
		}
	}
}

func markedNetwork(abs string) bool {
	networkVolumes.Lock()
	defer networkVolumes.Unlock()
	for _, p := range networkVolumes.prefixes {
		if abs == p || strings.HasPrefix(abs, p+string(filepath.Separator)) {
			return true
		}
	}
	return false
}

// volumeLocal walks up from abs to the first path statfs can read and asks
// volumeAnswer whether that volume is local.
func volumeLocal(abs string) error {
	for p := abs; ; p = filepath.Dir(p) {
		var st unix.Statfs_t
		err := statfsVolume(p, &st)
		if err == nil {
			return volumeAnswer(p, &st)
		}
		if !errors.Is(err, unix.ENOENT) && !errors.Is(err, unix.ENOTDIR) {
			return err
		}
		if filepath.Dir(p) == p {
			return errVolumeUnreached
		}
	}
}
