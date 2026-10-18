//go:build darwin || linux

package identity

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func stubStatfs(t *testing.T, f func(string, *unix.Statfs_t) error) {
	t.Helper()
	previous := statfsVolume
	statfsVolume = f
	t.Cleanup(func() { statfsVolume = previous })
}

// stubMountPoints replaces the mount table with points and the root aliases
// with none.
func stubMountPoints(t *testing.T, points ...string) {
	t.Helper()
	t.Cleanup(setMountReaders(
		func() ([]string, error) { return points, nil },
		func() ([]alias, error) { return nil, nil }))
}

// stubAliases replaces the root aliases until the test ends.
func stubAliases(t *testing.T, aliases ...alias) {
	t.Helper()
	t.Cleanup(setMountReaders(nil, func() ([]alias, error) { return aliases, nil }))
}

// mountName is mountOf waiting as long as the table read takes.
func mountName(p string) string {
	m, _ := mountOf(p, nil)
	return m
}

// [ID-F1] Root aliases put a path and the mount it lies on in one spelling:
// firmlinked folders count against the data volume, a root symbolic link
// against its target's mount, and a mount point spelled through a firmlink
// (/Volumes/share) keeps its own counter.
func TestMountOfFollowsRootAliases(t *testing.T) {
	stubMountPoints(t, "/", "/System/Volumes/Data", "/System/Volumes/Data/home", "/Volumes/share")
	stubAliases(t,
		alias{"/Users", "/System/Volumes/Data/Users"},
		alias{"/Volumes", "/System/Volumes/Data/Volumes"},
		alias{"/private", "/System/Volumes/Data/private"},
		alias{"/home", "/System/Volumes/Data/home"},
		alias{"/var", "/private/var"})
	for path, want := range map[string]string{
		"/Users/u/model.bin":     "/System/Volumes/Data",
		"/var/folders/x":         "/System/Volumes/Data",
		"/home/u/file":           "/System/Volumes/Data/home",
		"/Volumes/share/m.bin":   "/System/Volumes/Data/Volumes/share",
		"/Volumes/Other/m.bin":   "/System/Volumes/Data",
		"/usr/bin/true":          "/",
		"/Usersx/file":           "/",
		"/System/Volumes/Data/x": "/System/Volumes/Data",
	} {
		if got := mountName(path); got != want {
			t.Errorf("mountOf(%q) = %q, want %q", path, got, want)
		}
	}
}

// [ID-F1] A dead automounted home folder (/home, autofs below the data
// volume) does not starve /Users or the root: its paths count against its
// own mount however they are spelled.
func TestLocalPathDeadHomeDoesNotStarveFirmlinkedFolders(t *testing.T) {
	stubMountPoints(t, "/", "/System/Volumes/Data", "/System/Volumes/Data/home")
	stubAliases(t, alias{"/Users", "/System/Volumes/Data/Users"}, alias{"/home", "/System/Volumes/Data/home"})
	release := make(chan struct{})
	stubStatfs(t, func(path string, st *unix.Statfs_t) error {
		if strings.HasPrefix(path, "/home/") || strings.HasPrefix(path, "/System/Volumes/Data/home/") {
			<-release
		}
		markLocal(st)
		return nil
	})
	t.Cleanup(func() { close(release); waitProbesDrained() })
	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			p := "/home/u/file"
			if i%2 == 1 {
				p = "/System/Volumes/Data/home/u/file"
			}
			if LocalPath(p) == nil {
				t.Errorf("dead home admitted %s", p)
			}
		}(i)
	}
	wg.Wait()
	for _, p := range []string{"/Users/u/model.bin", "/usr/bin/true", "/System/Volumes/Data/Users/u/x"} {
		if err := LocalPath(p); err != nil {
			t.Errorf("LocalPath(%q) beside a dead home = %v", p, err)
		}
	}
}

// [ID-F1] A mount-table read that blocks never holds a caller past its
// deadline: before the first read finishes the caller is refused within the
// deadline, and once a table is loaded a blocked refresh runs in the
// background while callers use the loaded table.
func TestLocalPathMountTableReadThatBlocks(t *testing.T) {
	stubMountPoints(t, "/")
	stubStatfs(t, func(_ string, st *unix.Statfs_t) error { markLocal(st); return nil })
	release := make(chan struct{})
	var reads atomic.Int32
	released := false
	t.Cleanup(func() {
		if !released {
			close(release)
		}
	})
	t.Cleanup(setMountReaders(func() ([]string, error) {
		reads.Add(1)
		<-release
		return []string{"/"}, nil
	}, nil))
	begun := time.Now()
	if err := LocalPath("/home/u/model.bin"); !errors.Is(err, ErrNotLocalPath) {
		t.Fatalf("LocalPath with no mount table = %v", err)
	}
	if elapsed := time.Since(begun); elapsed > localVolumeDeadline+time.Second {
		t.Fatalf("LocalPath waited %v on a blocked mount-table read", elapsed)
	}
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); _ = LocalPath("/home/u/model.bin") }()
	}
	wg.Wait()
	if n := reads.Load(); n != 1 {
		t.Fatalf("%d mount-table reads in flight, want 1", n)
	}
	released = true
	close(release)
	if err := LocalPath("/home/u/model.bin"); err != nil {
		t.Fatalf("LocalPath once the table loaded = %v", err)
	}
	// The table is loaded; age it and block the next read.
	block := make(chan struct{})
	defer close(block)
	mountTable.Lock()
	mountTable.readPoints = func() ([]string, error) { <-block; return []string{"/"}, nil }
	mountTable.read = time.Now().Add(-2 * mountTableTTL)
	mountTable.Unlock()
	begun = time.Now()
	for i := 0; i < 4; i++ {
		if err := LocalPath("/home/u/model.bin"); err != nil {
			t.Fatalf("LocalPath during a blocked refresh = %v", err)
		}
	}
	if elapsed := time.Since(begun); elapsed > localVolumeDeadline/2 {
		t.Fatalf("a blocked refresh held callers for %v", elapsed)
	}
}

// waitProbesDrained waits, up to two seconds, for every probe to return.
func waitProbesDrained() {
	for deadline := time.Now().Add(2 * time.Second); outstandingProbes() != 0 && time.Now().Before(deadline); {
		time.Sleep(10 * time.Millisecond)
	}
}

// [ID-F1] The probe cap is kept per mount: one dead mount holding all its
// probes refuses only its own paths, and every other mount's paths are still
// probed and admitted, in a burst as well as one by one.
func TestLocalPathDeadMountDoesNotStarveOtherMounts(t *testing.T) {
	stubMountPoints(t, "/", "/mnt/dead", "/mnt/dead/nested", "/data")
	release := make(chan struct{})
	var deadStarted atomic.Int32
	stubStatfs(t, func(path string, st *unix.Statfs_t) error {
		if path == "/mnt/dead" || strings.HasPrefix(path, "/mnt/dead/") {
			deadStarted.Add(1)
			<-release
		}
		markLocal(st)
		return nil
	})
	t.Cleanup(func() { close(release); waitProbesDrained() })
	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := LocalPath("/mnt/dead/models/m.bin"); !errors.Is(err, ErrNotLocalPath) {
				t.Errorf("dead mount admitted: %v", err)
			}
		}()
	}
	wg.Wait()
	if n := deadStarted.Load(); n > maxStuckVolumeProbes {
		t.Fatalf("%d probes started on the dead mount, cap %d", n, maxStuckVolumeProbes)
	}
	if n := outstandingProbes(); n != maxStuckVolumeProbes {
		t.Fatalf("%d probes outstanding, want the dead mount's %d", n, maxStuckVolumeProbes)
	}
	for _, p := range []string{"/home/u/model.bin", "/data/models/m.bin", "/mnt/other/file", "/mnt/deadline/file"} {
		begun := time.Now()
		if err := LocalPath(p); err != nil {
			t.Errorf("LocalPath(%q) beside a dead mount = %v", p, err)
		}
		if time.Since(begun) > localVolumeDeadline/2 {
			t.Errorf("LocalPath(%q) waited %v", p, time.Since(begun))
		}
	}
	var refused atomic.Int32
	for i := 0; i < 64; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if LocalPath("/data/models/m.bin") != nil {
				refused.Add(1)
			}
		}()
	}
	wg.Wait()
	if n := refused.Load(); n != 0 {
		t.Fatalf("%d of 64 local paths refused while another mount was dead", n)
	}
}

// [ID-F1] A burst on a healthy mount larger than the cap waits for slots
// within the deadline and is admitted; the cap never refuses a mount that
// answers.
func TestLocalPathBurstOnAHealthyMountWaitsForSlots(t *testing.T) {
	stubMountPoints(t, "/")
	var current, peak atomic.Int32
	stubStatfs(t, func(_ string, st *unix.Statfs_t) error {
		n := current.Add(1)
		for p := peak.Load(); n > p && !peak.CompareAndSwap(p, n); p = peak.Load() {
		}
		time.Sleep(20 * time.Millisecond)
		current.Add(-1)
		markLocal(st)
		return nil
	})
	var wg sync.WaitGroup
	var refused atomic.Int32
	for i := 0; i < 64; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if LocalPath("/home/u/model.bin") != nil {
				refused.Add(1)
			}
		}()
	}
	wg.Wait()
	if n := refused.Load(); n != 0 {
		t.Fatalf("%d of 64 paths on a healthy mount refused", n)
	}
	if p := peak.Load(); p > maxStuckVolumeProbes {
		t.Fatalf("%d probes outstanding at once, cap %d", p, maxStuckVolumeProbes)
	}
}

// mountOf picks the longest mount point that is a whole-component prefix.
func TestMountOfPicksTheLongestMountPoint(t *testing.T) {
	stubMountPoints(t, "/", "/mnt/a", "/mnt/a/b", "/mnt/ab")
	for path, want := range map[string]string{
		"/": "/", "/etc/x": "/", "/mnt/a": "/mnt/a", "/mnt/a/x": "/mnt/a",
		"/mnt/a/b/c": "/mnt/a/b", "/mnt/ab/c": "/mnt/ab", "/mnt/abc": "/",
	} {
		if got := mountName(path); got != want {
			t.Errorf("mountOf(%q) = %q, want %q", path, got, want)
		}
	}
}

// [ID-F1] A volume that does not answer (a dead mount) is refused within the
// deadline. A concurrent burst against it never has more than
// maxStuckVolumeProbes statfs calls outstanding, and every call past that is
// refused at once.
func TestLocalPathBoundsADeadMount(t *testing.T) {
	stubMountPoints(t, "/", "/Volumes/dead")
	release := make(chan struct{})
	var current, peak, started atomic.Int32
	stubStatfs(t, func(string, *unix.Statfs_t) error {
		started.Add(1)
		n := current.Add(1)
		for p := peak.Load(); n > p && !peak.CompareAndSwap(p, n); p = peak.Load() {
		}
		<-release
		current.Add(-1)
		return nil
	})
	released := false
	drain := func() {
		if !released {
			released = true
			close(release)
		}
		for deadline := time.Now().Add(2 * time.Second); outstandingProbes() != 0 && time.Now().Before(deadline); {
			time.Sleep(10 * time.Millisecond)
		}
	}
	t.Cleanup(drain)
	start := time.Now()
	if err := LocalPath("/Volumes/dead/program"); !errors.Is(err, ErrNotLocalPath) {
		t.Fatalf("dead mount admitted: %v", err)
	}
	if elapsed := time.Since(start); elapsed > localVolumeDeadline+time.Second {
		t.Fatalf("LocalPath waited %v on a dead mount", elapsed)
	}
	const burst = 64
	var wg sync.WaitGroup
	var refusedAtOnce atomic.Int32
	for i := 0; i < burst; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			began := time.Now()
			if err := LocalPath("/Volumes/dead/program"); !errors.Is(err, ErrNotLocalPath) {
				t.Errorf("dead mount admitted in the burst: %v", err)
			}
			if time.Since(began) < localVolumeDeadline/2 {
				refusedAtOnce.Add(1)
			}
		}()
	}
	wg.Wait()
	if p := peak.Load(); p > maxStuckVolumeProbes {
		t.Fatalf("%d statfs calls were outstanding at once, cap %d", p, maxStuckVolumeProbes)
	}
	if s := started.Load(); s > maxStuckVolumeProbes {
		t.Fatalf("%d statfs calls started against a dead mount, cap %d", s, maxStuckVolumeProbes)
	}
	if refusedAtOnce.Load() < burst-maxStuckVolumeProbes {
		t.Fatalf("only %d of %d calls past the cap were refused at once", refusedAtOnce.Load(), burst)
	}
	drain()
	if n := outstandingProbes(); n != 0 {
		t.Fatalf("%d probes still counted after statfs returned", n)
	}
}

// [ID-F1] Inside answers false for a refused path, even one spelled below a
// refused folder; the spelling comparison is only for a folder that does not
// exist yet.
func TestInsideFailsClosedOnRefusedVolumes(t *testing.T) {
	dir := t.TempDir()
	share := filepath.Join(dir, "share")
	if err := os.MkdirAll(share, 0o700); err != nil {
		t.Fatal(err)
	}
	future := filepath.Join(dir, "future")
	if !Inside(filepath.Join(future, "app"), future) {
		t.Fatal("a path spelled below a folder not created yet is not inside it")
	}
	restore := TreatVolumeAsNetwork(share)
	defer restore()
	if Inside(filepath.Join(share, "app"), share) || Inside(filepath.Join(share, "new", "app"), filepath.Join(share, "new")) {
		t.Fatal("Inside placed a path on a refused volume by spelling")
	}
	restore()
	if !Inside(filepath.Join(share, "app"), share) {
		t.Fatal("the restored local folder no longer holds its child")
	}
}
