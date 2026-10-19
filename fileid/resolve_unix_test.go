//go:build darwin || linux

package fileid

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func folderLink(link, target string) error { return os.Symlink(target, link) }

func TestLinkTargetClassifiedBeforePathVolumeProbe(t *testing.T) {
	dir := physicalTempDir(t)
	target := writeFile(t, filepath.Join(dir, "target"), "local")
	link := filepath.Join(dir, "link")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	previous := statfsVolume
	statfsVolume = func(path string, st *unix.Statfs_t) error {
		if path == link {
			return unix.EPERM
		}
		return previous(path, st)
	}
	defer func() { statfsVolume = previous }()
	id, err := Resolve(bg, Self, link, Options{})
	if err != nil {
		t.Fatalf("volume query followed an unclassified link: %v", err)
	}
	if !id.Equal(mustResolve(t, target, Options{})) {
		t.Fatal("link did not name the local target")
	}
}

// ".." after a symbolic link walks up from where the link led, as the
// kernel does; a cleaned spelling would name another file.
func TestDotDotAfterALinkWalksFromTheTarget(t *testing.T) {
	dir := t.TempDir()
	deep := filepath.Join(dir, "elsewhere", "deep")
	if err := os.MkdirAll(deep, 0o755); err != nil {
		t.Fatal(err)
	}
	f := writeFile(t, filepath.Join(dir, "elsewhere", "f.txt"), "x")
	if err := os.Symlink(deep, filepath.Join(dir, "link")); err != nil {
		t.Fatal(err)
	}
	got := mustResolve(t, dir+"/link/../f.txt", Options{})
	if !got.Equal(mustResolve(t, f, Options{})) {
		t.Errorf("link/../f.txt resolved to %s, want %s", got.Path(), f)
	}
}

// A name replaced by a symbolic link between the walk's stat and its open is
// refused with ErrLink, for an identity open (Linux: O_PATH, which opens the
// link itself) and for a read: the link's FileID is never the file's.
func TestANameThatBecomesALinkWhileOpenedIsRefused(t *testing.T) {
	dir := t.TempDir()
	f := writeFile(t, filepath.Join(dir, "f.txt"), "x")
	other := writeFile(t, filepath.Join(dir, "other.txt"), "y")
	for _, opt := range []Options{{}, {Read: true}} {
		swapped := false
		betweenStatAndOpen = func(here string) {
			if here != f || swapped {
				return
			}
			swapped = true
			if err := os.Remove(f); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(other, f); err != nil {
				t.Fatal(err)
			}
		}
		_, err := Resolve(bg, Self, f, opt)
		betweenStatAndOpen = nil
		if !swapped || !errors.Is(err, ErrLink) {
			t.Errorf("Resolve %+v with the name swapped for a link: %v, want ErrLink", opt, err)
		}
		if err := os.Remove(f); err != nil {
			t.Fatal(err)
		}
		writeFile(t, f, "x")
	}
}

// physicalTempDir is a new temporary folder spelled by its final path, so a
// spelling built below it names folders the walk opens by that spelling.
func physicalTempDir(t *testing.T) string {
	t.Helper()
	return mustResolve(t, t.TempDir(), Options{}).Path()
}

func mkdirs(t *testing.T, folders ...string) {
	t.Helper()
	for _, f := range folders {
		if err := os.MkdirAll(f, 0o755); err != nil {
			t.Fatal(err)
		}
	}
}

func symlink(t *testing.T, target, link string) {
	t.Helper()
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
}

// Locality follows the physical walk (ID-F3; coordinator ruling D1,
// 2026-10-21). In dir/u/lnk/../mnt/x, lnk leads to dir/deep/b, so ".." reaches
// dir/deep and the walk's next folder is dir/deep/mnt, a refused mount. The
// cleaned spelling dir/u/mnt/x is a local folder. Typed and as a relative link
// target, the path is refused before anything at or below the mount is
// opened.
func TestDotDotAfterALinkIsCheckedOnThePhysicalPath(t *testing.T) {
	dir := physicalTempDir(t)
	mount := filepath.Join(dir, "deep", "mnt")
	mkdirs(t, filepath.Join(dir, "u", "mnt"), filepath.Join(dir, "deep", "b"), mount)
	writeFile(t, filepath.Join(dir, "u", "mnt", "x"), "the cleaned spelling")
	writeFile(t, filepath.Join(mount, "x"), "below the mount")
	symlink(t, filepath.Join(dir, "deep", "b"), filepath.Join(dir, "u", "lnk"))
	symlink(t, "lnk/../mnt/x", filepath.Join(dir, "u", "evil"))
	restore := TreatVolumeAsNetwork(mount)
	defer restore()
	var opened []string
	stop, ok := ObserveOpens(func(p string) {
		if p == mount || strings.HasPrefix(p, mount+"/") {
			opened = append(opened, p)
		}
	})
	if !ok {
		t.Fatal("another observer is set")
	}
	defer stop()
	for _, p := range []string{dir + "/u/lnk/../mnt/x", filepath.Join(dir, "u", "evil")} {
		opened = nil
		id, err := Resolve(bg, Self, p, Options{})
		if !errors.Is(err, ErrNotLocalPath) {
			t.Errorf("Resolve %s = %v, %v; want ErrNotLocalPath", p, id, err)
		}
		if len(opened) > 0 {
			t.Errorf("Resolve %s opened %v at or below the refused mount", p, opened)
		}
	}
}

// A Homebrew-shaped link, bin/tool -> ../Cellar/tool/1.0/bin/tool, and one
// through a folder link, opt/tool -> ../Cellar/tool/1.0, resolve to the
// target's FileID.
func TestACellarLinkResolvesToItsTarget(t *testing.T) {
	dir := physicalTempDir(t)
	tool := writeFile(t, filepath.Join(dir, "Cellar", "tool", "1.0", "bin", "tool"), "x")
	mkdirs(t, filepath.Join(dir, "bin"), filepath.Join(dir, "opt"))
	symlink(t, "../Cellar/tool/1.0", filepath.Join(dir, "opt", "tool"))
	symlink(t, "../Cellar/tool/1.0/bin/tool", filepath.Join(dir, "bin", "tool"))
	symlink(t, "../opt/tool/bin/tool", filepath.Join(dir, "bin", "through-opt"))
	want := mustResolve(t, tool, Options{})
	for _, p := range []string{filepath.Join(dir, "bin", "tool"), filepath.Join(dir, "bin", "through-opt"), filepath.Join(dir, "opt", "tool", "bin", "tool")} {
		if got := mustResolve(t, p, Options{}); !got.Equal(want) {
			t.Errorf("Resolve %s = %s, want %s", p, got, want)
		}
	}
}

// ResolveLeaf and Pending take the folder from the walk Open runs (coordinator
// ruling D2, 2026-10-21): with a/link leading to elsewhere/deep, every
// spelling a/link/../… names a place in elsewhere, whatever a/ holds under the
// cleaned spelling.
func TestLeafAndPendingTakeTheFolderFromThePhysicalWalk(t *testing.T) {
	dir := physicalTempDir(t)
	elsewhere := filepath.Join(dir, "elsewhere")
	mkdirs(t, filepath.Join(elsewhere, "deep"), filepath.Join(dir, "a", "new"))
	f := writeFile(t, filepath.Join(elsewhere, "f"), "x")
	writeFile(t, filepath.Join(dir, "a", "f"), "the cleaned spelling")
	symlink(t, filepath.Join(elsewhere, "deep"), filepath.Join(dir, "a", "link"))
	folder := mustResolve(t, elsewhere, Options{})

	spelled := dir + "/a/link/../f"
	if got := mustResolve(t, spelled, Options{}); !got.Equal(mustResolve(t, f, Options{})) {
		t.Errorf("Resolve %s = %s, want %s", spelled, got, f)
	}
	leaf, err := ResolveLeaf(bg, Self, spelled)
	if err != nil {
		t.Fatalf("ResolveLeaf %s: %v", spelled, err)
	}
	if !leaf.Folder().Equal(folder) || leaf.Name() != "f" || leaf.Path() != f {
		t.Errorf("ResolveLeaf %s = %s in %s, want f in %s", spelled, leaf.Name(), leaf.Folder(), folder)
	}
	pending, err := Pending(bg, Self, spelled, dir)
	if err != nil {
		t.Fatalf("Pending %s: %v", spelled, err)
	}
	if want, _ := Pending(bg, Self, f, dir); pending.Key() != want.Key() || pending.Path() != f {
		t.Errorf("Pending %s = %s (%s), want %s (%s)", spelled, pending.Path(), pending.Key(), want.Path(), want.Key())
	}

	unborn := dir + "/a/link/../new/x"
	pending, err = Pending(bg, Self, unborn, dir)
	if err != nil {
		t.Fatalf("Pending %s: %v", unborn, err)
	}
	want, err := Pending(bg, Self, filepath.Join(elsewhere, "new", "x"), dir)
	if err != nil {
		t.Fatal(err)
	}
	if pending.Key() != want.Key() || pending.Path() != filepath.Join(elsewhere, "new", "x") {
		t.Errorf("Pending %s = %s (%s), want %s (%s)", unborn, pending.Path(), pending.Key(), want.Path(), want.Key())
	}
	if _, err := Resolve(bg, Self, unborn, Options{}); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("Resolve %s: %v, want not found", unborn, err)
	}
	if l, err := ResolveLeaf(bg, Self, unborn); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("ResolveLeaf %s = %s in %s, %v; want not found: elsewhere/new does not exist", unborn, l.Name(), l.Folder(), err)
	}
	if l, err := ResolveLeaf(bg, Self, dir+"/a/link/../new"); err != nil || !l.Folder().Equal(folder) || l.Name() != "new" {
		t.Errorf("ResolveLeaf a/link/../new = %s in %s, %v; want new in %s", l.Name(), l.Folder(), err, folder)
	}
}

// A symbolic link to a volume LocalPath refuses is refused before anything
// at the target is opened.
func TestALinkToANetworkVolumeIsRefused(t *testing.T) {
	dir := t.TempDir()
	remote := filepath.Join(dir, "remote")
	if err := os.Mkdir(remote, 0o755); err != nil {
		t.Fatal(err)
	}
	restore := TreatVolumeAsNetwork(remote)
	defer restore()
	if err := os.Symlink(remote, filepath.Join(dir, "link")); err != nil {
		t.Fatal(err)
	}
	if _, err := Resolve(bg, Self, filepath.Join(dir, "link", "f.txt"), Options{}); !errors.Is(err, ErrNotLocalPath) {
		t.Errorf("Resolve through a link to a network volume: %v, want ErrNotLocalPath", err)
	}
}

func TestHeldFolderRenameKeepsDescriptorObservation(t *testing.T) {
	for _, marked := range []bool{true, false} {
		label := "local"
		if marked {
			label = "refused-volume"
		}
		t.Run(label, func(t *testing.T) {
			dir := physicalTempDir(t)
			a, b := filepath.Join(dir, "a"), filepath.Join(dir, "b")
			mkdirs(t, filepath.Join(a, "x"))
			writeFile(t, filepath.Join(a, "x", "f"), "original held tree")
			if marked {
				restore := TreatVolumeAsNetwork(filepath.Join(b, "x"))
				defer restore()
			}
			renamed := false
			stop, ok := ObserveOpens(func(p string) {
				if renamed || p != filepath.Join(a, "x") {
					return
				}
				renamed = true
				if err := os.Rename(a, b); err != nil {
					t.Fatal(err)
				}
				mkdirs(t, filepath.Join(a, "x"))
				writeFile(t, filepath.Join(a, "x", "f"), "replacement spelling")
			})
			if !ok {
				t.Fatal("another observer is set")
			}
			defer stop()
			got, err := Resolve(bg, Self, filepath.Join(a, "x", "f"), Options{})
			if !renamed {
				t.Fatal("owned rename control did not execute")
			}
			if marked {
				if !errors.Is(err, ErrNotLocalPath) {
					t.Fatalf("held refused folder returned %v, %v", got, err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			actual := filepath.Join(b, "x", "f")
			if got.Path() != actual || !got.Equal(mustResolve(t, actual, Options{})) {
				t.Fatalf("held file observation %v, want current descriptor path %s", got, actual)
			}
		})
	}
}

func TestHeldFolderRenameDotDotUsesCurrentParent(t *testing.T) {
	dir := physicalTempDir(t)
	a, moved := filepath.Join(dir, "a"), filepath.Join(dir, "other", "b")
	mkdirs(t, filepath.Join(a, "x"), filepath.Dir(moved))
	writeFile(t, filepath.Join(dir, "f"), "old ancestor")
	want := writeFile(t, filepath.Join(dir, "other", "f"), "current ancestor")
	renamed := false
	stop, ok := ObserveOpens(func(p string) {
		if !renamed && p == filepath.Join(a, "x") {
			renamed = true
			if err := os.Rename(a, moved); err != nil {
				t.Fatal(err)
			}
		}
	})
	if !ok {
		t.Fatal("another observer is set")
	}
	defer stop()
	got, err := Resolve(bg, Self, a+"/x/../../f", Options{})
	if err != nil {
		t.Fatal(err)
	}
	if !renamed || got.Path() != want || !got.Equal(mustResolve(t, want, Options{})) {
		t.Fatalf("held '..' returned %v, want current parent %s", got, want)
	}
}

func TestDescriptorObservationUnavailableRefuses(t *testing.T) {
	p := writeFile(t, filepath.Join(t.TempDir(), "f"), "owned")
	fd, err := unix.Open(p, unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	previous := descriptorName
	descriptorName = func(int) (string, error) { return "", os.ErrNotExist }
	t.Cleanup(func() { descriptorName = previous })
	if _, err := describe(fd, p); !errors.Is(err, ErrNotLocalPath) {
		t.Fatalf("unavailable descriptor name: %v", err)
	}
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != unix.EBADF {
		t.Fatalf("refused description left caller-owned result fd open: %v", err)
	}
}

func TestDescriptorDeletedNamesNeedLiveIdentity(t *testing.T) {
	for _, kind := range []string{"file", "directory", "other-hardlink", "diagnostic-name-collision"} {
		t.Run(kind, func(t *testing.T) {
			dir := physicalTempDir(t)
			p := filepath.Join(dir, "held")
			if kind == "directory" {
				mkdirs(t, p)
			} else {
				writeFile(t, p, "held identity")
			}
			if kind == "other-hardlink" {
				if err := os.Link(p, filepath.Join(dir, "another-name")); err != nil {
					t.Fatal(err)
				}
			}
			if kind == "diagnostic-name-collision" {
				writeFile(t, p+" (deleted)", "a different live identity")
			}
			fd, err := unix.Open(p, unix.O_RDONLY|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.Remove(p); err != nil {
				unix.Close(fd)
				t.Fatal(err)
			}
			h, err := describe(fd, p)
			if err == nil {
				h.Close()
				t.Fatalf("unlinked descriptor produced a live locator: %s", h.FileID().Path())
			}
			if !errors.Is(err, ErrNotLocalPath) {
				t.Fatalf("unavailable descriptor locator: %v", err)
			}
		})
	}
	dir := physicalTempDir(t)
	p := writeFile(t, filepath.Join(dir, "genuine (deleted)"), "a real filename")
	got, err := Resolve(bg, Self, p, Options{})
	if err != nil || got.Path() != p {
		t.Fatalf("valid suffix filename: %v, %v", got, err)
	}
}

func TestHeldFolderBeneathAndCreateKeepTheirFence(t *testing.T) {
	dir := physicalTempDir(t)
	a, b := filepath.Join(dir, "a"), filepath.Join(dir, "b")
	mkdirs(t, a)
	writeFile(t, filepath.Join(a, "inside"), "owned")
	out := writeFile(t, filepath.Join(dir, "outside"), "outside the bound folder")
	symlink(t, out, filepath.Join(a, "link"))
	h, err := Open(bg, Self, a, Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer h.Close()
	if err := os.Rename(a, b); err != nil {
		t.Fatal(err)
	}
	if _, err := h.Beneath("../outside", Options{}); !errors.Is(err, ErrUnsafeName) {
		t.Fatalf("Beneath parent escape: %v", err)
	}
	if _, err := h.Beneath("link", Options{}); !errors.Is(err, ErrLink) {
		t.Fatalf("Beneath link escape: %v", err)
	}
	child, err := h.Beneath("inside", Options{})
	if err != nil {
		t.Fatal(err)
	}
	if child.FileID().Path() != filepath.Join(b, "inside") {
		t.Errorf("Beneath retained a stale spelling: %s", child.FileID().Path())
	}
	child.Close()
	restore := TreatVolumeAsNetwork(b)
	defer restore()
	if created, err := CreateExclusive(h, "new"); !errors.Is(err, ErrNotLocalPath) {
		created.Close()
		t.Fatalf("creation below a now-refused held folder: %v", err)
	}
	if _, err := os.Lstat(filepath.Join(b, "new")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("refused creation changed the owned folder: %v", err)
	}
}

func TestDescriptorProbeTimeoutKeepsWorkerDescriptor(t *testing.T) {
	p := writeFile(t, filepath.Join(t.TempDir(), "f"), "owned")
	fd, err := unix.Open(p, unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(fd)
	previous := fstatfsVolume
	release := make(chan struct{})
	var once sync.Once
	worker := make(chan int, 1)
	fstatfsVolume = func(duplicate int, st *unix.Statfs_t) error {
		worker <- duplicate
		<-release
		return unix.Fstatfs(duplicate, st)
	}
	t.Cleanup(func() {
		once.Do(func() { close(release) })
		waitProbesDrained()
		if outstandingProbes() != 0 {
			t.Error("descriptor worker did not drain during cleanup")
		}
		fstatfsVolume = previous
	})
	started := time.Now()
	if _, _, err := descriptorLocal(fd, p); !errors.Is(err, ErrNotLocalPath) {
		t.Fatalf("blocked descriptor probe: %v", err)
	}
	if time.Since(started) > 2*time.Second {
		t.Fatal("descriptor probe exceeded its existing deadline")
	}
	duplicate := <-worker
	if duplicate == fd {
		t.Fatal("worker borrowed the caller's descriptor")
	}
	if flags, err := unix.FcntlInt(uintptr(duplicate), unix.F_GETFD, 0); err != nil || flags&unix.FD_CLOEXEC == 0 {
		t.Fatalf("worker descriptor lacks atomic close-on-exec: flags=%d error=%v", flags, err)
	}
	var st unix.Stat_t
	if err := unix.Fstat(duplicate, &st); err != nil {
		t.Fatalf("timeout closed the running worker's descriptor: %v", err)
	}
	if n := outstandingProbes(); n != 1 {
		t.Fatalf("blocked descriptor probes=%d, want 1", n)
	}
	once.Do(func() { close(release) })
	waitProbesDrained()
	if outstandingProbes() != 0 {
		t.Fatal("descriptor worker did not drain")
	}
}

func TestDescriptorChildStatDeadlineKeepsWorkerParent(t *testing.T) {
	dir := physicalTempDir(t)
	p := writeFile(t, filepath.Join(dir, "blocked"), "owned")
	previous := fstatatEntry
	release := make(chan struct{})
	var once sync.Once
	worker := make(chan int, 1)
	fstatatEntry = func(fd int, name string, st *unix.Stat_t, flags int) error {
		if name == "blocked" {
			worker <- fd
			<-release
		}
		return previous(fd, name, st, flags)
	}
	t.Cleanup(func() {
		once.Do(func() { close(release) })
		waitProbesDrained()
		fstatatEntry = previous
	})
	var observed []string
	stop, ok := ObserveOpens(func(path string) { observed = append(observed, path) })
	if !ok {
		t.Fatal("another observer is set")
	}
	defer stop()
	started := time.Now()
	if _, err := Resolve(bg, Self, p, Options{}); !errors.Is(err, ErrNotLocalPath) {
		t.Fatalf("blocked child classification: %v", err)
	}
	if time.Since(started) > 2*time.Second {
		t.Fatal("child classification exceeded its existing deadline")
	}
	for _, path := range observed {
		if path == p {
			t.Fatal("unadmitted child was reported opened")
		}
	}
	duplicate := <-worker
	var st unix.Stat_t
	if err := unix.Fstat(duplicate, &st); err != nil {
		t.Fatalf("caller retirement closed worker parent: %v", err)
	}
	if flags, err := unix.FcntlInt(uintptr(duplicate), unix.F_GETFD, 0); err != nil || flags&unix.FD_CLOEXEC == 0 {
		t.Fatalf("worker parent lacks atomic close-on-exec: %d %v", flags, err)
	}
	if n := outstandingProbes(); n != 1 {
		t.Fatalf("blocked child probes=%d, want 1", n)
	}
	once.Do(func() { close(release) })
	waitProbesDrained()
	if outstandingProbes() != 0 {
		t.Fatal("child worker did not drain")
	}
}
