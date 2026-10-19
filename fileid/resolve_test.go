package fileid

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

var bg = context.Background()

func writeFile(t *testing.T, name, data string) string {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(name), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(name, []byte(data), 0o644); err != nil {
		t.Fatal(err)
	}
	return name
}

func mustResolve(t *testing.T, path string, opt Options) FileID {
	t.Helper()
	id, err := Resolve(bg, Self, path, opt)
	if err != nil {
		t.Fatalf("Resolve %s: %v", path, err)
	}
	return id
}

// A FileID's key is the key FileKey gives the same file, its path is the
// final spelling, and its durability, link count and kind are read from the
// handle.
func TestResolveReadsTheFileFromItsHandle(t *testing.T) {
	dir := t.TempDir()
	f := writeFile(t, filepath.Join(dir, "a file.txt"), "x")
	id := mustResolve(t, f, Options{})
	key, err := FileKey(f)
	if err != nil {
		t.Fatal(err)
	}
	if id.Key() != key {
		t.Errorf("Resolve key %s, FileKey %s", id.Key(), key)
	}
	if id.IsDir() || id.Links() != 1 || id.IsZero() {
		t.Errorf("Resolve %s = %+v, want one regular file with one name", f, id)
	}
	if !strings.EqualFold(filepath.Base(id.Path()), "a file.txt") {
		t.Errorf("Path %s, want the file's name", id.Path())
	}
	if d := mustResolve(t, dir, Options{}); !d.IsDir() {
		t.Errorf("%s is not a folder: %+v", dir, d)
	}
	if runtime.GOOS == "windows" && id.Durability() != Persistent {
		t.Errorf("an NTFS file's key is %s, want persistent", id.Durability())
	}
	t.Logf("durability %s on %s", id.Durability(), runtime.GOOS)
	if _, err := Resolve(bg, Self, filepath.Join(dir, "absent"), Options{}); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("Resolve of an absent file: %v, want fs.ErrNotExist", err)
	}
}

// Two names of one file are one FileID with two links, and containment of
// the file under each name's folder reports the second name.
func TestHardLinksAreOneFileWithTwoNames(t *testing.T) {
	dir := t.TempDir()
	a := writeFile(t, filepath.Join(dir, "folder A", "f.txt"), "x")
	b := filepath.Join(dir, "folder B", "f.txt")
	if err := os.MkdirAll(filepath.Dir(b), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(a, b); err != nil {
		t.Skip("hard links not available here:", err)
	}
	ia, ib := mustResolve(t, a, Options{}), mustResolve(t, b, Options{})
	if !ia.Equal(ib) || ia.Links() != 2 {
		t.Fatalf("%s and %s: %+v and %+v, want one file with two names", a, b, ia, ib)
	}
	hb, err := Open(bg, Self, b, Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer hb.Close()
	folderA, err := Open(bg, Self, filepath.Dir(a), Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer folderA.Close()
	r, err := hb.Relate(folderA)
	if err != nil || r.Kind != RelationOutside || !r.MultiName {
		t.Errorf("Relate(%s, folder A) = %+v, %v; want outside with more than one name", b, r, err)
	}
	ha, err := Open(bg, Self, a, Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer ha.Close()
	r, err = ha.Relate(folderA)
	if err != nil || r.Kind != RelationInside || r.Rel != "f.txt" || !r.MultiName {
		t.Errorf("Relate(%s, folder A) = %+v, %v; want inside at f.txt with more than one name", a, r, err)
	}
	if r, err := ha.Relate(hb); err != nil || r.Kind != RelationSame {
		t.Errorf("Relate of two names of one file = %+v, %v; want same", r, err)
	}
}

// A store file replaced by renaming a new file over it reads replaced; the
// same file reads same; a deleted file reads gone, and a renamed one moved
// where the platform can find a file by its ID.
func TestRevalidateTellsSameReplacedGoneAndMoved(t *testing.T) {
	dir := t.TempDir()
	f := writeFile(t, filepath.Join(dir, "store.json"), "1")
	stored, err := mustResolve(t, f, Options{}).Stored()
	if err != nil {
		t.Skip("this file system's keys are volatile:", err)
	}
	back, err := ParseStoredFileID(stored.String())
	if err != nil || back != stored {
		t.Fatalf("ParseStoredFileID(%q) = %+v, %v", stored.String(), back, err)
	}
	if _, state, err := Revalidate(bg, back); err != nil || state != StateSame {
		t.Fatalf("Revalidate of the unchanged file: %v, %v", state, err)
	}
	writeFile(t, f+".new", "2")
	if err := os.Rename(f+".new", f); err != nil {
		t.Fatal(err)
	}
	now, state, err := Revalidate(bg, stored)
	if err != nil || state != StateReplaced || now.Key() == "" {
		t.Fatalf("Revalidate after a rename-over: %v, %v, %+v; want replaced", state, err, now)
	}
	replaced, _ := now.Stored()
	moved := filepath.Join(dir, "moved.json")
	if err := os.Rename(f, moved); err != nil {
		t.Fatal(err)
	}
	got, state, err := Revalidate(bg, replaced)
	want := StateGone
	if runtime.GOOS == "windows" {
		want = StateMoved
	}
	if err != nil || state != want {
		t.Fatalf("Revalidate after a rename away: %v, %v; want %v", state, err, want)
	}
	if want == StateMoved && !strings.EqualFold(got.Path(), mustResolve(t, moved, Options{}).Path()) {
		t.Errorf("moved to %s, want %s", got.Path(), moved)
	}
	if err := os.Remove(moved); err != nil {
		t.Fatal(err)
	}
	if _, state, err := Revalidate(bg, replaced); err != nil || state != StateGone {
		t.Errorf("Revalidate after a delete: %v, %v; want gone", state, err)
	}
}

func TestStoredFileIDRefusesVolatileZeroAndMalformed(t *testing.T) {
	if _, err := (FileID{key: "1-2", path: "/x", durability: Volatile}).Stored(); !errors.Is(err, ErrVolatile) {
		t.Errorf("a volatile key stored: %v", err)
	}
	if _, err := (FileID{}).Stored(); !errors.Is(err, ErrNoFile) {
		t.Errorf("a zero FileID stored: %v", err)
	}
	if (FileID{}).Equal(FileID{}) {
		t.Error("two zero FileIDs are equal")
	}
	for _, text := range []string{"", "fileid1|", "fileid1|1-2|relative", "fileid2|1-2|/x", "fileid1|XY-2|/x", "fileid1|12|/x", "fileid1|1-2|/x\n"} {
		if _, err := ParseStoredFileID(text); err == nil {
			t.Errorf("ParseStoredFileID(%q) accepted", text)
		}
	}
	if _, _, err := Revalidate(bg, StoredFileID{}); !errors.Is(err, ErrNoFile) {
		t.Errorf("Revalidate of a zero StoredFileID: %v", err)
	}
}

// A walk under RefuseLinks refuses a link on the path; the default follows
// one to a local target and resolves the target's file.
func TestLinksFollowedOrRefusedByPolicy(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target folder")
	f := writeFile(t, filepath.Join(target, "f.txt"), "x")
	link := filepath.Join(dir, "link folder")
	if err := folderLink(link, target); err != nil {
		t.Skip("no folder link here:", err)
	}
	if got, want := mustResolve(t, filepath.Join(link, "f.txt"), Options{}), mustResolve(t, f, Options{}); !got.Equal(want) {
		t.Errorf("through the link %+v, directly %+v", got, want)
	}
	if _, err := Resolve(bg, Self, filepath.Join(link, "f.txt"), Options{Links: RefuseLinks}); !errors.Is(err, ErrLink) {
		t.Errorf("RefuseLinks through %s: %v, want ErrLink", link, err)
	}
	h, err := Open(bg, Self, dir, Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer h.Close()
	if _, err := h.Beneath(filepath.Join("link folder", "f.txt"), Options{}); !errors.Is(err, ErrLink) {
		t.Errorf("Beneath through a link: %v, want ErrLink", err)
	}
	inner, err := h.Beneath(filepath.Join("target folder", "f.txt"), Options{})
	if err != nil {
		t.Fatalf("Beneath to a plain file: %v", err)
	}
	defer inner.Close()
	if !inner.FileID().Equal(mustResolve(t, f, Options{})) {
		t.Errorf("Beneath opened %+v", inner.FileID())
	}
	for _, bad := range []string{"..", filepath.Join("target folder", ".."), "", string(filepath.Separator) + "x"} {
		if _, err := h.Beneath(bad, Options{}); !errors.Is(err, ErrUnsafeName) {
			t.Errorf("Beneath(%q): %v, want ErrUnsafeName", bad, err)
		}
	}
}

// A leaf keys by its folder and name: a folder link and the folder itself
// give one leaf, whether or not the leaf exists, and its path is spelled
// below the folder's final path.
func TestLeafKeysByFolderAndName(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target folder")
	if err := os.Mkdir(target, 0o755); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link folder")
	if err := folderLink(link, target); err != nil {
		t.Skip("no folder link here:", err)
	}
	for _, exists := range []bool{false, true} {
		if exists {
			writeFile(t, filepath.Join(target, "counter.json"), "0")
		}
		a, err := ResolveLeaf(bg, Self, filepath.Join(target, "counter.json"))
		if err != nil {
			t.Fatal(err)
		}
		b, err := ResolveLeaf(bg, Self, filepath.Join(link, "counter.json"))
		if err != nil {
			t.Fatal(err)
		}
		if a.Key() != b.Key() || a.Path() != b.Path() {
			t.Errorf("exists %v: leaf %s (%s) and %s (%s)", exists, a.Key(), a.Path(), b.Key(), b.Path())
		}
		if !a.Folder().Equal(mustResolve(t, target, Options{})) {
			t.Errorf("leaf folder %+v", a.Folder())
		}
	}
	device := "CON"
	if runtime.GOOS != "windows" {
		device = ".."
	}
	if _, err := ResolveLeaf(bg, Self, target+string(filepath.Separator)+device); err == nil {
		t.Errorf("leaf %q accepted", device)
	}
}

// A pending name keys by its stable root and the names below it, through
// any spelling of the part that exists.
func TestPendingNameKeysAcrossSpellings(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target folder")
	if err := os.Mkdir(target, 0o755); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link folder")
	if err := folderLink(link, target); err != nil {
		t.Skip("no folder link here:", err)
	}
	a, err := Pending(bg, Self, filepath.Join(target, "new", "model.gguf"))
	if err != nil {
		t.Fatal(err)
	}
	b, err := Pending(bg, Self, filepath.Join(link, "new", "model.gguf"))
	if err != nil {
		t.Fatal(err)
	}
	if a.Key() != b.Key() {
		t.Errorf("pending %s and %s", a.Key(), b.Key())
	}
	writeFile(t, filepath.Join(target, "new", "model.gguf"), "x")
	c, err := Pending(bg, Self, filepath.Join(link, "new", "model.gguf"))
	if err != nil {
		t.Fatal(err)
	}
	if c.Key() != a.Key() {
		t.Errorf("after the file was created the key %s, before %s", c.Key(), a.Key())
	}
	if !strings.HasSuffix(filepath.ToSlash(a.Path()), "target folder/new/model.gguf") {
		t.Errorf("pending path %s", a.Path())
	}
}

// Pending reads each folder above the deepest existing one as Relate does: a
// folder swapped for a link to a stable root while the anchor is sought never
// makes that root the anchor (ID-F7). The swap happens at the anchor search's
// own resolve of the folder, after the descent and the roots were resolved;
// Pending then refuses or answers the key the path had before the swap.
func TestPendingNeverAnchorsThroughALinkSwappedIn(t *testing.T) {
	dir := mustResolve(t, t.TempDir(), Options{}).Path()
	anchor := filepath.Join(dir, "anchor")
	if err := os.Mkdir(anchor, 0o755); err != nil {
		t.Fatal(err)
	}
	a := filepath.Join(dir, "a")
	if err := os.MkdirAll(filepath.Join(a, "x"), 0o755); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(a, "x", "new")
	honest, err := Pending(bg, Self, target, anchor)
	if err != nil {
		t.Fatal(err)
	}
	if strings.HasPrefix(honest.Key(), mustResolve(t, anchor, Options{}).Key()+"/") {
		t.Fatalf("before any swap the key %s is anchored at the root beside the path", honest.Key())
	}
	swapped, armed := false, false
	var swapErr error
	stop, ok := ObserveOpens(func(p string) {
		switch {
		case strings.EqualFold(filepath.Clean(p), anchor):
			armed = true
		case armed && !swapped && strings.EqualFold(filepath.Clean(p), a):
			swapped = true
			if swapErr = os.Rename(a, filepath.Join(dir, "a moved")); swapErr == nil {
				swapErr = folderLink(a, anchor)
			}
		}
	})
	if !ok {
		t.Fatal("another observer is set")
	}
	got, err := Pending(bg, Self, target, anchor)
	stop()
	t.Cleanup(func() { os.Remove(a) })
	if swapErr != nil {
		t.Skip("no folder swap here:", swapErr)
	}
	if !swapped {
		t.Fatal("the anchor search never resolved the folder by name")
	}
	t.Logf("after the swap: %v", err)
	if err != nil && !errors.Is(err, ErrLink) {
		t.Fatalf("after the swap: %v, want ErrLink", err)
	}
	if err == nil && got.Key() != honest.Key() {
		t.Errorf("a link swapped in made Pending answer %s (key %s); want a refusal or the key %s", got.Path(), got.Key(), honest.Key())
	}
}

func TestCreateExclusiveReportsACollision(t *testing.T) {
	dir := t.TempDir()
	h, err := Open(bg, Self, dir, Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer h.Close()
	f, err := CreateExclusive(h, "Model.gguf")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.File().Write([]byte("x")); err != nil {
		t.Errorf("write through the created handle: %v", err)
	}
	f.Close()
	if _, err := CreateExclusive(h, "Model.gguf"); !errors.Is(err, fs.ErrExist) {
		t.Errorf("a second create: %v, want fs.ErrExist", err)
	}
	if runtime.GOOS == "windows" {
		if _, err := CreateExclusive(h, "model.GGUF"); !errors.Is(err, fs.ErrExist) {
			t.Errorf("a create differing in case in a case-insensitive folder: %v, want fs.ErrExist", err)
		}
	}
	if _, err := CreateExclusive(h, "a:stream"); !errors.Is(err, ErrUnsafeName) {
		t.Errorf("a stream name: %v", err)
	}
}

func TestSafeName(t *testing.T) {
	for _, bad := range []string{"", ".", "..", "a/b", `a\b`, "a\x00", "x:$DATA", "name.", "name ", "CON", "con.txt", "COM¹", "lpt9.log", "CONIN$", "nul ", "Aux.json"} {
		if err := SafeName(bad); !errors.Is(err, ErrUnsafeName) {
			t.Errorf("SafeName(%q) = %v, want ErrUnsafeName", bad, err)
		}
	}
	for _, good := range []string{"model.gguf", "CONSOLE", "COM10", "lpt", "con-fig", ".hidden", "Kelvin", "café"} {
		if err := SafeName(good); err != nil {
			t.Errorf("SafeName(%q) = %v", good, err)
		}
	}
}

type otherView struct{ calls *int }

func (o otherView) SameView() error {
	*o.calls++
	return errors.New("another namespace")
}

// A peer whose view differs is refused before anything is opened, and the
// refusal matches ErrOtherView whatever error the peer gave.
func TestAnotherViewIsRefusedBeforeAnyOpen(t *testing.T) {
	f := writeFile(t, filepath.Join(t.TempDir(), "f.txt"), "x")
	opened := 0
	stop, ok := ObserveOpens(func(string) { opened++ })
	if !ok {
		t.Fatal("another observer is set")
	}
	defer stop()
	calls := 0
	peer := otherView{&calls}
	if _, err := Resolve(bg, peer, f, Options{}); !errors.Is(err, ErrOtherView) {
		t.Errorf("Resolve: %v", err)
	}
	if _, err := Pending(bg, peer, f); !errors.Is(err, ErrOtherView) {
		t.Errorf("Pending: %v", err)
	}
	if _, err := ResolveLeaf(bg, peer, f); !errors.Is(err, ErrOtherView) {
		t.Errorf("ResolveLeaf: %v", err)
	}
	if _, err := Resolve(bg, nil, f, Options{}); !errors.Is(err, ErrOtherView) {
		t.Errorf("Resolve with no peer: %v", err)
	}
	if calls != 3 || opened != 0 {
		t.Errorf("the peer was asked %d times and %d opens happened; want 3 and 0", calls, opened)
	}
}

// Relate never reads a folder through a link swapped in after the open, and
// a file that left the folder meanwhile is outside: containment authorizes
// (ID-F6), so a stale path is never an answer.
func TestRelateReadsTheFolderAboveTheFileAsItIsNow(t *testing.T) {
	dir := t.TempDir()
	granted := filepath.Join(dir, "granted")
	if err := os.Mkdir(granted, 0o755); err != nil {
		t.Fatal(err)
	}
	g, err := Open(bg, Self, granted, Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer g.Close()

	// A file that moves out of the folder after its open reads outside.
	inside := writeFile(t, filepath.Join(granted, "in.txt"), "x")
	hi, err := Open(bg, Self, inside, Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer hi.Close()
	if r, err := hi.Relate(g); err != nil || r.Kind != RelationInside || r.Rel != "in.txt" {
		t.Fatalf("a file in the folder: %+v, %v; want inside at in.txt", r, err)
	}
	if err := os.Rename(inside, filepath.Join(dir, "in.txt")); err != nil {
		t.Fatal("rename the open file:", err)
	}
	if r, err := hi.Relate(g); err != nil || r.Kind != RelationOutside {
		t.Errorf("a file moved out after its open: %+v, %v; want outside", r, err)
	}

	// The folder of a file outside is moved aside and a link to the granted
	// folder takes its name: the file's old path now reads as below the
	// granted folder. Windows refuses to rename a folder holding an open
	// file, so there the swap cannot happen.
	f := writeFile(t, filepath.Join(dir, "elsewhere", "f.txt"), "x")
	h, err := Open(bg, Self, f, Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer h.Close()
	if r, err := h.Relate(g); err != nil || r.Kind != RelationOutside {
		t.Fatalf("before the swap: %+v, %v", r, err)
	}
	if err := os.Rename(filepath.Join(dir, "elsewhere"), filepath.Join(dir, "moved")); err != nil {
		t.Skip("the folder of an open file cannot be renamed here:", err)
	}
	if err := folderLink(filepath.Join(dir, "elsewhere"), granted); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Remove(filepath.Join(dir, "elsewhere")) })
	if r, err := h.Relate(g); err != nil || r.Kind != RelationOutside {
		t.Errorf("a link swapped in above the file: %+v, %v; want outside", r, err)
	}
}

// A Handle from Open holds the access ID-F4 names: identity alone, reading
// under Options.Read, and never writing.
func TestAHandleHoldsTheAccessItNames(t *testing.T) {
	f := writeFile(t, filepath.Join(t.TempDir(), "f.txt"), "data")
	id, err := Open(bg, Self, f, Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer id.Close()
	buf := make([]byte, 4)
	if _, err := id.File().Read(buf); err == nil && runtime.GOOS != "darwin" {
		t.Errorf("an identity Handle read data")
	}
	if _, err := id.File().Write([]byte("x")); err == nil {
		t.Errorf("an identity Handle wrote")
	}
	rd, err := Open(bg, Self, f, Options{Read: true})
	if err != nil {
		t.Fatal(err)
	}
	defer rd.Close()
	if n, err := rd.File().Read(buf); err != nil || string(buf[:n]) != "data" {
		t.Errorf("a read Handle read %q, %v", buf[:n], err)
	}
	if _, err := rd.File().Write([]byte("x")); err == nil {
		t.Errorf("a read Handle wrote")
	}
}

type sameView struct{}

func (sameView) SameView() error { return nil }

// A relative path from a peer other than Self is refused before anything is
// opened: it would be read against this process's working folder, which the
// caller never named (ID-F2). Self reads a relative path from its own
// working folder.
func TestARelativePathFromAPeerIsRefusedBeforeAnyOpen(t *testing.T) {
	dir := t.TempDir()
	// Self's positive relative-path case needs a local working folder;
	// the source checkout may itself live on a refused mounted volume.
	t.Chdir(dir)
	writeFile(t, filepath.Join(dir, "f.txt"), "x")
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	rel, err := filepath.Rel(wd, filepath.Join(dir, "f.txt"))
	if err != nil {
		t.Skip("no relative spelling from the working folder:", err)
	}
	opened := 0
	stop, ok := ObserveOpens(func(string) { opened++ })
	if !ok {
		t.Fatal("another observer is set")
	}
	defer stop()
	for _, p := range []string{rel, "f.txt", "."} {
		if _, err := Resolve(bg, sameView{}, p, Options{}); !errors.Is(err, ErrUnsafeName) {
			t.Errorf("Resolve %q: %v, want ErrUnsafeName", p, err)
		}
		if _, err := Pending(bg, sameView{}, p); !errors.Is(err, ErrUnsafeName) {
			t.Errorf("Pending %q: %v, want ErrUnsafeName", p, err)
		}
		if _, err := ResolveLeaf(bg, sameView{}, p); !errors.Is(err, ErrUnsafeName) {
			t.Errorf("ResolveLeaf %q: %v, want ErrUnsafeName", p, err)
		}
	}
	if opened != 0 {
		t.Errorf("%d opens happened for a peer's relative path", opened)
	}
	stop()
	if !mustResolve(t, rel, Options{}).Equal(mustResolve(t, filepath.Join(dir, "f.txt"), Options{})) {
		t.Errorf("Self's relative %s and the absolute path name two files", rel)
	}
	if _, err := Resolve(bg, sameView{}, filepath.Join(dir, "f.txt"), Options{}); err != nil {
		t.Errorf("a peer's absolute path: %v", err)
	}
}

func TestACancelledWalkStops(t *testing.T) {
	ctx, cancel := context.WithCancel(bg)
	cancel()
	if _, err := Resolve(ctx, Self, t.TempDir(), Options{}); !errors.Is(err, context.Canceled) {
		t.Errorf("Resolve under a cancelled context: %v", err)
	}
}
