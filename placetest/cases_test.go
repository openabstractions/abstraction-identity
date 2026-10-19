package placetest_test

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	identity "github.com/openabstractions/abstraction-identity"
	"github.com/openabstractions/abstraction-identity/fileid"
	"github.com/openabstractions/abstraction-identity/internal/personfolders"
	"github.com/openabstractions/abstraction-identity/placetest"
)

var shortTempReason string

// TestMain puts TEMP and TMP on the 8.3 alias first, so the per-user folder
// stand-in (personfolders.Main) is made below it too; the factory starts
// cmd, fsutil and compact, which inherit both.
func TestMain(m *testing.M) {
	restore, err := shortTemp()
	if err != nil {
		shortTempReason = err.Error()
	}
	code := personfolders.Main(m)
	restore()
	os.Exit(code)
}

// shortTemp points TEMP and TMP at the 8.3 alias of a new long, spaced folder
// below the current temporary folder, as the hosted runner's RUNNER~1 does.
// restore removes the folder and puts the variables back. When the volume
// has no short names it returns the reason and changes nothing.
func shortTemp() (restore func(), err error) {
	long, err := placetest.Root(os.TempDir())
	if err != nil {
		return func() {}, err
	}
	short, err := placetest.ShortName(long)
	if err != nil {
		os.RemoveAll(long)
		return func() {}, err
	}
	oldTemp, oldTmp := os.Getenv("TEMP"), os.Getenv("TMP")
	os.Setenv("TEMP", short)
	os.Setenv("TMP", short)
	return func() {
		os.Setenv("TEMP", oldTemp)
		os.Setenv("TMP", oldTmp)
		os.RemoveAll(long)
	}, nil
}

// fixture is what a setup builds: two locators, and for FileKey and the
// rename-over rows a change applied between the two reads.
type fixture struct {
	a, b   string
	change func() error
}

type skip string

// throughDotDot spells dir/x/../name by concatenation, since filepath.Join
// cleans the dot-dot step away, and makes dir/x so the step resolves on
// every platform.
func throughDotDot(t *testing.T, dir, name string) string {
	t.Helper()
	if err := os.MkdirAll(filepath.Join(dir, "x"), 0o755); err != nil {
		t.Fatal(err)
	}
	sep := string(os.PathSeparator)
	spelling := dir + sep + "x" + sep + ".." + sep + name
	if !strings.Contains(spelling, sep+".."+sep) {
		t.Fatalf("%s lost its dot-dot step", spelling)
	}
	return spelling
}

func write(t *testing.T, name string) string {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(name), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(name, []byte("fixture"), 0o644); err != nil {
		t.Fatal(err)
	}
	return name
}

// distinctNameFiles builds the two physical files required by the Unicode
// rows. The volume decides whether it can hold both spellings. A collision
// skips only when native file identity confirms the spellings are aliases.
func distinctNameFiles(a, b string) (fixture, skip, error) {
	if err := os.WriteFile(a, []byte("fixture"), 0o644); err != nil {
		return fixture{}, "", err
	}
	f, createErr := os.OpenFile(b, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o644)
	if createErr != nil && !errors.Is(createErr, fs.ErrExist) {
		return fixture{}, "", createErr
	}
	if f != nil {
		if err := f.Close(); err != nil {
			return fixture{}, "", err
		}
	}
	left, err := os.Stat(a)
	if err != nil {
		return fixture{}, "", err
	}
	right, err := os.Stat(b)
	if err != nil {
		return fixture{}, "", err
	}
	if os.SameFile(left, right) {
		if errors.Is(createErr, fs.ErrExist) {
			return fixture{}, skip(fmt.Sprintf("volume aliases %q and %q; this row requires distinct files", a, b)), nil
		}
		return fixture{}, "", fmt.Errorf("exclusive creation of %q produced the same file as %q", b, a)
	}
	if createErr != nil {
		return fixture{}, "", createErr
	}
	return fixture{a: a, b: b}, "", nil
}

func build(t *testing.T, c placetest.Case) (fixture, skip) {
	root, err := placetest.Root(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	switch c.Setup {
	case "short-alias":
		long := write(t, filepath.Join(root, "Long Named Child Folder", "model file.gguf"))
		short, err := placetest.ShortName(long)
		if err != nil {
			return fixture{}, skip(err.Error())
		}
		return fixture{a: long, b: short}, ""
	case "short-temp":
		if shortTempReason != "" {
			return fixture{}, skip(shortTempReason)
		}
		f := write(t, filepath.Join(t.TempDir(), "temp file.txt"))
		if !identity.HasShortNameComponent(f) {
			return fixture{}, skip("TEMP is not on a short alias")
		}
		long, err := placetest.LongPath(f)
		if err != nil {
			t.Fatal(err)
		}
		return fixture{a: f, b: long}, ""
	case "case-twins":
		dir := filepath.Join(root, "twins")
		if err := os.Mkdir(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := placetest.CaseSensitive(dir); err != nil {
			return fixture{}, skip(err.Error())
		}
		return fixture{a: write(t, filepath.Join(dir, "Model.gguf")), b: write(t, filepath.Join(dir, "model.gguf"))}, ""
	case "names":
		return fixture{a: filepath.Join(root, "Model.gguf"), b: filepath.Join(root, "model.gguf")}, ""
	case "kelvin":
		f, why, err := distinctNameFiles(filepath.Join(root, "Kelvin"), filepath.Join(root, "kelvin"))
		if err != nil {
			t.Fatal(err)
		}
		return f, why
	case "nfc-nfd":
		f, why, err := distinctNameFiles(filepath.Join(root, "café"), filepath.Join(root, "café"))
		if err != nil {
			t.Fatal(err)
		}
		return f, why
	case "junction":
		target := filepath.Join(root, "target folder")
		f := write(t, filepath.Join(target, "file.txt"))
		link := filepath.Join(root, "junction folder")
		if err := placetest.Junction(link, target); err != nil {
			return fixture{}, skip(err.Error())
		}
		if c.Op == "Within" {
			return fixture{a: filepath.Join(link, "file.txt"), b: target}, ""
		}
		return fixture{a: filepath.Join(link, "file.txt"), b: f}, ""
	case "symlink":
		target := filepath.Join(root, "target folder")
		f := write(t, filepath.Join(target, "file.txt"))
		link := filepath.Join(root, "link folder")
		if err := placetest.FolderSymlink(link, target); err != nil {
			return fixture{}, skip("symbolic link not allowed here: " + err.Error())
		}
		return fixture{a: filepath.Join(link, "file.txt"), b: f}, ""
	case "symlink-share":
		// The link's target is a share of the TEST-NET host; making the link
		// opens nothing (FolderSymlink), and the row's op stops every open
		// below the link before it happens.
		link := filepath.Join(root, "share link")
		if err := placetest.FolderSymlink(link, placetest.TestNetShare("", false)); err != nil {
			return fixture{}, skip("symbolic link not allowed here: " + err.Error())
		}
		return fixture{a: filepath.Join(link, "file.txt"), b: link}, ""
	case "junction-share":
		link := filepath.Join(root, "share junction")
		if err := placetest.ShareJunction(link); err != nil {
			return fixture{}, skip(err.Error())
		}
		// Remove the junction itself before the folder is removed, so no
		// cleanup lists the share through it.
		t.Cleanup(func() {
			if err := os.Remove(link); err != nil {
				t.Errorf("remove the share junction: %v", err)
			}
		})
		return fixture{a: filepath.Join(link, "file.txt"), b: link}, ""
	case "hardlink":
		fa := write(t, filepath.Join(root, "folder A", "file.txt"))
		fb := filepath.Join(root, "folder B", "file.txt")
		if err := os.MkdirAll(filepath.Dir(fb), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.Link(fa, fb); err != nil {
			return fixture{}, skip(err.Error())
		}
		if c.Op == "Within" {
			return fixture{a: fb, b: filepath.Dir(fa)}, ""
		}
		return fixture{a: fa, b: fb}, ""
	case "rename-over", "inode-reuse":
		// A store keeps a StoredFileID only on a file system whose keys
		// survive a reboot; /tmp is tmpfs on several Linux systems and WSL.
		store, volatile := persistentRoot(t)
		if volatile != "" && c.Op == "Revalidate" {
			return fixture{}, skip("no folder whose file IDs survive a reboot: " + volatile)
		}
		if volatile == "" {
			root = store
		}
		f := write(t, filepath.Join(root, "store.json"))
		change := func() error {
			next := filepath.Join(root, "store.json.new")
			if err := os.WriteFile(next, []byte("next"), 0o644); err != nil {
				return err
			}
			return os.Rename(next, f)
		}
		if c.Setup == "inode-reuse" {
			change = func() error {
				if err := os.Remove(f); err != nil {
					return err
				}
				return os.WriteFile(f, []byte("next"), 0o644)
			}
		}
		return fixture{a: f, b: f, change: change}, ""
	case "long-path":
		dir := root
		for len(dir) < 300 {
			dir = filepath.Join(dir, "a long folder name with spaces")
		}
		// A Go process is long-path aware whatever LongPathsEnabled says (the
		// runtime sets the process flag), so this row ignores the setting.
		f := write(t, filepath.Join(dir, "file.txt"))
		return fixture{a: f, b: throughDotDot(t, dir, "file.txt")}, ""
	case "dot-dot":
		f := write(t, filepath.Join(root, "file.txt"))
		return fixture{a: throughDotDot(t, root, "file.txt"), b: f}, ""
	case "non-ascii-root":
		f := write(t, filepath.Join(root, "Ünïcødé 名前 folder", "file.txt"))
		return fixture{a: f, b: f}, ""
	case "spaces":
		f := write(t, filepath.Join(root, "a spaced folder", "a spaced file.txt"))
		return fixture{a: f, b: f}, ""
	case "share", "share-extended":
		return fixture{a: placetest.TestNetShare(`scratch\file.txt`, c.Setup == "share-extended")}, ""
	case "reserved":
		name := "CONIN$"
		if strings.Contains(c.A, "SUPERSCRIPT") {
			name = "COM¹"
		}
		return fixture{a: filepath.Join(root, name)}, ""
	case "stream":
		f := write(t, filepath.Join(root, "file.txt"))
		return fixture{a: f + "::$DATA", b: f}, ""
	case "stream-program":
		p := write(t, filepath.Join(root, "p.exe"))
		if err := os.WriteFile(p+":evil.exe", []byte("other code"), 0o644); err != nil {
			return fixture{}, skip("this volume keeps no alternate streams: " + err.Error())
		}
		return fixture{a: p + ":evil.exe", b: p}, ""
	case "stream-ads", "junction-stream":
		// Every open below the fixture's root is stopped, so the row shows
		// the refusal comes before the stream is opened; a junction itself
		// may be opened and read.
		f := write(t, filepath.Join(root, "file.txt"))
		if err := os.WriteFile(f+":ads", []byte("hidden"), 0o644); err != nil {
			return fixture{}, skip("this volume keeps no alternate streams: " + err.Error())
		}
		if c.Setup == "stream-ads" {
			return fixture{a: f + ":ads", b: root}, ""
		}
		link := filepath.Join(root, "stream junction")
		if err := placetest.MountPoint(link, `\??\`+f+":ads", f+":ads"); err != nil {
			return fixture{}, skip(err.Error())
		}
		t.Cleanup(func() { os.Remove(link) })
		return fixture{a: link, b: link}, ""
	case "guid-mount":
		f := write(t, filepath.Join(root, "target folder", "file.txt"))
		link := filepath.Join(root, "volume mount")
		if _, err := placetest.VolumeMountPoint(link, filepath.Dir(f)); err != nil {
			return fixture{}, skip(err.Error())
		}
		t.Cleanup(func() { os.Remove(link) })
		return fixture{a: filepath.Join(link, "file.txt"), b: f}, ""
	case "relate-inside":
		f := write(t, filepath.Join(root, "folder", "file.txt"))
		return fixture{a: f, b: filepath.Dir(f)}, ""
	case "relate-moved":
		f := write(t, filepath.Join(root, "folder", "file.txt"))
		return fixture{a: f, b: filepath.Dir(f), change: func() error { return os.Rename(f, filepath.Join(root, "file.txt")) }}, ""
	case "trailing":
		return fixture{a: filepath.Join(root, "name."), b: filepath.Join(root, "name")}, ""
	case "trailing-space":
		return fixture{a: filepath.Join(root, "name "), b: filepath.Join(root, "name")}, ""
	case "wof":
		f := write(t, filepath.Join(root, "compressed.bin"))
		if err := placetest.Compact(f); err != nil {
			return fixture{}, skip(err.Error())
		}
		return fixture{a: f, b: f}, ""
	case "sid-alias":
		admin, err := placetest.MachineAdministratorSID()
		if err != nil {
			return fixture{}, skip(err.Error())
		}
		return fixture{a: "LA", b: admin}, ""
	case "drvfs":
		if _, err := os.Stat("/mnt/c/Windows"); err != nil {
			return fixture{}, skip("not WSL with /mnt/c")
		}
		return fixture{a: "/mnt/c/Windows"}, ""
	}
	return fixture{}, skip("no factory for setup " + c.Setup)
}

// persistentRoot returns a new folder, removed when the test ends, on a file
// system whose file IDs survive a reboot (fileid.Persistent): the test's
// temporary folder, else one in the working folder, the module's checkout
// (the home folder is a stand-in below the temporary folder in tests). When
// none is persistent it returns "" and why.
func persistentRoot(t *testing.T) (string, string) {
	t.Helper()
	candidates := []func() (string, error){
		func() (string, error) { return t.TempDir(), nil },
		func() (string, error) { return os.MkdirTemp(".", ".placetest-store-") },
	}
	var why []string
	for i, mk := range candidates {
		dir, err := mk()
		if err != nil {
			why = append(why, err.Error())
			continue
		}
		if i > 0 {
			t.Cleanup(func() { os.RemoveAll(dir) })
		}
		abs, err := filepath.Abs(dir)
		if err != nil {
			why = append(why, err.Error())
			continue
		}
		id, err := fileid.Resolve(context.Background(), fileid.Self, abs, fileid.Options{})
		if err == nil && id.Durability() == fileid.Persistent {
			return abs, ""
		}
		why = append(why, fmt.Sprintf("%s: %v %v", abs, id.Durability(), err))
	}
	return "", strings.Join(why, "; ")
}

func answer(err error, refused, ok, no string, yes bool) string {
	switch {
	case errors.Is(err, identity.ErrNotLocalPath), errors.Is(err, fileid.ErrUnsafeName):
		return "refused"
	case err != nil && refused != "" && strings.Contains(err.Error(), refused):
		return "refused"
	case err != nil:
		return "error: " + err.Error()
	case yes:
		return ok
	}
	return no
}

var errOpened = errors.New("placetest: an open reached the system")

// guarded runs op with identity's open observer set. An open of a path below
// stop, or of any path when stop is empty, is stopped before it reaches the
// system: the observer panics, and guarded recovers and answers errOpened.
// stop itself, a link, may be opened without being followed. A row that
// names a share therefore contacts no host even when the code under test
// would open it.
func guarded(t *testing.T, stop string, op func() error) (err error) {
	t.Helper()
	stopObserving, ok := identity.ObserveOpens(func(path string) {
		if stop == "" || strings.HasPrefix(path, stop+string(filepath.Separator)) {
			panic(errOpened)
		}
	})
	if !ok {
		t.Fatal("another open observer is set")
	}
	defer stopObserving()
	defer func() {
		if r := recover(); r != nil {
			if r != errOpened {
				panic(r)
			}
			err = errOpened
		}
	}()
	return op()
}

func run(t *testing.T, c placetest.Case, f fixture) string {
	switch c.Op {
	case "SameFile":
		same, err := identity.SameFile(f.a, f.b)
		return answer(err, "", "same", "different", same)
	case "Within":
		in, err := identity.Within(f.a, f.b)
		return answer(err, "", "within", "outside", in)
	case "Relate":
		// Before fileid a caller asked SameFile, then Within, of the two
		// spellings after the setup's change.
		if f.change != nil {
			if err := f.change(); err != nil {
				t.Fatal(err)
			}
		}
		if same, err := identity.SameFile(f.a, f.b); err == nil && same {
			return "same"
		}
		in, err := identity.Within(f.a, f.b)
		return answer(err, "", "inside", "outside", in)
	case "PlaceKey":
		ka, err := identity.PlaceKey(f.a)
		if err != nil || f.b == "" && f.change == nil {
			return answer(err, "reserved", "local", "", true)
		}
		if f.change != nil {
			if err := f.change(); err != nil {
				t.Fatal(err)
			}
		}
		kb, err := identity.PlaceKey(f.b)
		return answer(err, "reserved", "same", "different", ka == kb)
	case "FileKey":
		ka, err := identity.FileKey(f.a)
		if err != nil {
			return answer(err, "", "", "", false)
		}
		if err := f.change(); err != nil {
			t.Fatal(err)
		}
		kb, err := identity.FileKey(f.a)
		return answer(err, "", "same", "different", ka == kb)
	case "SamePathName":
		if identity.SamePathName(f.a, f.b) {
			return "same"
		}
		return "different"
	case "SameSubjectProgram":
		if identity.SameSubjectProgram(f.a, f.b) {
			return "same"
		}
		return "different"
	case "ValidSubjectProgram":
		if identity.ValidSubjectProgram(f.a) {
			return "valid"
		}
		return "invalid"
	case "LocalPath":
		return answer(guarded(t, f.b, func() error { return identity.LocalPath(f.a) }), "", "local", "", true)
	case "Open":
		// Today's owner keys an existing file by opening it, links followed
		// (FileKey); the observer stops the open below the link before it
		// reaches the system, so the row contacts no host.
		err := guarded(t, f.b, func() error { _, err := identity.FileKey(f.a); return err })
		if errors.Is(err, errOpened) {
			return "opens"
		}
		// An error's text names the scratch folder, so the row records the
		// word and the log keeps the text.
		got := answer(err, "", "resolves", "", true)
		if strings.HasPrefix(got, "error: ") {
			t.Logf("%s: %s", c.ID, got)
			return "error"
		}
		return got
	case "Kind":
		// Before fileid, a caller asked os.Lstat what a path is.
		info, err := os.Lstat(f.a)
		switch {
		case err != nil:
			return answer(err, "", "", "", false)
		case info.Mode()&os.ModeSymlink != 0:
			return "link"
		case info.IsDir():
			return "folder"
		}
		return "regular file"
	case "Revalidate":
		// A store keeps today's PlaceKey and compares it on its next read.
		ka, err := identity.PlaceKey(f.a)
		if err != nil {
			return answer(err, "", "", "", false)
		}
		if err := f.change(); err != nil {
			t.Fatal(err)
		}
		kb, err := identity.PlaceKey(f.a)
		return answer(err, "", "same", "replaced", ka == kb)
	case "SameSID":
		same, err := placetest.SameSID(f.a, f.b)
		return answer(err, "", "same", "different", same)
	case "SIDString":
		if f.a == f.b {
			return "same"
		}
		return "different"
	}
	t.Fatalf("unknown op %q", c.Op)
	return ""
}

// TestCases records today's identity answers for every row of cases.json on
// this platform. A row whose answer changes fails, so PT-3 changes a row's
// current answer on purpose; a row that fails today must cite its cause.
func TestCases(t *testing.T) {
	table, name, err := placetest.Load()
	if errors.Is(err, placetest.ErrNoTable) {
		t.Skip(err)
	}
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for _, c := range table.Rows {
		if seen[c.ID] {
			t.Errorf("%s: duplicate row id %s", name, c.ID)
		}
		seen[c.ID] = true
		if c.Current != c.Want && c.Current != "observed" && c.Cites == "" {
			t.Errorf("%s: row %s fails today (%s, want %s) and cites no hiccup or commit", name, c.ID, c.Current, c.Want)
		}
		if c.Platform == "darwin" && !strings.Contains(c.Skip, "owner's Mac") {
			t.Errorf("%s: macOS row %s must name the owner's Mac as its pending run", name, c.ID)
		}
		observed := c.Basis == "observed" || strings.HasPrefix(c.Basis, "observed: ")
		if !observed && !strings.HasPrefix(c.Basis, "inferred: ") {
			t.Errorf("%s: row %s has basis %q, want observed or inferred: <source>", name, c.ID, c.Basis)
		}
		if c.Skip != "" && observed {
			t.Errorf("%s: row %s never runs, so its current answer is inferred, not observed", name, c.ID)
		}
		c := c
		t.Run(c.ID, func(t *testing.T) {
			if !c.ForThisPlatform() {
				t.Skipf("platform %s, running on %s", c.Platform, runtime.GOOS)
			}
			if c.Skip != "" {
				t.Skip(c.Skip)
			}
			if c.External != nil {
				t.Skip("runs in its own module: py -3.12 scripts/file_boundary_testkit.py --external")
			}
			if why := elsewhere(c); why != "" {
				t.Skip(why)
			}
			f, why := build(t, c)
			if why != "" {
				t.Skip(string(why))
			}
			got := run(t, c, f)
			if c.Current == "observed" {
				t.Logf("%s: observed %s (want %s)", c.ID, got, c.Want)
				return
			}
			if got != c.Current {
				t.Errorf("%s %s(%q, %q) = %s, recorded current answer %s", c.ID, c.Op, f.a, f.b, got, c.Current)
			}
		})
	}
}

// elsewhere names the test that runs a row this runner does not: a caller
// row needs a synthetic identity.Peer, whose fields only identity's own
// tests can set; a synthetic reparse row needs fileid's classifier; and a
// row whose fixture changes the walk between two of its reads needs fileid's
// own seams.
func elsewhere(c placetest.Case) string {
	switch c.Setup {
	case "caller", "caller-relative":
		return "runs in abstraction-identity's own tests (TestCallerRowsOfCasesJSON), which build the peer"
	case "cloud-synthetic":
		return "runs in fileid's own tests (TestSyntheticRowsOfCasesJSON), which classify the attributes"
	case "folder-mount-named", "data-tag-swap":
		return "runs in fileid's own tests (TestSeamRowsOfCasesJSON), which name a folder through its mount point or swap an entry between two opens"
	}
	return ""
}

// ownerOps are the ops fileid's resolver answers; their want is the owner's
// answer.
var ownerOps = map[string]bool{"SameFile": true, "Within": true, "FileKey": true, "PlaceKey": true,
	"Open": true, "Revalidate": true, "LocalPath": true, "Kind": true, "Relate": true}

// owner answers a row through fileid's resolver: Resolve and Open in this
// process's view, Relate, Pending and Revalidate.
func owner(t *testing.T, c placetest.Case, f fixture) string {
	ctx := context.Background()
	resolve := func(p string) (fileid.FileID, error) { return fileid.Resolve(ctx, fileid.Self, p, fileid.Options{}) }
	switch c.Op {
	case "SameFile":
		a, err := resolve(f.a)
		if err != nil {
			return answer(err, "", "", "", false)
		}
		b, err := resolve(f.b)
		return answer(err, "", "same", "different", a.Equal(b))
	case "Within":
		a, err := fileid.Open(ctx, fileid.Self, f.a, fileid.Options{})
		if err != nil {
			return answer(err, "", "", "", false)
		}
		defer a.Close()
		b, err := fileid.Open(ctx, fileid.Self, f.b, fileid.Options{})
		if err != nil {
			return answer(err, "", "", "", false)
		}
		defer b.Close()
		r, err := a.Relate(b)
		return answer(err, "", "within", "outside", r.Kind == fileid.RelationInside)
	case "Relate":
		// Both files are opened, then the setup's change runs, then Relate
		// answers from the handles.
		a, err := fileid.Open(ctx, fileid.Self, f.a, fileid.Options{})
		if err != nil {
			return answer(err, "", "", "", false)
		}
		defer a.Close()
		b, err := fileid.Open(ctx, fileid.Self, f.b, fileid.Options{})
		if err != nil {
			return answer(err, "", "", "", false)
		}
		defer b.Close()
		if f.change != nil {
			if err := f.change(); err != nil {
				t.Fatal(err)
			}
		}
		r, err := a.Relate(b)
		if err != nil {
			return answer(err, "", "", "", false)
		}
		return r.Kind.String()
	case "FileKey":
		a, err := resolve(f.a)
		if err != nil {
			return answer(err, "", "", "", false)
		}
		if err := f.change(); err != nil {
			t.Fatal(err)
		}
		b, err := resolve(f.a)
		return answer(err, "", "same", "different", a.Equal(b))
	case "PlaceKey":
		ka, err := fileid.Pending(ctx, fileid.Self, f.a)
		if err != nil || f.b == "" && f.change == nil {
			return answer(err, "reserved", "local", "", true)
		}
		if f.change != nil {
			if err := f.change(); err != nil {
				t.Fatal(err)
			}
		}
		kb, err := fileid.Pending(ctx, fileid.Self, f.b)
		return answer(err, "reserved", "same", "different", ka.Key() == kb.Key())
	case "Open":
		err := guarded(t, f.b, func() error { _, err := resolve(f.a); return err })
		if errors.Is(err, errOpened) {
			return "opens"
		}
		return answer(err, "", "resolves", "", true)
	case "Revalidate":
		a, err := resolve(f.a)
		if err != nil {
			return answer(err, "", "", "", false)
		}
		stored, err := a.Stored()
		if err != nil {
			return answer(err, "", "", "", false)
		}
		if err := f.change(); err != nil {
			t.Fatal(err)
		}
		_, state, err := fileid.Revalidate(ctx, stored)
		if err != nil {
			return answer(err, "", "", "", false)
		}
		return state.String()
	case "LocalPath":
		return answer(guarded(t, f.b, func() error { return fileid.LocalPath(f.a) }), "", "local", "", true)
	case "Kind":
		h, err := fileid.Open(ctx, fileid.Self, f.a, fileid.Options{Links: fileid.RefuseLinks})
		if errors.Is(err, fileid.ErrLink) {
			return "link"
		}
		if err != nil {
			return answer(err, "", "", "", false)
		}
		defer h.Close()
		if h.FileID().IsDir() {
			return "folder"
		}
		return "regular file"
	}
	t.Fatalf("op %q is not the owner's", c.Op)
	return ""
}

// TestCasesThroughTheOwner runs every row whose op fileid answers through
// fileid's resolver and requires the row's want: cases.json passes on the
// owner. A row whose current answer differs from want is a reproducer the
// owner repairs; the old functions keep their current answers (TestCases).
func TestCasesThroughTheOwner(t *testing.T) {
	table, _, err := placetest.Load()
	if errors.Is(err, placetest.ErrNoTable) {
		t.Skip(err)
	}
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range table.Rows {
		if !ownerOps[c.Op] {
			continue
		}
		c := c
		t.Run(c.ID, func(t *testing.T) {
			if !c.ForThisPlatform() {
				t.Skipf("platform %s, running on %s", c.Platform, runtime.GOOS)
			}
			if c.Skip != "" {
				t.Skip(c.Skip)
			}
			if why := elsewhere(c); why != "" {
				t.Skip(why)
			}
			f, why := build(t, c)
			if why != "" {
				t.Skip(string(why))
			}
			got := owner(t, c, f)
			if c.Current == "observed" {
				t.Logf("%s: the owner answers %s (want %s)", c.ID, got, c.Want)
				return
			}
			if got != c.Want {
				t.Errorf("%s through fileid: %s(%q, %q) = %s, want %s", c.ID, c.Op, f.a, f.b, got, c.Want)
			}
		})
	}
}

// TestOldFunctionsAnswerAsFileidOverCases runs each row of an op identity
// exported before fileid through identity's wrapper and through the fileid
// function of the same name, on one fixture, and requires the same answer:
// the wrappers keep every old answer byte for byte (PT-3).
func TestOldFunctionsAnswerAsFileidOverCases(t *testing.T) {
	table, _, err := placetest.Load()
	if errors.Is(err, placetest.ErrNoTable) {
		t.Skip(err)
	}
	if err != nil {
		t.Fatal(err)
	}
	type pair struct{ old, owner func(a, b string) string }
	str := func(s string, err error) string { return fmt.Sprintf("%q %v", s, err) }
	pairs := map[string]pair{
		"SameFile": {func(a, b string) string { s, err := identity.SameFile(a, b); return fmt.Sprint(s, err) },
			func(a, b string) string { s, err := fileid.SameFile(a, b); return fmt.Sprint(s, err) }},
		"Within": {func(a, b string) string { r, s, err := identity.WithinRel(a, b); return fmt.Sprint(r, s, err) },
			func(a, b string) string { r, s, err := fileid.WithinRel(a, b); return fmt.Sprint(r, s, err) }},
		"FileKey":  {func(a, _ string) string { return str(identity.FileKey(a)) }, func(a, _ string) string { return str(fileid.FileKey(a)) }},
		"PlaceKey": {func(a, _ string) string { return str(identity.PlaceKey(a)) }, func(a, _ string) string { return str(fileid.PlaceKey(a)) }},
		"SamePathName": {func(a, b string) string {
			return fmt.Sprint(identity.SamePathName(a, b), identity.PathNameKey(a), identity.PathNameWithin(a, b))
		},
			func(a, b string) string {
				return fmt.Sprint(fileid.SamePathName(a, b), fileid.PathNameKey(a), fileid.PathNameWithin(a, b))
			}},
		"LocalPath": {func(a, _ string) string { return fmt.Sprint(identity.LocalPath(a)) }, func(a, _ string) string { return fmt.Sprint(fileid.LocalPath(a)) }},
	}
	programs := pair{
		func(a, b string) string {
			return fmt.Sprint(identity.CanonicalProgramPath(a), identity.NormalizeSubjectProgram(a), identity.SameSubjectProgram(a, b),
				identity.ProgramKey(a), identity.ValidSubjectProgram(a), identity.HasShortNameComponent(a), identity.UnresolvedShortName(a), identity.Inside(a, b))
		},
		func(a, b string) string {
			return fmt.Sprint(fileid.CanonicalProgramPath(a), fileid.NormalizeSubjectProgram(a), fileid.SameSubjectProgram(a, b),
				fileid.ProgramKey(a), fileid.ValidSubjectProgram(a), fileid.HasShortNameComponent(a), fileid.UnresolvedShortName(a), fileid.Inside(a, b))
		},
	}
	for _, c := range table.Rows {
		p, ok := pairs[c.Op]
		if !ok {
			continue
		}
		c := c
		t.Run(c.ID, func(t *testing.T) {
			if !c.ForThisPlatform() || c.Skip != "" || elsewhere(c) != "" || c.Setup == "rename-over" || c.Setup == "inode-reuse" {
				t.Skip("not run here, or its fixture changes between two reads")
			}
			f, why := build(t, c)
			if why != "" {
				t.Skip(string(why))
			}
			var oldA, ownA, oldP, ownP string
			if err := guarded(t, f.b, func() error {
				oldA, ownA = p.old(f.a, f.b), p.owner(f.a, f.b)
				oldP, ownP = programs.old(f.a, f.b), programs.owner(f.a, f.b)
				return nil
			}); err != nil {
				t.Skipf("the row's fixture is not opened here: %v", err)
			}
			if oldA != ownA {
				t.Errorf("%s: identity answers %s, fileid answers %s", c.Op, oldA, ownA)
			}
			if oldP != ownP {
				t.Errorf("program functions: identity answers %s, fileid answers %s", oldP, ownP)
			}
		})
	}
}
