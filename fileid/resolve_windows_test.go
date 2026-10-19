package fileid

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"unicode/utf16"

	"github.com/openabstractions/abstraction-identity/placetest"
	"golang.org/x/sys/windows"
)

func folderLink(link, target string) error {
	if out, err := exec.Command("cmd", "/c", "mklink", "/J", link, target).CombinedOutput(); err != nil {
		return fmt.Errorf("mklink /J: %v: %s", err, out)
	}
	return nil
}

// guardOpens replaces the walk's two openers for the test: each name they
// are given is recorded, and a name that is a UNC path or names the TEST-NET
// host fails the test and is never opened.
func guardOpens(t *testing.T) *[]string {
	t.Helper()
	var seen []string
	remote := func(name string) bool {
		return strings.HasPrefix(name, `\\`) || strings.Contains(name, placetest.TestNetHost)
	}
	realAt, realRoot := openAt, openRoot
	openAt = func(parent windows.Handle, name string, access, disposition, options uint32) (windows.Handle, error) {
		seen = append(seen, name)
		if remote(name) {
			t.Errorf("the walk asked to open %q", name)
			return 0, windows.ERROR_ACCESS_DENIED
		}
		return realAt(parent, name, access, disposition, options)
	}
	openRoot = func(root string) (windows.Handle, error) {
		seen = append(seen, root)
		guid, isGUID := strings.CutPrefix(root, `\\?\`)
		if isGUID && !volumeGUIDPath(guid) || !isGUID && (remote(root) || !driveAbsolute(root)) {
			t.Errorf("the walk asked to open the root %q", root)
			return 0, windows.ERROR_ACCESS_DENIED
		}
		return realRoot(root)
	}
	t.Cleanup(func() { openAt, openRoot = realAt, realRoot })
	return &seen
}

// A local junction whose reparse data names a share is refused before
// anything at the share is opened: the walk opens the junction itself
// without following it, reads its target and refuses it. The openers fail
// the test if they are ever given a remote name, so no SMB connection is
// attempted even if the walk were wrong.
func TestALinkToAShareIsRefusedBeforeAnyOpen(t *testing.T) {
	seen := guardOpens(t)
	dir := t.TempDir()
	link := filepath.Join(dir, "share junction")
	if err := placetest.ShareJunction(link); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Remove(link) })
	for _, p := range []string{filepath.Join(link, "file.txt"), link} {
		for _, opt := range []Options{{}, {Read: true}} {
			_, err := Resolve(bg, Self, p, opt)
			var nl *NotLocalPathError
			if !errors.Is(err, ErrNotLocalPath) || !errors.As(err, &nl) || !strings.Contains(nl.Reason, placetest.TestNetHost) {
				t.Errorf("Resolve %s: %v, want a refusal naming the share", p, err)
			}
		}
	}
	if _, err := Pending(bg, Self, filepath.Join(link, "new", "file.txt")); !errors.Is(err, ErrNotLocalPath) {
		t.Errorf("Pending below the junction: %v", err)
	}
	if _, err := ResolveLeaf(bg, Self, filepath.Join(link, "file.txt")); !errors.Is(err, ErrNotLocalPath) {
		t.Errorf("ResolveLeaf below the junction: %v", err)
	}
	opened := false
	for _, name := range *seen {
		if name == "share junction" {
			opened = true
		}
	}
	if !opened {
		t.Errorf("the walk never opened the junction itself; it opened %q", *seen)
	}
}

// A mount point whose target is a volume named by GUID, as a volume mounted
// in a folder has (a Dev Drive or a VHD without a letter), is followed when
// GetDriveType reads the volume as local: the walk restarts at the volume's
// GUID root (ID-F4). The fixture names the temporary folder's own volume by
// its GUID, which needs no administrator rights; a GUID no volume has is
// refused before its root is opened.
func TestAMountPointToALocalVolumeGUIDIsFollowed(t *testing.T) {
	dir := t.TempDir()
	target := writeFile(t, filepath.Join(dir, "target folder", "file.txt"), "x")
	link := filepath.Join(dir, "volume mount")
	guid, err := placetest.VolumeMountPoint(link, filepath.Dir(target))
	if err != nil {
		t.Skip(err)
	}
	t.Cleanup(func() { os.Remove(link) })
	zero := filepath.Join(dir, "no volume")
	const zeroGUID = `Volume{00000000-0000-0000-0000-000000000000}\`
	if err := placetest.MountPoint(zero, `\??\`+zeroGUID, `\\?\`+zeroGUID); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Remove(zero) })
	seen := guardOpens(t)
	through, direct := mustResolve(t, filepath.Join(link, "file.txt"), Options{}), mustResolve(t, target, Options{})
	if !through.Equal(direct) || through.Path() != direct.Path() {
		t.Errorf("through the mount point %s, directly %s", through, direct)
	}
	la, err := ResolveLeaf(bg, Self, filepath.Join(link, "file.txt"))
	if err != nil {
		t.Fatal(err)
	}
	lb, err := ResolveLeaf(bg, Self, target)
	if err != nil {
		t.Fatal(err)
	}
	if la.Key() != lb.Key() {
		t.Errorf("leaf through the mount point %s, directly %s", la.Key(), lb.Key())
	}
	reached := false
	for _, name := range *seen {
		reached = reached || strings.EqualFold(name, guid)
	}
	if !reached {
		t.Errorf("the walk never restarted at %s; it opened %q", guid, *seen)
	}
	*seen = nil
	_, err = Resolve(bg, Self, filepath.Join(zero, "file.txt"), Options{})
	var nl *NotLocalPathError
	if !errors.Is(err, ErrNotLocalPath) || !errors.As(err, &nl) || !strings.Contains(nl.Reason, zeroGUID[:len(zeroGUID)-1]) {
		t.Errorf("a mount point to a GUID no volume has: %v, want a refusal naming it", err)
	}
	for _, name := range *seen {
		if strings.Contains(name, "Volume{") {
			t.Errorf("the walk opened %s for a GUID no volume has", name)
		}
	}
}

// The same with a symbolic link, where Developer Mode lets this account make
// one.
func TestASymbolicLinkToAShareIsRefusedBeforeAnyOpen(t *testing.T) {
	guardOpens(t)
	link := filepath.Join(t.TempDir(), "share link")
	if err := placetest.FolderSymlink(link, placetest.TestNetShare("", false)); err != nil {
		t.Skip("symbolic link not allowed here:", err)
	}
	t.Cleanup(func() { os.Remove(link) })
	if _, err := Resolve(bg, Self, filepath.Join(link, "file.txt"), Options{}); !errors.Is(err, ErrNotLocalPath) {
		t.Errorf("Resolve below the link: %v", err)
	}
}

func reparseBuffer(tag uint32, flags uint32, sub string) []byte {
	s := utf16.Encode([]rune(sub))
	body := 16
	if tag == windows.IO_REPARSE_TAG_SYMLINK {
		body = 20
	}
	buf := make([]byte, body+2*len(s)+2)
	binary.LittleEndian.PutUint32(buf, tag)
	binary.LittleEndian.PutUint16(buf[4:], uint16(len(buf)-8))
	binary.LittleEndian.PutUint16(buf[8:], 0)
	binary.LittleEndian.PutUint16(buf[10:], uint16(2*len(s)))
	binary.LittleEndian.PutUint16(buf[12:], uint16(2*len(s)))
	binary.LittleEndian.PutUint16(buf[14:], 0)
	if tag == windows.IO_REPARSE_TAG_SYMLINK {
		binary.LittleEndian.PutUint32(buf[16:], flags)
	}
	for i, u := range s {
		binary.LittleEndian.PutUint16(buf[body+2*i:], u)
	}
	return buf
}

func openFixtureReparse(t *testing.T, path string, access uint32) windows.Handle {
	t.Helper()
	p, err := windows.UTF16PtrFromString(`\\?\` + path)
	if err != nil {
		t.Fatal(err)
	}
	h, err := windows.CreateFile(p, access, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, nil, windows.OPEN_EXISTING,
		windows.FILE_FLAG_OPEN_REPARSE_POINT|windows.FILE_FLAG_BACKUP_SEMANTICS, 0)
	if err != nil {
		t.Fatal(err)
	}
	return h
}

func TestVolumeRootIsOpenedWithoutFollowingAReparsePoint(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "local target")
	if err := os.Mkdir(target, 0o755); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "root junction")
	if err := placetest.Junction(link, target); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Remove(link) })
	h, err := openVolumeRoot(link)
	if err != nil {
		t.Fatal(err)
	}
	defer windows.CloseHandle(h)
	tag, err := readAttributeTag(h)
	if err != nil || !isLink(tag) {
		t.Fatalf("root open followed the owned junction: tag=%+v err=%v", tag, err)
	}
}

func TestASubstitutedRootLinkIsRefusedBeforeAnyChildOpen(t *testing.T) {
	link := filepath.Join(t.TempDir(), "share root")
	if err := placetest.ShareJunction(link); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Remove(link) })
	realType, realRoot, realAt := pathDriveType, openRoot, openAt
	t.Cleanup(func() { pathDriveType, openRoot, openAt = realType, realRoot, realAt })
	pathDriveType = func(string) uint32 { return windows.DRIVE_FIXED }
	openRoot = func(root string) (windows.Handle, error) {
		if root != `Q:\` {
			t.Fatalf("unexpected fake root %q", root)
		}
		return openFixtureReparse(t, link, accessIdentity), nil
	}
	children := 0
	openAt = func(windows.Handle, string, uint32, uint32, uint32) (windows.Handle, error) {
		children++
		return 0, windows.ERROR_ACCESS_DENIED // Never let the baseline contact the share.
	}
	for _, path := range []string{`Q:\`, `Q:\child`} {
		h, err := Open(bg, Self, path, Options{})
		if err == nil {
			h.Close()
		}
		if !errors.Is(err, ErrLink) {
			t.Errorf("fake substituted root %q: %v, want ErrLink", path, err)
		}
	}
	if children != 0 {
		t.Errorf("root link reached %d child opens", children)
	}
}

func TestAbsoluteLinkTargetsWithDotComponentsAreRefused(t *testing.T) {
	for _, tag := range []uint32{windows.IO_REPARSE_TAG_MOUNT_POINT, windows.IO_REPARSE_TAG_SYMLINK} {
		for _, target := range []string{`\??\C:\dir\.\x`, `\??\C:\dir\..\x`, `C:\dir\.\x`, `C:\dir\..\x`, `\??\Volume{00000000-0000-0000-0000-000000000000}\dir\..\x`} {
			if _, err := linkTarget(reparseBuffer(tag, 0, target), `C:\links\j`, `C:\links`); !errors.Is(err, ErrLink) {
				t.Errorf("absolute target %q tag %#x: %v, want ErrLink", target, tag, err)
			}
		}
	}
}

func TestJunctionNTDotTargetAgreesWithKernelRefusal(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "deep", "b"), 0o755); err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(dir, "x", "f"), "text-cleaned decoy")
	link := filepath.Join(dir, "NT dot target")
	sub := `\??\` + dir + `\deep\b\..\..\x`
	if err := placetest.MountPoint(link, sub, sub); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Remove(link) })
	path := filepath.Join(link, "f")
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		t.Fatal(err)
	}
	h, err := windows.CreateFile(p, accessIdentity, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, nil, windows.OPEN_EXISTING, windows.FILE_FLAG_BACKUP_SEMANTICS, 0)
	if err == nil {
		windows.CloseHandle(h)
	}
	if !errors.Is(err, windows.ERROR_INVALID_NAME) {
		t.Fatalf("kernel NT dot-target open: %v, want ERROR_INVALID_NAME", err)
	}
	got, err := Open(bg, Self, path, Options{})
	if err == nil {
		got.Close()
	}
	if !errors.Is(err, ErrLink) {
		t.Fatalf("fileid NT dot-target open: %v, want ErrLink", err)
	}
}

func TestSameFileDataTagBecomesALinkBeforeReopen(t *testing.T) {
	dir, err := placetest.ShortName(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(dir, "target")
	probe := filepath.Join(dir, "probe")
	for _, name := range []string{target, probe} {
		if err := os.WriteFile(name, nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	setLink := func(h windows.Handle) error {
		buf := reparseBuffer(windows.IO_REPARSE_TAG_SYMLINK, 0, `\??\`+target)
		printName := utf16.Encode([]rune(target))
		printOffset := len(buf) - 20
		buf = append(buf, make([]byte, 2*len(printName)+2)...)
		binary.LittleEndian.PutUint16(buf[4:], uint16(len(buf)-8))
		binary.LittleEndian.PutUint16(buf[12:], uint16(printOffset))
		binary.LittleEndian.PutUint16(buf[14:], uint16(2*len(printName)))
		for i, u := range printName {
			binary.LittleEndian.PutUint16(buf[20+printOffset+2*i:], u)
		}
		var n uint32
		return windows.DeviceIoControl(h, 0x900a4, &buf[0], uint32(len(buf)), nil, 0, &n, nil)
	}
	h := openFixtureReparse(t, probe, windows.GENERIC_WRITE)
	err = setLink(h)
	windows.CloseHandle(h)
	if errors.Is(err, windows.ERROR_PRIVILEGE_NOT_HELD) {
		t.Skip("same-file symbolic-link tag transition unavailable without existing privilege:", err)
	}
	if err != nil {
		t.Fatal("preflight symbolic-link tag:", err)
	}
	sock := filepath.Join(dir, "data")
	l, err := net.Listen("unix", sock)
	if err != nil {
		t.Skip("no AF_UNIX socket file here:", err)
	}
	l.(*net.UnixListener).SetUnlinkOnClose(false)
	l.Close()
	// An exclusive target handle makes accidental following observable without
	// giving the link any remote target or changing account security settings.
	p, err := windows.UTF16PtrFromString(`\\?\` + target)
	if err != nil {
		t.Fatal(err)
	}
	blocked, err := windows.CreateFile(p, windows.GENERIC_READ, 0, nil, windows.OPEN_EXISTING, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer windows.CloseHandle(blocked)
	mutator := openFixtureReparse(t, sock, windows.GENERIC_WRITE)
	defer windows.CloseHandle(mutator)
	wantKey, _, err := fileIDKey(mutator)
	if err != nil {
		t.Fatal(err)
	}
	var mutation error
	betweenOpens = func(string) {
		tag, err := readAttributeTag(mutator)
		if err != nil {
			mutation = err
			return
		}
		var header [8]byte
		binary.LittleEndian.PutUint32(header[:], tag.tag)
		var n uint32
		mutation = windows.DeviceIoControl(mutator, 0x900ac, &header[0], uint32(len(header)), nil, 0, &n, nil)
		if mutation == nil {
			mutation = setLink(mutator)
		}
		if mutation == nil {
			got, _, err := fileIDKey(mutator)
			if err != nil || got != wantKey {
				mutation = fmt.Errorf("same-file transition changed identity: %s, %v; want %s", got, err, wantKey)
			}
		}
	}
	t.Cleanup(func() { betweenOpens = nil })
	opened, err := Open(bg, Self, sock, Options{Read: true})
	if err == nil {
		opened.Close()
	}
	if mutation != nil {
		t.Fatal("same-file tag transition:", mutation)
	}
	if !errors.Is(err, ErrLink) {
		t.Fatalf("same-file link transition: %v, want ErrLink without opening the held target", err)
	}
}

func TestReopenedNameSurrogateIsRefusedBeforeKeyComparison(t *testing.T) {
	dir, err := placetest.ShortName(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	sock := filepath.Join(dir, "data tag")
	l, err := net.Listen("unix", sock)
	if err != nil {
		t.Skip("no owned AF_UNIX data-tag fixture:", err)
	}
	l.(*net.UnixListener).SetUnlinkOnClose(false)
	l.Close()
	link := filepath.Join(dir, "late surrogate")
	if err := placetest.ShareJunction(link); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Remove(link) })
	real := reopenFile
	reopenFile = func(windows.Handle, uint32) (windows.Handle, error) {
		return openFixtureReparse(t, link, accessIdentity), nil
	}
	t.Cleanup(func() { reopenFile = real })
	h, err := Open(bg, Self, sock, Options{Read: true})
	if err == nil {
		h.Close()
	}
	if !errors.Is(err, ErrLink) {
		t.Fatalf("reopened surrogate: %v, want ErrLink before the changed key is considered", err)
	}
}

func TestLinkTargetReadsOnlyLocalDriveTargets(t *testing.T) {
	const dir = `C:\data\links`
	sym, mount := uint32(windows.IO_REPARSE_TAG_SYMLINK), uint32(windows.IO_REPARSE_TAG_MOUNT_POINT)
	ok := []struct {
		tag, flags uint32
		sub, want  string
	}{
		{sym, 0, `\??\C:\models\x`, `C:\models\x`},
		{sym, symlinkFlagRelative, `..\other\y`, `C:\data\other\y`},
		{sym, symlinkFlagRelative, `\root\z`, `C:\root\z`},
		{mount, 0, `\??\D:\target\`, `D:\target`},
		{mount, 0, `\??\E:`, `E:\`},
		{mount, 0, `\??\Volume{00000000-0000-0000-0000-000000000000}\`, `\\?\Volume{00000000-0000-0000-0000-000000000000}\`},
		{mount, 0, `\??\Volume{00000000-0000-0000-0000-000000000000}\models\`, `\\?\Volume{00000000-0000-0000-0000-000000000000}\models`},
	}
	for _, c := range ok {
		got, err := linkTarget(reparseBuffer(c.tag, c.flags, c.sub), dir+`\l`, dir)
		if err != nil || got != c.want {
			t.Errorf("target %q: %q, %v; want %q", c.sub, got, err, c.want)
		}
	}
	refused := []struct {
		tag uint32
		sub string
	}{
		{sym, `\??\UNC\192.0.2.1\share\x`},
		{sym, `\??\unc\192.0.2.1\share`},
		{mount, `\??\UNC\192.0.2.1\share\`},
		{mount, `\??\Volume{00000000-0000-0000-0000-000000000000}x`},
		{sym, `\??\GLOBALROOT\Device\Mup\192.0.2.1\share`},
		{sym, `\Device\HarddiskVolume1\x`},
	}
	for _, c := range refused {
		if _, err := linkTarget(reparseBuffer(c.tag, 0, c.sub), dir+`\l`, dir); !errors.Is(err, ErrNotLocalPath) {
			t.Errorf("target %q: %v, want ErrNotLocalPath", c.sub, err)
		}
	}
	if _, err := linkTarget(reparseBuffer(0xA000001D, 0, "x"), dir+`\l`, dir); !errors.Is(err, ErrLink) {
		t.Errorf("a WSL symlink: %v, want ErrLink", err)
	}
	bad := reparseBuffer(sym, 0, `\??\C:\x`)
	binary.LittleEndian.PutUint16(bad[10:], 400)
	if _, err := linkTarget(bad, dir+`\l`, dir); !errors.Is(err, ErrLink) {
		t.Errorf("malformed reparse data: %v, want ErrLink", err)
	}
	if _, err := linkTarget(bad[:10], dir+`\l`, dir); !errors.Is(err, ErrLink) {
		t.Errorf("short reparse data: %v, want ErrLink", err)
	}
}

// Attributes and tags the classifier is asked about: a name surrogate is a
// link; a data tag, such as a cloud files placeholder, is a regular file.
var syntheticTags = []struct {
	name string
	a    attributeTag
	link bool
}{
	{"cloud files placeholder (CLOUD_6, recall on data access)", attributeTag{windows.FILE_ATTRIBUTE_REPARSE_POINT | 0x00400000 | windows.FILE_ATTRIBUTE_ARCHIVE, 0x9000601A}, false},
	{"cloud files placeholder (CLOUD)", attributeTag{windows.FILE_ATTRIBUTE_REPARSE_POINT | windows.FILE_ATTRIBUTE_OFFLINE, 0x9000001A}, false},
	{"cloud files folder placeholder (CLOUD_F)", attributeTag{windows.FILE_ATTRIBUTE_REPARSE_POINT | windows.FILE_ATTRIBUTE_DIRECTORY, 0x9000F01A}, false},
	{"WOF-compressed file without the filter", attributeTag{windows.FILE_ATTRIBUTE_REPARSE_POINT, 0x80000017}, false},
	{"deduplicated file", attributeTag{windows.FILE_ATTRIBUTE_REPARSE_POINT, 0x80000013}, false},
	{"app execution alias", attributeTag{windows.FILE_ATTRIBUTE_REPARSE_POINT, 0x8000001B}, false},
	{"AF_UNIX socket", attributeTag{windows.FILE_ATTRIBUTE_REPARSE_POINT, 0x80000023}, false},
	{"WOF file with the filter (W0-07(s) fact 3)", attributeTag{windows.FILE_ATTRIBUTE_ARCHIVE, 0}, false},
	{"a tag without the reparse attribute", attributeTag{windows.FILE_ATTRIBUTE_ARCHIVE, windows.IO_REPARSE_TAG_SYMLINK}, false},
	{"symbolic link", attributeTag{windows.FILE_ATTRIBUTE_REPARSE_POINT, windows.IO_REPARSE_TAG_SYMLINK}, true},
	{"junction", attributeTag{windows.FILE_ATTRIBUTE_REPARSE_POINT | windows.FILE_ATTRIBUTE_DIRECTORY, windows.IO_REPARSE_TAG_MOUNT_POINT}, true},
	{"WSL symbolic link", attributeTag{windows.FILE_ATTRIBUTE_REPARSE_POINT, 0xA000001D}, true},
}

func TestDataTagsAreRegularFiles(t *testing.T) {
	for _, c := range syntheticTags {
		if got := isLink(c.a); got != c.link {
			t.Errorf("%s (%#x, tag %#x): link %v, want %v", c.name, c.a.attributes, c.a.tag, got, c.link)
		}
	}
}

// TestSyntheticRowsOfCasesJSON runs the cases.json rows whose fixture is a
// set of synthetic attributes (setup cloud-synthetic): every data tag reads
// as the row's want, a regular file, and every name surrogate as a link.
func TestSyntheticRowsOfCasesJSON(t *testing.T) {
	table, _, err := placetest.Load()
	if errors.Is(err, placetest.ErrNoTable) {
		t.Skip(err)
	}
	if err != nil {
		t.Fatal(err)
	}
	ran := 0
	for _, c := range table.Rows {
		if c.Setup != "cloud-synthetic" {
			continue
		}
		ran++
		for _, s := range syntheticTags {
			kind := "regular file"
			if isLink(s.a) {
				kind = "link"
			}
			if !s.link && kind != c.Want {
				t.Errorf("%s: %s reads %s, want %s", c.ID, s.name, kind, c.Want)
			}
		}
	}
	if ran == 0 {
		t.Error("cases.json has no cloud-synthetic row")
	}
}

// TestSeamRowsOfCasesJSON runs the cases.json rows whose fixture needs one of
// fileid's own seams: a folder named through its mount point, as the system
// names a volume with no drive letter (setup folder-mount-named), and a
// data-tag file's entry swapped for a junction between the walk's two opens
// (setup data-tag-swap). Each row runs the test that builds its fixture and
// requires the answer recorded here, and the row's want is that answer.
func TestSeamRowsOfCasesJSON(t *testing.T) {
	seams := map[string]struct {
		answer string
		run    func(*testing.T)
	}{
		"folder-mount-named": {"inside", TestRelateUnderAFolderMountedVolume},
		"data-tag-swap":      {"not followed", TestADataTagFileIsReopenedThroughItsOwnHandle},
		"junction-nt-dot":    {"refused", TestJunctionNTDotTargetAgreesWithKernelRefusal},
	}
	table, _, err := placetest.Load()
	if errors.Is(err, placetest.ErrNoTable) {
		t.Skip(err)
	}
	if err != nil {
		t.Fatal(err)
	}
	ran := map[string]bool{}
	for _, c := range table.Rows {
		s, ok := seams[c.Setup]
		if !ok {
			continue
		}
		ran[c.Setup] = true
		t.Run(c.ID, func(t *testing.T) {
			if c.Want != s.answer || c.Current != s.answer {
				t.Errorf("%s records current %s and want %s; its test answers %s", c.ID, c.Current, c.Want, s.answer)
			}
			s.run(t)
		})
	}
	for setup := range seams {
		if !ran[setup] {
			t.Errorf("cases.json has no %s row", setup)
		}
	}
}

// A WOF-compressed file, made with compact.exe in a folder of this module's
// own checkout, is a regular file: its handle read without following shows
// no link, it resolves to its own key, and a read returns its bytes (W0-07(s)
// fact 3).
func TestAWOFCompressedFileIsARegularFile(t *testing.T) {
	dir, err := os.MkdirTemp(".", ".wof-fixture-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	data := strings.Repeat("compressible text ", 14000)
	f := writeFile(t, filepath.Join(dir, "compressed.txt"), data)
	if err := placetest.Compact(f); err != nil {
		t.Skip("compact.exe:", err)
	}
	h, err := Open(bg, Self, f, Options{Read: true, Links: RefuseLinks})
	if err != nil {
		t.Fatalf("Open %s: %v", f, err)
	}
	defer h.Close()
	tag, err := readAttributeTag(windows.Handle(h.File().Fd()))
	if err != nil {
		t.Fatal(err)
	}
	if isLink(tag) || h.FileID().IsDir() {
		t.Errorf("the WOF file reads %#x tag %#x, a link or a folder", tag.attributes, tag.tag)
	}
	key, err := FileKey(f)
	if err != nil || key != h.FileID().Key() {
		t.Errorf("FileKey %s, %v; the handle %s", key, err, h.FileID().Key())
	}
	got, err := io.ReadAll(h.File())
	if err != nil || string(got) != data {
		t.Errorf("read %d bytes, %v; want the %d written", len(got), err, len(data))
	}
	t.Logf("WOF file: attributes %#x, tag %#x", tag.attributes, tag.tag)
}

// A path naming an alternate data stream is refused before anything is
// opened: a Handle on the stream would read data the file's FileID does not
// tell apart (ID-F4). "::$DATA", the file's own data, names the file.
func TestAStreamIsRefusedBeforeAnyOpen(t *testing.T) {
	f := writeFile(t, filepath.Join(t.TempDir(), "file.txt"), "visible")
	if err := os.WriteFile(f+":ads", []byte("hidden"), 0o644); err != nil {
		t.Skip("this volume keeps no alternate streams:", err)
	}
	seen := guardOpens(t)
	for _, p := range []string{f + ":ads", f + ":ads:$DATA", f + ":$DATA", f + "::$INDEX_ALLOCATION", f + "::$data", filepath.Dir(f) + `:x\file.txt`} {
		for _, opt := range []Options{{}, {Read: true}} {
			h, err := Open(bg, Self, p, opt)
			if err == nil {
				h.Close()
			}
			if !errors.Is(err, ErrUnsafeName) {
				t.Errorf("Open %s: %v, want ErrUnsafeName", p, err)
			}
		}
		if _, err := ResolveLeaf(bg, Self, p); !errors.Is(err, ErrUnsafeName) {
			t.Errorf("ResolveLeaf %s: %v, want ErrUnsafeName", p, err)
		}
		if _, err := Pending(bg, Self, p); !errors.Is(err, ErrUnsafeName) {
			t.Errorf("Pending %s: %v, want ErrUnsafeName", p, err)
		}
	}
	if len(*seen) != 0 {
		t.Errorf("a stream path opened %q", *seen)
	}
	h, err := Open(bg, Self, f+"::$DATA", Options{Read: true})
	if err != nil {
		t.Fatalf("Open %s::$DATA: %v", f, err)
	}
	defer h.Close()
	got, err := io.ReadAll(h.File())
	if err != nil || string(got) != "visible" || !h.FileID().Equal(mustResolve(t, f, Options{})) {
		t.Errorf("%s::$DATA reads %q, %v, %s; want the file itself", f, got, err, h.FileID())
	}
}

// A junction whose target names an alternate stream is refused before the
// stream is opened, under every op that resolves: a link's target passes the
// stream refusal a typed path passes (ID-F4). placetest.MountPoint writes the
// junction's reparse data directly and needs no privilege.
func TestAStreamThroughALinkIsRefusedBeforeAnyOpen(t *testing.T) {
	dir := t.TempDir()
	f := writeFile(t, filepath.Join(dir, "file.txt"), "visible")
	if err := os.WriteFile(f+":ads", []byte("hidden"), 0o644); err != nil {
		t.Skip("this volume keeps no alternate streams:", err)
	}
	links := map[string]string{
		"stream junction": `\??\` + f + ":ads",
		"folder stream":   `\??\` + dir + `:x\file.txt`,
		"named data":      `\??\` + f + ":ads:$DATA",
	}
	for name, sub := range links {
		link := filepath.Join(dir, name)
		if err := placetest.MountPoint(link, sub, strings.TrimPrefix(sub, `\??\`)); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { os.Remove(link) })
	}
	folder, err := Open(bg, Self, dir, Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer folder.Close()
	seen := guardOpens(t)
	for name := range links {
		link := filepath.Join(dir, name)
		for _, opt := range []Options{{}, {Read: true}} {
			h, err := Open(bg, Self, link, opt)
			if err == nil {
				h.Close()
			}
			if !errors.Is(err, ErrUnsafeName) {
				t.Errorf("Open %s (read %v): %v, want ErrUnsafeName", name, opt.Read, err)
			}
		}
		if _, err := Resolve(bg, Self, filepath.Join(link, "below"), Options{}); !errors.Is(err, ErrUnsafeName) {
			t.Errorf("Resolve below %s: %v, want ErrUnsafeName", name, err)
		}
		if _, err := ResolveLeaf(bg, Self, filepath.Join(link, "leaf")); !errors.Is(err, ErrUnsafeName) {
			t.Errorf("ResolveLeaf below %s: %v, want ErrUnsafeName", name, err)
		}
		for _, p := range []string{link, filepath.Join(link, "new", "file.txt")} {
			if _, err := Pending(bg, Self, p); !errors.Is(err, ErrUnsafeName) {
				t.Errorf("Pending %s: %v, want ErrUnsafeName", p, err)
			}
		}
		if h, err := folder.Beneath(name, Options{Read: true}); err == nil || !errors.Is(err, ErrLink) {
			if err == nil {
				h.Close()
			}
			t.Errorf("Beneath %s: %v, want ErrLink", name, err)
		}
	}
	for _, name := range *seen {
		if driveAbsolute(name) {
			name = name[3:]
		}
		if strings.Contains(name, ":") {
			t.Errorf("the walk opened the stream %q", name)
		}
	}
}

// localTarget refuses a link target naming a stream, on a drive and on a
// volume named by GUID, before GetDriveType reads the volume; "::$DATA", the
// file's own data, names the file as it does in a typed path.
func TestLocalTargetRefusesAStream(t *testing.T) {
	const zero = `\\?\Volume{00000000-0000-0000-0000-000000000000}\`
	read := 0
	realType := pathDriveType
	pathDriveType = func(root string) uint32 { read++; return realType(root) }
	t.Cleanup(func() { pathDriveType = realType })
	for _, target := range []string{`C:\data\file.txt:ads`, `C:\data:x\file.txt`, `C:\data\file.txt:ads:$DATA`, zero + `file.txt:ads`, zero + `models:x\y`} {
		read = 0
		if _, _, err := localTarget(`C:\l`, target); !errors.Is(err, ErrUnsafeName) {
			t.Errorf("target %s: %v, want ErrUnsafeName", target, err)
		}
		if read != 0 {
			t.Errorf("target %s: the volume's type was read before the refusal", target)
		}
	}
	root, rest, err := localTarget(`C:\l`, `C:\data\file.txt::$DATA`)
	if err != nil || root != `C:\` || rest != `data\file.txt` {
		t.Errorf("target ::$DATA: %q %q %v, want the file", root, rest, err)
	}
}

// nameThrough makes finalPathOf name every path below folder through link
// for the rest of the test, as GetFinalPathNameByHandle names a volume with
// no drive letter through the folder it is mounted on.
func nameThrough(t *testing.T, folder, link string) {
	t.Helper()
	real := finalPathOf
	finalPathOf = func(h windows.Handle) (string, error) {
		p, err := real(h)
		if rest, ok := strings.CutPrefix(p, folder); ok && (rest == "" || rest[0] == '\\') {
			p = link + rest
		}
		return p, err
	}
	t.Cleanup(func() { finalPathOf = real })
}

// A file on a volume mounted in a folder (a Dev Drive or a VHD without a
// letter) has a final path through the mount folder. Relate reads that
// folder as the volume's root: it answers inside for a file below a folder on
// that volume, and outside for a file whose final path runs through a link
// that is not the mount of what it names (ID-F6). The fixture is a mount
// point to a folder named through its volume's GUID
// (placetest.VolumeMountPoint, no administrator rights), and the final path
// reader names that folder through the mount point, as the system names a
// folder-mounted volume's root through its mount folder.
func TestRelateUnderAFolderMountedVolume(t *testing.T) {
	dir := t.TempDir()
	root := filepath.Join(dir, "volume root")
	writeFile(t, filepath.Join(root, "models", "m.gguf"), "x")
	mount := filepath.Join(dir, "mount folder")
	if _, err := placetest.VolumeMountPoint(mount, root); err != nil {
		t.Skip(err)
	}
	t.Cleanup(func() { os.Remove(mount) })
	rootPath := mustResolve(t, root, Options{}).Path()
	mountPath := filepath.Join(filepath.Dir(rootPath), "mount folder")
	nameThrough(t, rootPath, mountPath)
	open := func(p string) Handle {
		t.Helper()
		h, err := Open(bg, Self, p, Options{})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { h.Close() })
		return h
	}
	volume, models := open(mount), open(filepath.Join(mount, "models"))
	file := open(filepath.Join(mount, "models", "m.gguf"))
	if want := filepath.Join(mountPath, "models", "m.gguf"); file.FileID().Path() != want {
		t.Fatalf("the file reads %s, want the path through the mount folder %s", file.FileID().Path(), want)
	}
	// The folder holding the mount folder holds the volume, as the walk
	// reaches it.
	for _, c := range []struct {
		other Handle
		rel   string
	}{{volume, `models\m.gguf`}, {models, "m.gguf"}, {open(dir), `mount folder\models\m.gguf`}} {
		if r, err := file.Relate(c.other); err != nil || r.Kind != RelationInside || r.Rel != c.rel {
			t.Errorf("Relate to %s: %+v, %v; want inside at %s", c.other.FileID().Path(), r, err, c.rel)
		}
	}
	granted := filepath.Join(dir, "granted")
	if err := os.Mkdir(granted, 0o755); err != nil {
		t.Fatal(err)
	}
	if r, err := file.Relate(open(granted)); err != nil || r.Kind != RelationOutside {
		t.Errorf("Relate to a folder beside the mount folder: %+v, %v; want outside", r, err)
	}

	// A final path through a junction to the granted folder, which the
	// junction is not the mount of: the junction resolves to a folder whose
	// own final path is elsewhere, so it never matches.
	junction := filepath.Join(dir, "junction")
	if err := placetest.Junction(junction, granted); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Remove(junction) })
	elsewhere := writeFile(t, filepath.Join(dir, "elsewhere", "f.txt"), "x")
	nameThrough(t, filepath.Dir(mustResolve(t, elsewhere, Options{}).Path()), filepath.Join(filepath.Dir(rootPath), "junction"))
	h := open(elsewhere)
	if r, err := h.Relate(open(granted)); err != nil || r.Kind != RelationOutside {
		t.Errorf("a final path through a junction to the granted folder: %+v, %v; want outside", r, err)
	}
}

// A file behind a data tag, read for its data, is reopened through the
// walk's own handle: the folder entry is swapped for a junction between the
// two opens, and the reopen is still given the data-tag file's handle and no
// name, so the junction is never followed (ID-F4). An AF_UNIX socket file
// carries a data tag (IO_REPARSE_TAG_AF_UNIX) and needs no privilege; the
// junction's target is a local folder, so a reopen by name would contact no
// host either.
func TestADataTagFileIsReopenedThroughItsOwnHandle(t *testing.T) {
	dir, err := placetest.ShortName(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	sock := filepath.Join(dir, "data tag")
	l, err := net.Listen("unix", sock)
	if err != nil {
		t.Skip("no AF_UNIX socket file here:", err)
	}
	l.(*net.UnixListener).SetUnlinkOnClose(false)
	l.Close()
	h0, err := Open(bg, Self, sock, Options{Links: RefuseLinks})
	if err != nil {
		t.Fatal(err)
	}
	tag, err := readAttributeTag(handleOf(h0))
	want := h0.FileID().Key()
	h0.Close()
	if err != nil || tag.attributes&windows.FILE_ATTRIBUTE_REPARSE_POINT == 0 || isLink(tag) {
		t.Skipf("the socket file reads attributes %#x tag %#x, %v; not a data tag", tag.attributes, tag.tag, err)
	}
	elsewhere := filepath.Join(dir, "elsewhere")
	if err := os.Mkdir(elsewhere, 0o755); err != nil {
		t.Fatal(err)
	}
	seen := guardOpens(t)
	var given []string
	realReopen := reopenFile
	reopenFile = func(h windows.Handle, access uint32) (windows.Handle, error) {
		key, _, err := fileIDKey(h)
		given = append(given, key)
		if err != nil || key != want {
			t.Errorf("the reopen was given %s, %v; want the data-tag file's own handle %s", key, err, want)
			return 0, windows.ERROR_ACCESS_DENIED
		}
		return realReopen(h, access)
	}
	betweenOpens = func(string) {
		if err := os.Rename(sock, sock+".moved"); err != nil {
			t.Errorf("move the data-tag file aside: %v", err)
			return
		}
		if err := placetest.Junction(sock, elsewhere); err != nil {
			t.Errorf("swap in a junction: %v", err)
		}
	}
	t.Cleanup(func() {
		reopenFile, betweenOpens = realReopen, nil
		os.Remove(sock)
	})
	h, err := Open(bg, Self, sock, Options{Read: true})
	if err == nil {
		defer h.Close()
		if h.FileID().Key() != want {
			t.Errorf("Open read %s, want the data-tag file %s", h.FileID().Key(), want)
		}
	}
	t.Logf("Open for reading after the swap: %v", err)
	if errors.Is(err, windows.ERROR_DIRECTORY) || errors.Is(err, windows.ERROR_ACCESS_DENIED) {
		t.Errorf("Open for reading followed the swapped entry: %v", err)
	}
	if len(given) != 1 {
		t.Errorf("the reopen ran %d times, want once", len(given))
	}
	if n := strings.Count(strings.Join(*seen, "\n"), "data tag"); n != 1 {
		t.Errorf("the walk opened the data-tag name %d times, want once: %q", n, *seen)
	}
}

// ntReopen opens the file an identity handle holds again, through that
// handle and no name, for reading: the reopen reads the file's bytes and
// keeps its key. It is the success path of the data-tag reopen (ID-F4),
// which no data-tag file on 10.0.26200 reaches without a provider.
func TestAReopenThroughTheHandleReadsTheFile(t *testing.T) {
	f := writeFile(t, filepath.Join(t.TempDir(), "file.txt"), "visible")
	h, err := Open(bg, Self, f, Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer h.Close()
	want, _, err := fileIDKey(handleOf(h))
	if err != nil {
		t.Fatal(err)
	}
	again, err := ntReopen(handleOf(h), accessIdentity|windows.FILE_GENERIC_READ)
	if err != nil {
		t.Fatalf("reopen through the identity handle: %v", err)
	}
	r := os.NewFile(uintptr(again), f)
	defer r.Close()
	if got, _, err := fileIDKey(again); err != nil || got != want {
		t.Errorf("the reopened file reads key %s, %v; want %s", got, err, want)
	}
	if data, err := io.ReadAll(r); err != nil || string(data) != "visible" {
		t.Errorf("the reopened file reads %q, %v; want its bytes", data, err)
	}
}

// An 8.3 alias and its long name resolve to one FileID, whose path is the
// long spelling.
func TestShortAliasResolvesToTheLongFile(t *testing.T) {
	root, err := placetest.Root(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	long := writeFile(t, filepath.Join(root, "Long Named Child Folder", "model file.gguf"), "x")
	short, err := placetest.ShortName(long)
	if err != nil {
		t.Skip(err)
	}
	a, b := mustResolve(t, long, Options{}), mustResolve(t, short, Options{})
	if !a.Equal(b) || a.Path() != b.Path() || strings.Contains(b.Path(), "~") {
		t.Errorf("long %+v, short %+v", a, b)
	}
	la, err := ResolveLeaf(bg, Self, short)
	if err != nil {
		t.Fatal(err)
	}
	lb, err := ResolveLeaf(bg, Self, long)
	if err != nil {
		t.Fatal(err)
	}
	if la.Key() != lb.Key() || la.Path() != lb.Path() || la.Name() != "model file.gguf" {
		t.Errorf("leaf through the alias %s (%s), through the long name %s (%s)", la.Key(), la.Path(), lb.Key(), lb.Path())
	}
}

// A \\?\ path is read as written, so its leaf keeps a trailing dot or space
// (coordinator ruling D4, 2026-10-21): with files "name" and "name." in one
// folder, ResolveLeaf of \\?\…\name. names "name.", and its Path reads back
// as that file.
func TestAVerbatimLeafKeepsItsTrailingDotOrSpace(t *testing.T) {
	dir := mustResolve(t, t.TempDir(), Options{}).Path()
	plain := writeFile(t, filepath.Join(dir, "name"), "plain")
	plainLeaf, err := ResolveLeaf(bg, Self, plain)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"name.", "name "} {
		verbatim := `\\?\` + dir + `\` + name
		if err := os.WriteFile(verbatim, []byte(name), 0o644); err != nil {
			t.Fatalf("write %s: %v", verbatim, err)
		}
		t.Cleanup(func() { os.Remove(verbatim) })
		own := mustResolve(t, verbatim, Options{})
		if own.Equal(mustResolve(t, plain, Options{})) {
			t.Fatalf("%q and %q are one file", verbatim, plain)
		}
		leaf, err := ResolveLeaf(bg, Self, verbatim)
		if err != nil {
			t.Fatalf("ResolveLeaf %q: %v", verbatim, err)
		}
		if leaf.Name() != name || leaf.Key() == plainLeaf.Key() {
			t.Errorf("ResolveLeaf %q = %q (%s); want %q, another key than %s", verbatim, leaf.Name(), leaf.Key(), name, plainLeaf.Key())
		}
		if got, err := Resolve(bg, Self, leaf.Path(), Options{}); err != nil || !got.Equal(own) {
			t.Errorf("the leaf's path %q resolves to %s, %v; want %s", leaf.Path(), got, err, own)
		}
	}

	// A folder named "x." or "x " is made only through a \\?\ path, and the
	// final path of a file below it keeps that name. Win32 reads any other
	// spelling of it as the folder x, which exists here with a file f of
	// its own. The file f below the folder, at the parent and the
	// grandparent depth, reads back through Leaf.Path, FileID.Path,
	// PendingName.Path and its StoredFileID as itself, and lies inside the
	// folder.
	decoy := filepath.Join(dir, "x")
	if err := os.MkdirAll(filepath.Join(decoy, "sub"), 0o755); err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(decoy, "f"), "decoy")
	writeFile(t, filepath.Join(decoy, "sub", "f"), "decoy")
	for _, name := range []string{"x.", "x "} {
		top := `\\?\` + dir + `\` + name
		if err := os.MkdirAll(top+`\sub`, 0o755); err != nil {
			t.Fatalf("make %s: %v", top, err)
		}
		t.Cleanup(func() { os.RemoveAll(top) })
		folder := mustResolve(t, top, Options{})
		for _, file := range []string{top + `\f`, top + `\sub\f`} {
			if err := os.WriteFile(file, []byte("own"), 0o644); err != nil {
				t.Fatalf("write %s: %v", file, err)
			}
			own := mustResolve(t, file, Options{})
			if got, err := Resolve(bg, Self, own.Path(), Options{}); err != nil || !got.Equal(own) {
				t.Errorf("the FileID's path %q resolves to %s, %v; want %s", own.Path(), got, err, own)
			}
			leaf, err := ResolveLeaf(bg, Self, file)
			if err != nil {
				t.Fatalf("ResolveLeaf %q: %v", file, err)
			}
			if got, err := Resolve(bg, Self, leaf.Path(), Options{}); err != nil || !got.Equal(own) {
				t.Errorf("the leaf's path %q resolves to %s, %v; want %s", leaf.Path(), got, err, own)
			}
			if got, err := Resolve(bg, Self, leaf.Folder().Path(), Options{}); err != nil || !got.Equal(leaf.Folder()) {
				t.Errorf("the leaf's folder path %q resolves to %s, %v; want %s", leaf.Folder().Path(), got, err, leaf.Folder())
			}
			if stored, err := own.Stored(); err == nil {
				if got, state, err := Revalidate(bg, stored); err != nil || state != StateSame || !got.Equal(own) {
					t.Errorf("Revalidate %s = %s, %s, %v; want the file, same", stored, got, state, err)
				}
			}
			pending, err := Pending(bg, Self, file+".new")
			if err != nil {
				t.Errorf("Pending %q: %v", file+".new", err)
			} else if again, err := Pending(bg, Self, pending.Path()); err != nil || again.Key() != pending.Key() {
				t.Errorf("the pending path %q keys %s, %v; want %s", pending.Path(), again.Key(), err, pending.Key())
			}
			h, err := Open(bg, Self, file, Options{})
			if err != nil {
				t.Fatal(err)
			}
			fh, err := Open(bg, Self, top, Options{})
			if err != nil {
				h.Close()
				t.Fatal(err)
			}
			r, err := h.Relate(fh)
			h.Close()
			fh.Close()
			if err != nil || r.Kind != RelationInside {
				t.Errorf("%s relates to %s as %s, %v; want inside", file, folder, r.Kind, err)
			}
		}
	}
}

// A leaf in a case-insensitive folder keys "Counter.json" and "counter.json"
// alike before either exists; in a case-sensitive folder they stay two.
func TestLeafKeyFollowsTheFoldersCaseRule(t *testing.T) {
	dir := t.TempDir()
	a, err := ResolveLeaf(bg, Self, filepath.Join(dir, "Counter.json"))
	if err != nil {
		t.Fatal(err)
	}
	b, err := ResolveLeaf(bg, Self, filepath.Join(dir, "counter.json"))
	if err != nil {
		t.Fatal(err)
	}
	if a.Key() != b.Key() {
		t.Errorf("case-insensitive folder: %s and %s", a.Key(), b.Key())
	}
	twins := filepath.Join(dir, "twins")
	if err := os.Mkdir(twins, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := placetest.CaseSensitive(twins); err != nil {
		t.Skip(err)
	}
	a, _ = ResolveLeaf(bg, Self, filepath.Join(twins, "Counter.json"))
	b, _ = ResolveLeaf(bg, Self, filepath.Join(twins, "counter.json"))
	if a.Key() == b.Key() {
		t.Errorf("case-sensitive folder: one key %s for two names", a.Key())
	}
}

func TestLeafNameStaysWithItsHeldFolderAfterJunctionSwap(t *testing.T) {
	dir := t.TempDir()
	folder, other := filepath.Join(dir, "folder"), filepath.Join(dir, "other")
	for _, p := range []string{folder, other} {
		if err := os.Mkdir(p, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	honest := writeFile(t, filepath.Join(folder, "long canonical honest.txt"), "honest")
	decoy := writeFile(t, filepath.Join(other, "long canonical decoy.txt"), "decoy")
	a, err := placetest.ShortName(honest)
	if err != nil {
		t.Skip("8.3 aliases unavailable:", err)
	}
	b, err := placetest.ShortName(decoy)
	if err != nil || filepath.Base(a) != filepath.Base(b) || filepath.Base(a) == filepath.Base(honest) {
		t.Skipf("matching 8.3 aliases unavailable: %q, %q, %v", a, b, err)
	}
	alias := filepath.Join(folder, filepath.Base(a))
	swapped := false
	var swapErr error
	stop, ok := ObserveOpens(func(path string) {
		if path != alias || swapped {
			return
		}
		swapped = true
		if swapErr = os.Rename(folder, folder+".held"); swapErr == nil {
			swapErr = placetest.Junction(folder, other)
		}
	})
	if !ok {
		t.Fatal("open observer already owned")
	}
	defer stop()
	got, err := ResolveLeaf(bg, Self, alias)
	if swapErr != nil {
		t.Fatal("owned folder swap:", swapErr)
	}
	if !swapped {
		t.Fatal("leaf lookup did not reach the held-folder seam")
	}
	if err == nil && got.Name() != filepath.Base(honest) {
		t.Fatalf("held folder answered decoy name %q; want %q or refusal", got.Name(), filepath.Base(honest))
	}
}

// ResolveLeaf reads the canonical name from its held folder. Replacing the
// entry during that lookup must not require or leave a handle on the leaf.
func TestResolvingALeafNeverRefusesARenameOverIt(t *testing.T) {
	dir := t.TempDir()
	const canonical = "Store.JSON"
	leaf := writeFile(t, filepath.Join(dir, canonical), "old")
	next := writeFile(t, filepath.Join(dir, "replacement.tmp"), "new")
	request := filepath.Join(dir, "store.json")

	realOpen := openAt
	openAt = func(parent windows.Handle, name string, access, disposition, options uint32) (windows.Handle, error) {
		if strings.EqualFold(name, canonical) {
			t.Error("leaf resolution attempted to open the replaced file")
			return 0, windows.ERROR_ACCESS_DENIED
		}
		return realOpen(parent, name, access, disposition, options)
	}
	defer func() { openAt = realOpen }()

	var renameErr error
	replaced := false
	stop, ok := ObserveOpens(func(path string) {
		if path == request && !replaced {
			replaced = true
			renameErr = os.Rename(next, leaf)
		}
	})
	if !ok {
		t.Fatal("open observer already owned")
	}
	defer stop()

	got, err := ResolveLeaf(bg, Self, request)
	if !replaced || renameErr != nil {
		t.Fatalf("rename during held-folder lookup: attempted=%v err=%v", replaced, renameErr)
	}
	if err != nil || got.Name() != canonical {
		t.Fatalf("resolve replaced leaf: name=%q err=%v", got.Name(), err)
	}
	if data, err := os.ReadFile(leaf); err != nil || string(data) != "new" {
		t.Fatalf("replacement contents: %q, %v", data, err)
	}
}
