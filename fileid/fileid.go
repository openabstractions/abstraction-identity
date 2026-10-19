// Package fileid is OA's one owner of file identity (ID-F1; PLAN 0.8.0 T12).
// A path is a locator: a spelling a person typed, a request carried or a
// tool needs. fileid resolves a path once, in the caller's view, and returns
// a FileID, what the operating system says the file is: the volume and file
// ID read from an open handle, the final path for display, the number of
// names the file has, and whether the ID survives a reboot (Durability). An
// effect on the file goes through a Handle, the open file the same walk
// returned. A store keeps a StoredFileID and reads it back only through
// Revalidate.
//
// The walk opens each component of the path without following it. A
// junction or symbolic link is read, and its target is checked to be on a
// local drive before anything below it is opened: a link to a share is
// refused before the share is contacted. A data reparse point, such as a
// cloud files placeholder or a WOF-compressed file, is a regular file.
//
// Three name comparisons remain, each with its own form: a leaf name beneath
// a locked folder (Leaf), a name that does not exist yet beneath a stable
// root (Pending), and a collision found by creating the name exclusively
// (CreateExclusive). Every other "same file" or "inside" question compares
// FileIDs (Relate).
//
// The path functions identity exported before this package (SameFile,
// Within, FileKey, PlaceKey and the rest) live here unchanged, and identity
// keeps them as wrappers until their consumers move (PT-3b).
package fileid

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

// Durability says whether a FileID's key names the same file after a reboot
// and a remount.
type Durability int

const (
	// Volatile keys hold within one session: FAT and exFAT, whose IDs change
	// when a name is rewritten, and file systems that reuse IDs without a
	// generation. An authority store refuses them (StoredFileID).
	Volatile Durability = iota
	// Persistent keys survive a reboot: NTFS and ReFS with a 128-bit file
	// ID, APFS and HFS+, and the Linux file systems with stable inodes.
	Persistent
)

func (d Durability) String() string {
	if d == Persistent {
		return "persistent"
	}
	return "volatile"
}

// FileID is what the operating system says a file is: its volume and file
// ID, read from an open handle. Two FileIDs name one file exactly when their
// keys are equal. The zero FileID names no file, and every function that
// takes one refuses it.
type FileID struct {
	key        string
	path       string
	durability Durability
	links      int
	dir        bool
}

// Key is the volume and file ID: on Windows the volume serial number and the
// 128-bit file ID, on POSIX the device and inode numbers. It is the key
// identity's FileKey gives the same file, and it holds within one host.
func (f FileID) Key() string { return f.key }

// Path is the final spelling of the file, read once from the handle for
// display, spelled as exactPath spells it so that it reads back as the
// file. It is never a key.
func (f FileID) Path() string { return exactPath(f.path) }

// Durability says whether Key survives a reboot.
func (f FileID) Durability() Durability { return f.durability }

// Links is the number of names the file has. A file with more than one name
// is in more than one folder at once (a hard link); containment that
// authorizes refuses it (Relation.MultiName). A folder's count is the
// platform's own (on POSIX it counts "." and each subfolder's ".."), and a
// folder has one name.
func (f FileID) Links() int { return f.links }

// IsDir reports whether the file is a folder.
func (f FileID) IsDir() bool { return f.dir }

// IsZero reports whether f names no file.
func (f FileID) IsZero() bool { return f.key == "" }

// Equal reports whether f and g name one file. A zero FileID equals nothing.
func (f FileID) Equal(g FileID) bool { return f.key != "" && f.key == g.key }

func (f FileID) String() string {
	if f.IsZero() {
		return "fileid: no file"
	}
	return f.path + " (" + f.key + ")"
}

// Handle is an open file and its FileID. Reading a resolved file, opening a
// name below it (Beneath) and creating a name in it (CreateExclusive) go
// through it, so the file acted on is the file that was resolved. A Handle
// from Open holds identity access, and read access under Options.Read; on
// Windows it shares reading, writing and deleting with every other open.
// Write, access-list and delete access are not built (ID-F1).
type Handle struct {
	f  *os.File
	id FileID
}

// File is the open file. On Linux a Handle opened without Options.Read is an
// O_PATH descriptor, which answers Stat and serves as a folder for Beneath
// and CreateExclusive but reads no data.
func (h Handle) File() *os.File { return h.f }

// FileID is the identity of the open file.
func (h Handle) FileID() FileID { return h.id }

// Close closes the file.
func (h Handle) Close() error {
	if h.f == nil {
		return nil
	}
	return h.f.Close()
}

// Links is the link policy of a walk.
type Links int

const (
	// FollowLocalLinks follows a junction or symbolic link whose target is
	// on a local drive, and refuses one whose target is not, before anything
	// at the target is opened.
	FollowLocalLinks Links = iota
	// RefuseLinks refuses every junction and symbolic link on the path.
	RefuseLinks
)

// Options shape one resolution.
type Options struct {
	// Links is the link policy; the zero value follows local links.
	Links Links
	// Read opens the file for reading too. Without it the handle reads
	// identity only, and a cloud files placeholder is not recalled.
	Read bool
}

// Peer is the caller a path comes from. *identity.Peer is one, the same
// argument identity.SubjectOf takes; Self is this process.
type Peer interface {
	// SameView reports whether a path from this caller names, in this
	// process, the file it names for the caller: nil when it does, and an
	// error matching ErrOtherView when the caller's namespace differs, as a
	// packaged app's virtualized folders, an AppContainer, a sandboxed app,
	// a WSL program, another account and a remote peer do.
	SameView() error
}

type self struct{}

func (self) SameView() error { return nil }

// Self is this process as the caller: a service resolving its own files.
var Self Peer = self{}

var (
	// ErrOtherView refuses a path from a caller whose paths name other files
	// than this process's (Peer.SameView). Nothing is opened for it.
	ErrOtherView = errors.New("fileid: the caller's paths name other files than this process's")
	// ErrLink refuses a junction or symbolic link the walk's policy does not
	// follow (RefuseLinks), or a link of a kind fileid does not read.
	ErrLink = errors.New("fileid: a link on the path is refused")
	// ErrVolatile refuses to store a key the file system may reuse
	// (Durability Volatile).
	ErrVolatile = errors.New("fileid: the file system may reuse this file ID; it is not stored")
	// ErrUnsafeName refuses a name SafeName refuses, a path naming a data
	// stream, and a relative path from a peer other than Self.
	ErrUnsafeName = errors.New("fileid: not a safe file name")
	// ErrNoFile refuses a zero FileID or Handle.
	ErrNoFile = errors.New("fileid: no file")
)

func view(peer Peer) error {
	if peer == nil {
		return fmt.Errorf("%w: no peer", ErrOtherView)
	}
	if err := peer.SameView(); err != nil {
		if errors.Is(err, ErrOtherView) {
			return err
		}
		return fmt.Errorf("%w: %v", ErrOtherView, err)
	}
	return nil
}

// Open resolves path in peer's view and returns the open file. In order it
// refuses: a peer whose view differs (ErrOtherView); a relative path from a
// peer other than Self and a path naming a data stream (ErrUnsafeName); a
// path LocalPath refuses; a component that is a link the policy refuses
// (ErrLink), or whose target is on no local volume (ErrNotLocalPath), before
// anything at the target is opened; and a final path off a local drive. A
// component that does not exist answers an error matching fs.ErrNotExist.
// ctx bounds the walk between components; an open in progress finishes.
func Open(ctx context.Context, peer Peer, path string, opt Options) (Handle, error) {
	if err := view(peer); err != nil {
		return Handle{}, err
	}
	if err := ctx.Err(); err != nil {
		return Handle{}, err
	}
	if path == "" {
		return Handle{}, errors.New("identity: empty path")
	}
	if err := located(peer, path); err != nil {
		return Handle{}, err
	}
	return open(ctx, path, opt)
}

// Resolve is Open that keeps only the FileID.
func Resolve(ctx context.Context, peer Peer, path string, opt Options) (FileID, error) {
	h, err := Open(ctx, peer, path, opt)
	if err != nil {
		return FileID{}, err
	}
	//unchecked: an identity query handle; closing it reports nothing a caller acts on
	h.Close()
	return h.id, nil
}

// Beneath opens name below the folder h holds, one component at a time, with
// every link refused: name is relative, and a ".." or "." component, an
// absolute name and a component SafeName refuses are refused.
func (h Handle) Beneath(name string, opt Options) (Handle, error) {
	if h.f == nil || h.id.IsZero() {
		return Handle{}, ErrNoFile
	}
	parts, err := beneathParts(name)
	if err != nil {
		return Handle{}, err
	}
	opt.Links = RefuseLinks
	return beneath(h, parts, opt)
}

func beneathParts(name string) ([]string, error) {
	if name == "" || filepath.IsAbs(name) || filepath.VolumeName(name) != "" || strings.HasPrefix(name, `\`) || strings.HasPrefix(name, "/") {
		return nil, fmt.Errorf("%w: %q is not a relative name", ErrUnsafeName, name)
	}
	parts := strings.FieldsFunc(name, func(r rune) bool { return r == '/' || r == '\\' })
	for _, p := range parts {
		if err := SafeName(p); err != nil {
			return nil, err
		}
	}
	return parts, nil
}

// RelationKind is how one file stands to another.
type RelationKind int

const (
	// RelationOutside: the file is neither the other file nor below it.
	RelationOutside RelationKind = iota
	// RelationSame: the two are one file.
	RelationSame
	// RelationInside: the file lies below the other, a folder.
	RelationInside
)

func (k RelationKind) String() string {
	switch k {
	case RelationSame:
		return "same"
	case RelationInside:
		return "inside"
	}
	return "outside"
}

// Relation is Relate's answer.
type Relation struct {
	Kind RelationKind
	// Rel is the file's final path below the folder, for RelationInside.
	Rel string
	// MultiName reports a file with more than one name: it lies in another
	// folder too, whatever Kind says, and a caller for whom containment
	// authorizes refuses it.
	MultiName bool
}

// Relate reports how the file h holds stands to the file other holds: the
// same file, inside it, or outside it, by FileID. Containment is read from
// h's final path, each folder above it resolved with local links followed
// and compared with other's FileID, and a folder matches only when its own
// final path is the folder's spelling in h's. A final path holds no link
// except the folder a volume with no drive letter is mounted on, whose
// root's final path is that folder: a link swapped in after the open
// resolves to a folder whose final path is elsewhere and never matches. Once
// a folder matches, h's own path is read again (stillAt), and a file that
// moved meanwhile is outside.
func (h Handle) Relate(other Handle) (Relation, error) {
	if h.id.IsZero() || other.id.IsZero() {
		return Relation{}, ErrNoFile
	}
	r := Relation{MultiName: !h.id.dir && h.id.links > 1}
	if h.id.Equal(other.id) {
		r.Kind = RelationSame
		return r, nil
	}
	if !other.id.dir {
		return r, nil
	}
	for p := filepath.Dir(h.id.path); ; p = filepath.Dir(p) {
		if id, err := ancestorAt(context.Background(), p); err == nil && id.Equal(other.id) {
			still, err := stillAt(h)
			if err != nil {
				return Relation{}, err
			}
			if still {
				r.Kind = RelationInside
				r.Rel = strings.TrimLeft(h.id.path[len(p):], `/`+string(filepath.Separator))
			}
			return r, nil
		}
		if filepath.Dir(p) == p {
			return r, nil
		}
	}
}

// ancestorAt resolves p, a folder in a final path, with local links followed
// and answers it only when its own final path is p. A final path holds no
// link except the folder a volume with no drive letter is mounted on, whose
// root's final path is that folder. A link swapped in for p after the final
// path was read resolves to a folder whose final path is elsewhere, and
// ancestorAt refuses it with ErrLink. Relate and Pending read the folders
// above a final path through it. A final path is already normalized, so on
// Windows a drive path is read as written, as a \\?\ path: Win32 would
// strip a trailing dot or space from a folder's name and read another
// folder (coordinator ruling D4).
func ancestorAt(ctx context.Context, p string) (FileID, error) {
	spelled := p
	if runtime.GOOS == "windows" && len(filepath.VolumeName(p)) == 2 {
		spelled = `\\?\` + p
	}
	id, err := Resolve(ctx, Self, spelled, Options{})
	if err != nil {
		return FileID{}, err
	}
	if filepath.Clean(id.path) != p {
		return FileID{}, fmt.Errorf("%w: %s now resolves to %s", ErrLink, p, id.path)
	}
	return id, nil
}

// CreateExclusive creates name, a new file, in the folder dir holds and
// opens it for reading and writing. The file system reports a collision with
// an existing name under its own case rule, as an error matching
// fs.ErrExist. name must pass SafeName.
func CreateExclusive(dir Handle, name string) (Handle, error) {
	if dir.f == nil || dir.id.IsZero() {
		return Handle{}, ErrNoFile
	}
	if err := SafeName(name); err != nil {
		return Handle{}, err
	}
	return createExclusive(dir, name)
}

// SafeName refuses a file name that names something other than an ordinary
// file in some folder on some platform OA runs on: the empty name, "." and
// "..", a name holding a separator, a NUL or a colon (an NTFS stream), a name
// ending in a dot or a space (Windows strips them), and a DOS device name
// (CON, PRN, AUX, NUL, COM0-9, LPT0-9 and their superscript forms, CONIN$,
// CONOUT$) with any extension. It applies the Windows rules on every
// platform, so a name accepted on Linux stays one name when the file moves
// to Windows. It is the one device-name rule (paths/DIAGNOSIS.md section 2.2).
func SafeName(name string) error {
	refuse := func(why string) error { return fmt.Errorf("%w: %q %s", ErrUnsafeName, name, why) }
	switch {
	case name == "":
		// "." and ".." end in a dot and are refused below with every other
		// name Windows would strip.
		return refuse("names no file")
	case strings.ContainsAny(name, "/\\\x00"):
		return refuse("holds a separator or a NUL")
	case strings.ContainsRune(name, ':'):
		return refuse("names a stream")
	case strings.HasSuffix(name, ".") || strings.HasSuffix(name, " "):
		return refuse("ends in a dot or a space, which Windows strips")
	case isDeviceName(name):
		return refuse("names a DOS device")
	}
	return nil
}

// isDeviceName is reservedDeviceName under every platform's build: the
// device list and the ordinal case rule Windows applies to it.
func isDeviceName(part string) bool {
	name := part
	if i := strings.IndexAny(name, ".:"); i >= 0 {
		name = name[:i]
	}
	name = strings.TrimRight(name, " ")
	if len(name) < 3 || len(name) > 7 || !strings.ContainsRune("CcPpAaNnLl", rune(name[0])) {
		return false
	}
	// ASCII case folds on every platform; on Windows the system uppercase
	// table also applies (samePathName), as reservedDeviceName compares.
	upper := strings.Map(func(r rune) rune {
		if r >= 'a' && r <= 'z' {
			return r - 'a' + 'A'
		}
		return r
	}, name)
	for _, device := range dosDeviceNames {
		if upper == device || samePathName(name, device) {
			return true
		}
	}
	return false
}

// dosDeviceNames are the DOS device names Win32 reads in any folder.
var dosDeviceNames = func() []string {
	names := []string{"CON", "PRN", "AUX", "NUL", "CONIN$", "CONOUT$"}
	for _, port := range []string{"COM", "LPT"} {
		for _, n := range []string{"0", "1", "2", "3", "4", "5", "6", "7", "8", "9", "¹", "²", "³"} {
			names = append(names, port+n)
		}
	}
	return names
}()
