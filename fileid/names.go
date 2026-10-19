package fileid

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

// Leaf is a name beneath a folder: the folder's FileID and the leaf name
// under the folder's case rule. It is the key of a file that is replaced by
// renaming a new file over its name. A rename-over gives the file a new ID,
// so a lock or a record keyed by the file's own FileID splits into two
// across a write (W0-06(a)); the folder and the name stay.
type Leaf struct {
	folder        FileID
	name          string
	caseSensitive bool
}

// Folder is the folder the leaf is in.
func (l Leaf) Folder() FileID { return l.folder }

// Name is the leaf name: the name the folder holds when a file has it (an
// 8.3 alias reads in its long form), else the name as written, without the
// trailing dots and spaces Windows strips when it creates a name. A \\?\
// path's leaf keeps them, since Windows reads that path as written.
func (l Leaf) Name() string { return l.name }

// Path is the folder's final path and the leaf name, the one spelling every
// spelling of the leaf reads as. A lock or staged file beside the leaf is
// named from it. On Windows a path with a name ending in a dot or a space,
// the leaf's or a folder's above it, is spelled as a \\?\ path (exactPath).
func (l Leaf) Path() string { return exactPath(filepath.Join(l.folder.path, l.name)) }

// exactPath spells p, a final path, so that Windows reads it as written. A
// name ending in a dot or a space is made only through a \\?\ path, a final
// path keeps it, and Win32 strips it from any other spelling, which then
// names another file or none (coordinator ruling D4, 2026-10-21). On
// Windows a drive path with such a name in any component is therefore
// spelled as a \\?\ path; every other path is p.
func exactPath(p string) string {
	if runtime.GOOS != "windows" || len(filepath.VolumeName(p)) != 2 {
		return p
	}
	for _, name := range strings.FieldsFunc(p[2:], func(r rune) bool { return r == '\\' || r == '/' }) {
		if strings.TrimRight(name, ". ") != name {
			return `\\?\` + p
		}
	}
	return p
}

// Key is the folder's key and the leaf name, the name folded through the
// system uppercase table unless the folder is case-sensitive. Two spellings
// of one leaf have one key.
func (l Leaf) Key() string {
	name := l.name
	if !l.caseSensitive {
		name = pathNameKey(name)
	}
	return l.folder.key + "/" + name
}

// ResolveLeaf resolves the folder above path in peer's view, links followed
// as Open follows them, and names the leaf beneath it. The folder is the
// spelling before the last separator, walked as Open walks it: on POSIX a
// ".." in it goes up from where a link led (coordinator ruling D2,
// 2026-10-21). The leaf itself is not followed and need not exist. On
// Windows a leaf SafeName refuses is refused, apart from the trailing dots
// and spaces a \\?\ path keeps; elsewhere a leaf is refused only when it
// names no file in the folder ("", "." or ".."), since a POSIX name may hold
// a colon or a device word.
func ResolveLeaf(ctx context.Context, peer Peer, path string) (Leaf, error) {
	if err := view(peer); err != nil {
		return Leaf{}, err
	}
	if err := located(peer, path); err != nil {
		return Leaf{}, err
	}
	if err := spellingLocal(path); err != nil {
		return Leaf{}, err
	}
	abs, err := absolute(path)
	if err != nil {
		return Leaf{}, err
	}
	if trimmed := strings.TrimRight(abs, `/`+string(filepath.Separator)); trimmed != "" && filepath.VolumeName(trimmed) != trimmed {
		abs = trimmed
	}
	folder, name := splitLeaf(abs)
	if runtime.GOOS == "windows" {
		check := name
		if !verbatim(abs) {
			name = strings.TrimRight(name, ". ")
			check = name
		} else if trimmed := strings.TrimRight(name, ". "); trimmed != "" {
			// Windows reads a \\?\ path as written, so the leaf keeps its
			// trailing dots and spaces (D4) and passes every other rule.
			check = trimmed
		}
		if err := SafeName(check); err != nil {
			return Leaf{}, err
		}
	} else if name == "" || name == "." || name == ".." {
		return Leaf{}, fmt.Errorf("%w: %q names no file in its folder", ErrUnsafeName, name)
	}
	h, err := Open(ctx, peer, folder, Options{})
	if err != nil {
		return Leaf{}, err
	}
	defer h.Close()
	if !h.id.dir {
		return Leaf{}, fmt.Errorf("fileid: %s is not a folder", folder)
	}
	onDisk, caseSensitive, err := leafName(h, name)
	if err != nil {
		return Leaf{}, err
	}
	return Leaf{folder: h.id, name: onDisk, caseSensitive: caseSensitive}, nil
}

// verbatim reports whether path is a Windows \\?\ path, which Windows reads
// as written.
func verbatim(path string) bool {
	return runtime.GOOS == "windows" && strings.HasPrefix(strings.ReplaceAll(path, "/", `\`), `\\?\`)
}

// splitLeaf splits an absolute path at its last separator by text, without
// cleaning it, so the folder keeps each ".." for the walk to read where the
// kernel reads it. A folder that is a volume keeps its separator.
func splitLeaf(abs string) (folder, name string) {
	seps := "/"
	if runtime.GOOS == "windows" {
		seps = `\/`
	}
	i := strings.LastIndexAny(abs, seps)
	if i < 0 {
		return ".", abs
	}
	folder = abs[:i]
	if len(folder) <= len(filepath.VolumeName(abs)) {
		folder = abs[:i+1]
	}
	return folder, abs[i+1:]
}

// absolute makes path absolute against the working folder: on Windows as
// Win32 reads it (GetFullPathName, which removes "." and ".." by spelling),
// elsewhere without cleaning, since a POSIX kernel walks ".." from where a
// link led. A path naming a data stream is refused (withoutStream).
func absolute(path string) (string, error) {
	if path == "" {
		return "", errors.New("identity: empty path")
	}
	if runtime.GOOS == "windows" {
		if verbatim(path) {
			return withoutStream(path)
		}
		abs, err := filepath.Abs(path)
		if err != nil {
			return "", err
		}
		return withoutStream(abs)
	}
	if filepath.IsAbs(path) {
		return withoutStream(path)
	}
	wd, err := os.Getwd()
	if err != nil {
		return "", err
	}
	return withoutStream(wd + string(filepath.Separator) + path)
}

// located refuses a relative path from any peer other than Self: a relative
// path is read against this process's working folder, which names nothing
// the caller chose (ID-F2).
func located(peer Peer, path string) error {
	if _, ok := peer.(self); ok || filepath.IsAbs(path) {
		return nil
	}
	return fmt.Errorf("%w: %q is not an absolute path", ErrUnsafeName, path)
}

// PendingName is a name for a file that may not exist yet: a stable root's
// FileID and the names below it. A download target, a rule for a program not
// yet installed and a folder about to be created key by it.
type PendingName struct {
	root FileID
	rest []string
}

// Root is the stable root the name is anchored at.
func (p PendingName) Root() FileID { return p.root }

// Path is the root's final path and the names below it, spelled as
// exactPath spells it.
func (p PendingName) Path() string {
	return exactPath(filepath.Join(append([]string{p.root.path}, p.rest...)...))
}

// Key is the root's key and the names below it, each folded as PathNameKey
// folds a name. Two spellings of one pending name have one key while the
// part of it that exists keeps its identity.
func (p PendingName) Key() string {
	parts := make([]string, len(p.rest))
	for i, name := range p.rest {
		parts[i] = pathNameKey(name)
	}
	return p.root.key + "/" + strings.Join(parts, "/")
}

// Pending names path, which may not exist yet, in peer's view. The deepest
// existing folder or file on the way is resolved as Open resolves it, each
// step up taken by text from the spelling, never by cleaning it, so on POSIX
// a ".." goes up from where a link led (coordinator ruling D2,
// 2026-10-21); a ".." that would be a name still to be created is refused by
// SafeName. The anchor is the nearest of roots at or above it, or the volume
// root. Each
// folder above the deepest existing one is read as Relate reads one, and a
// folder whose own final path is elsewhere (a link swapped in meanwhile)
// refuses the call with ErrLink. roots are
// the stable roots the caller's store anchors at, taken from storage's layout
// (STO-L2): the person's home folder, the Program Files folders,
// %LOCALAPPDATA%\Programs, /Applications. A deepest existing app folder is
// never an anchor, since a reinstall recreates it with a new ID. Two keys
// compare only under the same roots. The names still to be created keep their
// spelling, without the trailing dots and spaces Windows strips when it
// creates a name, and each must pass SafeName.
func Pending(ctx context.Context, peer Peer, path string, roots ...string) (PendingName, error) {
	if err := view(peer); err != nil {
		return PendingName{}, err
	}
	if err := located(peer, path); err != nil {
		return PendingName{}, err
	}
	if err := spellingLocal(path); err != nil {
		return PendingName{}, err
	}
	abs, err := absolute(trimCreatedNames(path))
	if err != nil {
		return PendingName{}, err
	}
	var rest []string
	existing := abs
	var id FileID
	for {
		id, err = Resolve(ctx, peer, existing, Options{})
		if err == nil {
			break
		}
		if !errors.Is(err, fs.ErrNotExist) {
			return PendingName{}, err
		}
		up, name := splitLeaf(existing)
		if up == existing {
			return PendingName{}, err
		}
		if name != "." && name != "" {
			if err := SafeName(name); err != nil {
				return PendingName{}, err
			}
			rest = append([]string{name}, rest...)
		}
		existing = up
	}
	anchors := map[string]bool{}
	for _, r := range roots {
		if rid, err := Resolve(ctx, Self, r, Options{}); err == nil && rid.dir {
			anchors[rid.key] = true
		}
	}
	for p := id.path; ; p = filepath.Dir(p) {
		pid := id
		if p != id.path {
			if pid, err = ancestorAt(ctx, p); err != nil {
				return PendingName{}, err
			}
		}
		if anchors[pid.key] || filepath.Dir(p) == p {
			below := strings.FieldsFunc(id.path[len(p):], func(r rune) bool { return r == '/' || r == filepath.Separator })
			return PendingName{root: pid, rest: append(below, rest...)}, nil
		}
	}
}
