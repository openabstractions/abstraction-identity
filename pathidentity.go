package identity

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// Path identity has one owner, here, and three questions, each with its own
// function. Whether two paths name one file is asked of the filesystem
// (VISION.md L623, the 2026-09-08 ruling; DL-R31: os.SameFile):
//
//   - SameFile: do two existing paths name one file? File identity answers.
//   - Within: does an existing path lie inside an existing folder? File
//     identity of each parent answers.
//   - SamePathName: are two names one name, for a file that may not exist
//     yet? Only rights rules naming a program not yet installed, collision
//     checks before placement, and fixed or pinned file names ask it.
//
// FileKey keys a set or map of existing files by the same identity.
//
// Every one of them asks the filesystem only about a path on a local drive or
// volume (LocalPath). Any other path is refused with a *NotLocalPathError before
// anything is opened: opening a UNC path sends the account's credentials to
// that host and can stall for as long as the host takes to answer, and a pipe
// or device opened by name runs its owner's code.

// ErrNotLocalPath is what errors.Is matches for a path identity refuses to
// open (LocalPath).
var ErrNotLocalPath = errors.New("identity: the path is not on a local drive")

// NotLocalPathError refuses a path that is not on a local drive. Nothing was
// opened for it.
type NotLocalPathError struct {
	Path   string
	Reason string
}

func (e *NotLocalPathError) Error() string {
	return "identity: " + e.Path + " is not on a local drive: " + e.Reason
}

// Is makes errors.Is(err, ErrNotLocalPath) true.
func (e *NotLocalPathError) Is(target error) bool { return target == ErrNotLocalPath }

// LocalPath reports whether identity's path functions may open path. On
// Windows that is an absolute path on a local drive letter, given directly or
// as \\?\X:\, with no component that is a reserved device name (CON, PRN,
// AUX, NUL, COM0-9, LPT0-9 and their superscript forms, CONIN$, CONOUT$) in
// any folder and with any extension; a UNC path, a \\.\ or other \\?\ path,
// an NT object path and a network drive letter are refused. On macOS a path
// is local when the volume holding it, or its deepest existing folder,
// reports MNT_LOCAL to statfs within a short deadline; a network volume and
// one that does not answer are refused; a mount that stops answering refuses
// only paths spelled on it. On Linux the volume's file system
// type decides under the same deadline: NFS, SMB/CIFS, Ceph, AFS, 9P and the
// other network and shared file systems are refused, and a FUSE mount is
// local only when its type in /proc/self/mountinfo is known local (fuseblk,
// lxcfs, squashfuse, fuse-overlayfs). Elsewhere every path is local. It
// reads the spelling, the drive's type or the volume's mount flags or type,
// and opens nothing on the volume; a refusal is a *NotLocalPathError.
func LocalPath(path string) error { return localPath(path) }

// SameFile reports whether a and b name one existing file, by file identity:
// the volume serial number and file ID (FileKey), as os.SameFile compares
// them. A junction or symbolic link and its target are one file, and so are
// an 8.3 alias and its long name; two names the volume keeps apart, such as
// twins that differ by a KELVIN SIGN or a LONG S, are two. When either side
// is refused (LocalPath) or cannot be read, SameFile answers false with that
// error.
func SameFile(a, b string) (bool, error) {
	if err := localPath(a); err != nil {
		return false, err
	}
	if err := localPath(b); err != nil {
		return false, err
	}
	ka, err := fileKey(a)
	if err != nil {
		return false, err
	}
	kb, err := fileKey(b)
	if err != nil {
		return false, err
	}
	return ka == kb, nil
}

// Within reports whether path lies strictly inside folder, by file identity:
// the deepest existing folder above path is first resolved through links, so
// a file reached through a junction counts where it actually is, and then
// each parent of the resolved path is compared with folder as SameFile
// compares. path itself need not exist, nor the folders still to be created
// on the way to it; their names stay as written. folder must exist; when
// either is refused (LocalPath), or folder or every folder above path cannot
// be read, Within answers false with the error.
func Within(path, folder string) (bool, error) {
	_, ok, err := WithinRel(path, folder)
	return ok, err
}

// WithinRel is Within that also returns the resolved path's remainder below
// folder, with the platform's separators.
func WithinRel(path, folder string) (string, bool, error) {
	if err := localPath(folder); err != nil {
		return "", false, err
	}
	if err := localPath(path); err != nil {
		return "", false, err
	}
	target, err := fileKey(folder)
	if err != nil {
		return "", false, err
	}
	resolved, err := resolveExisting(path, false)
	if err != nil {
		return "", false, err
	}
	for p := filepath.Dir(resolved); ; p = filepath.Dir(p) {
		if key, err := fileKey(p); err == nil && key == target {
			rel := strings.TrimLeft(resolved[len(p):], `/`+string(filepath.Separator))
			return rel, rel != "", nil
		}
		if filepath.Dir(p) == p {
			return "", false, nil
		}
	}
}

// Inside is Within for a folder that may not exist yet: when folder exists,
// Within answers. When folder does not exist, nothing can lie in it except a
// path spelled exactly below it, so path's cleaned spelling must begin with
// folder's and a separator; no case is folded. Every other failure answers
// false: either path refused (LocalPath), which is never opened, and a
// folder or path that cannot be read. A caller for whom false is the
// permissive answer checks LocalPath itself.
func Inside(path, folder string) bool {
	_, inside, _ := InsideRel(path, folder)
	return inside
}

// InsideRel is Inside that returns path's remainder below folder, with the
// platform's separators, and the error behind a false answer: a
// *NotLocalPathError (errors.Is ErrNotLocalPath) for a refused path, or the
// read error when folder exists but the question could not be asked. A
// caller tells "outside" (nil error) from "not answered" by the error.
func InsideRel(path, folder string) (string, bool, error) {
	rel, inside, err := WithinRel(path, folder)
	if err == nil || errors.Is(err, ErrNotLocalPath) {
		return rel, inside, err
	}
	// WithinRel checked both paths with LocalPath, so folder is local here.
	if _, lerr := os.Lstat(folder); !errors.Is(lerr, fs.ErrNotExist) {
		return "", false, err
	}
	prefix := strings.TrimRight(filepath.Clean(folder), `/`+string(filepath.Separator)) + string(filepath.Separator)
	rest, ok := strings.CutPrefix(filepath.Clean(path), prefix)
	if !ok || rest == "" {
		return "", false, nil
	}
	return rest, true, nil
}

// resolveExisting cleans path to an absolute path and resolves the deepest
// existing part of it through links; the rest stays as written. With self
// false only the folders above path are resolved, path's own name staying as
// written: a file another process is replacing at that moment does not fail
// the question, and a link's own entry lies where its folder lies. With self
// true, path itself is resolved when it exists. The caller has checked path
// with localPath.
func resolveExisting(path string, self bool) (string, error) {
	if path == "" {
		return "", errors.New("identity: empty path")
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	abs = filepath.Clean(abs)
	existing, rest := abs, ""
	if !self && filepath.Dir(abs) != abs {
		existing, rest = filepath.Dir(abs), filepath.Base(abs)
	}
	for !pathExists(existing) {
		up := filepath.Dir(existing)
		if up == existing {
			return "", &pathError{op: "stat", path: path, err: os.ErrNotExist}
		}
		rest = filepath.Join(filepath.Base(existing), rest)
		existing = up
	}
	real, err := resolveLinks(existing)
	if err != nil {
		return "", err
	}
	if rest == "" {
		return real, nil
	}
	return filepath.Join(real, rest), nil
}

// FileKey is a key for a set or map of existing files: the volume serial
// number and file ID, which two paths share exactly when SameFile reports
// them one file. A path refused (LocalPath) or unreadable has no key.
func FileKey(path string) (string, error) {
	if err := localPath(path); err != nil {
		return "", err
	}
	return fileKey(path)
}

// PlaceKey is a key for a file or folder that may not exist yet, such as a
// folder an install is about to create. The part of path that exists is
// replaced by its final path, the kernel's one spelling of it after links,
// junctions and 8.3 aliases (as Within resolves it); the part still to be
// created keeps its names, each without the trailing dots and spaces Windows
// strips when it creates a name. The result is keyed as PathNameKey keys
// names. The key stays the same as folders on the way are created, so a lock
// keyed by it serialises work started before and after. A path refused by
// LocalPath has no key.
func PlaceKey(path string) (string, error) {
	if err := localPath(path); err != nil {
		return "", err
	}
	resolved, err := resolveExisting(trimCreatedNames(path), true)
	if err != nil {
		return "", err
	}
	return PathNameKey(resolved), nil
}

type pathError struct {
	op, path string
	err      error
}

func (e *pathError) Error() string { return "identity: " + e.op + " " + e.path + ": " + e.err.Error() }
func (e *pathError) Unwrap() error { return e.err }
