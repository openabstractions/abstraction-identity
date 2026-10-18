package privatedir

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	identity "github.com/openabstractions/abstraction-identity"
)

// ErrNotModelFolder reports a folder CheckModelFolder or ProtectModelFolder
// refuses, or a models root CheckModelsRoot refuses (identity CONTRACT.md
// ID-D3).
var ErrNotModelFolder = errors.New("privatedir: folder is not a model folder of this account")

// ProtectModelFolder makes dir, an existing folder this account keeps model
// files in, a model folder (ID-D3). On Windows it is owned by this account
// with a protected DACL of three entries, this account, SYSTEM and
// Administrators with full control, and every file and folder below it is
// owned by this account and carries exactly those entries as inherited
// from it, whatever a move or a copy left on it. Elsewhere no group or
// other write bit remains on the folder or below it.
//
// Every entry is opened as itself (never through a link) and held before
// anything changes, and each is written through its own handle, never by
// path; no inheritance is propagated by the system. The whole folder is
// refused, and nothing changes, when dir or anything below it is a link or
// junction, or a file below it has another name outside every folder in
// roots (on Windows its names are enumerated; elsewhere a file of more
// than one name is refused). Every root that exists must pass
// CheckModelsRoot, so a broad root such as a drive root or the home cannot
// widen what counts as OA's own; a root that does not exist holds no name
// and is left out. dir must lie under one of roots. It then applies
// CheckModelFolder.
func ProtectModelFolder(dir string, roots []string) error {
	if !filepath.IsAbs(dir) {
		return fmt.Errorf("%w: %q is not absolute", ErrNotModelFolder, dir)
	}
	dir = filepath.Clean(dir)
	clean := make([]string, 0, len(roots))
	for _, r := range roots {
		if !filepath.IsAbs(r) {
			return fmt.Errorf("%w: root %q is not absolute", ErrNotModelFolder, r)
		}
		r = filepath.Clean(r)
		if err := identity.LocalPath(r); err != nil {
			return fmt.Errorf("%w: root %s: %v", ErrNotModelFolder, r, err)
		}
		if _, err := os.Lstat(r); errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err := CheckModelsRoot(r); err != nil {
			return err
		}
		clean = append(clean, r)
	}
	if !under(dir, clean) {
		return fmt.Errorf("%w: %s lies under none of %q", ErrNotModelFolder, dir, clean)
	}
	if err := protectModels(dir, clean); err != nil {
		return fmt.Errorf("%w: %s: %v", ErrNotModelFolder, dir, err)
	}
	return CheckModelFolder(dir)
}

// CheckModelFolder refuses dir (ErrNotModelFolder) unless it is a model
// folder of this account (ID-D3).
func CheckModelFolder(dir string) error {
	if !filepath.IsAbs(dir) {
		return fmt.Errorf("%w: %q is not absolute", ErrNotModelFolder, dir)
	}
	if err := checkModels(filepath.Clean(dir)); err != nil {
		return fmt.Errorf("%w: %s: %v", ErrNotModelFolder, dir, err)
	}
	return nil
}

// CheckModelsRoot refuses root (ErrNotModelFolder) as a folder OA owns, one
// it keeps model folders in or its job store, when it is a drive or volume root, this account's home or
// a folder that holds it, or one of its known folders (Documents, Desktop,
// Downloads, AppData and its Roaming and Local folders); when it or any
// folder above it is a link or junction; when it does not resolve to
// itself (ID-D3); and when it does not exist or identity.LocalPath refuses
// it, since the home check cannot then be made (ID-F1).
func CheckModelsRoot(root string) error {
	if !filepath.IsAbs(root) {
		return fmt.Errorf("%w: models root %q is not absolute", ErrNotModelFolder, root)
	}
	root = filepath.Clean(root)
	if filepath.Dir(root) == root {
		return fmt.Errorf("%w: models root %s is a drive or volume root", ErrNotModelFolder, root)
	}
	// A root identity refuses (a share, a network volume) cannot be compared
	// with the home, so it is refused before any comparison (ID-F1).
	if err := identity.LocalPath(root); err != nil {
		return fmt.Errorf("%w: models root %s: %v", ErrNotModelFolder, root, err)
	}
	if _, err := os.Lstat(root); err != nil {
		return fmt.Errorf("%w: models root %s: %v", ErrNotModelFolder, root, err)
	}
	if err := checkRoot(root); err != nil {
		return fmt.Errorf("%w: models root %s: %v", ErrNotModelFolder, root, err)
	}
	return nil
}

// under reports whether p is one of roots or lies below one, by file identity
// (identity.SameFile and identity.Within). A root that cannot be compared,
// such as one LocalPath refuses, does not count: the caller refuses p unless
// it is under a root.
func under(p string, roots []string) bool {
	for _, r := range roots {
		if ok, err := underRoot(p, r); err == nil && ok {
			return true
		}
	}
	return false
}

// underRoot is under for one root, with the identity error when p and root
// could not be compared.
func underRoot(p, root string) (bool, error) {
	same, err := identity.SameFile(p, root)
	if err == nil && same {
		return true, nil
	}
	inside, werr := identity.Within(p, root)
	if werr == nil {
		return inside, nil
	}
	if err == nil {
		err = werr
	}
	return false, err
}

// holds reports whether p is one of others or holds one of them. Any other
// that cannot be compared with p, such as when LocalPath refuses either,
// may be held, so holds answers true: its caller refuses p.
func holds(p string, others []string) bool {
	for _, o := range others {
		if o == "" {
			continue
		}
		if ok, err := underRoot(o, p); err != nil || ok {
			return true
		}
	}
	return false
}
