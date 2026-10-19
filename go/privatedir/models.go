package privatedir

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"path/filepath"

	identity "github.com/openabstractions/abstraction-identity"
	"github.com/openabstractions/abstraction-identity/fileid"
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
// roots (on Windows its names are enumerated; on Unix a complete inode
// inventory under the held roots accounts for every name). Every root that exists must pass
// CheckModelsRoot, so a broad root such as a drive root or the home cannot
// widen what counts as OA's own; a root that does not exist holds no name
// and is left out. dir must lie under one of roots. It then applies
// CheckModelFolder.
func ProtectModelFolder(dir string, roots []string) error {
	if !filepath.IsAbs(dir) {
		return fmt.Errorf("%w: %q is not absolute", ErrNotModelFolder, dir)
	}
	if err := fileid.OlderPath(dir); err != nil {
		return fmt.Errorf("%w: %v", ErrNotModelFolder, err)
	}
	d, err := fileid.Open(context.Background(), fileid.Self, dir, fileid.Options{Links: fileid.RefuseLinks})
	if err != nil {
		return fmt.Errorf("%w: %v", ErrNotModelFolder, err)
	}
	defer d.Close()
	var held []fileid.Handle
	defer func() {
		for _, h := range held {
			h.Close()
		}
	}()
	for _, r := range roots {
		if !filepath.IsAbs(r) {
			return fmt.Errorf("%w: root %q is not absolute", ErrNotModelFolder, r)
		}
		if err := fileid.OlderPath(r); err != nil {
			return fmt.Errorf("%w: %v", ErrNotModelFolder, err)
		}
		h, err := fileid.Open(context.Background(), fileid.Self, r, fileid.Options{Links: fileid.RefuseLinks})
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err != nil {
			return fmt.Errorf("%w: %v", ErrNotModelFolder, err)
		}
		if !fileid.SamePathName(h.FileID().Path(), filepath.Clean(r)) {
			h.Close()
			return fmt.Errorf("%w: root does not name its final folder", ErrNotModelFolder)
		}
		held = append(held, h)
	}
	return ProtectModelFolderAt(d, held)
}

// ProtectModelFolderAt applies ProtectModelFolder's ownership rule to live
// admitted files. Handles are borrowed for this synchronous operation and
// remain owned by the caller. A moved/replaced locator is refused before
// effects; protection and its final check use the admitted held file.
func ProtectModelFolderAt(dir fileid.Handle, roots []fileid.Handle) error {
	if err := currentModelHandle(dir); err != nil {
		return fmt.Errorf("%w: %v", ErrNotModelFolder, err)
	}
	inside := false
	for _, root := range roots {
		if err := currentModelHandle(root); err != nil {
			return fmt.Errorf("%w: %v", ErrNotModelFolder, err)
		}
		if err := checkModelRootAt(root); err != nil {
			return fmt.Errorf("%w: %v", ErrNotModelFolder, err)
		}
		relation, err := dir.Relate(root)
		if err != nil {
			return fmt.Errorf("%w: %v", ErrNotModelFolder, err)
		}
		inside = inside || relation.Kind != fileid.RelationOutside
	}
	if !inside {
		return fmt.Errorf("%w: admitted folder lies under none of the roots", ErrNotModelFolder)
	}
	if err := protectModelsAt(dir, roots); err != nil {
		return fmt.Errorf("%w: %v", ErrNotModelFolder, err)
	}
	return nil
}

func currentModelHandle(h fileid.Handle) error {
	if h.File() == nil || h.FileID().IsZero() {
		return fileid.ErrNoFile
	}
	st, err := h.File().Stat()
	if err != nil {
		return err
	}
	if !st.IsDir() || !h.FileID().IsDir() {
		return errors.New("it is not a directory")
	}
	current, err := fileid.Open(context.Background(), fileid.Self, h.FileID().Path(), fileid.Options{Links: fileid.RefuseLinks})
	if err != nil {
		return err
	}
	defer current.Close()
	if !current.FileID().Equal(h.FileID()) {
		return errors.New("admitted folder changed at its locator")
	}
	return nil
}

func checkModelRootAt(root fileid.Handle) error {
	p := root.FileID().Path()
	if filepath.Dir(p) == p {
		return errors.New("it is a drive or volume root")
	}
	known := modelKnownFolders()
	for i, p := range known {
		h, err := fileid.Open(context.Background(), fileid.Self, p, fileid.Options{})
		if err != nil {
			if i == 0 {
				return fmt.Errorf("the home cannot be compared: %w", err)
			}
			continue
		}
		relation, err := h.Relate(root)
		h.Close()
		if err != nil || relation.Kind == fileid.RelationSame || (i == 0 && relation.Kind == fileid.RelationInside) {
			return fmt.Errorf("it is or holds a known folder: %s", p)
		}
	}
	return nil
}

// CheckModelFolder refuses dir (ErrNotModelFolder) unless it is a model
// folder of this account (ID-D3).
func CheckModelFolder(dir string) error {
	if !filepath.IsAbs(dir) {
		return fmt.Errorf("%w: %q is not absolute", ErrNotModelFolder, dir)
	}
	if err := fileid.OlderPath(dir); err != nil {
		return fmt.Errorf("%w: %v", ErrNotModelFolder, err)
	}
	h, err := fileid.Open(context.Background(), fileid.Self, dir, fileid.Options{Links: fileid.RefuseLinks})
	if err != nil {
		return fmt.Errorf("%w: %v", ErrNotModelFolder, err)
	}
	defer h.Close()
	if err := checkModelsAt(h); err != nil {
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
// it, since the home check cannot then be made (ID-F9).
func CheckModelsRoot(root string) error {
	if !filepath.IsAbs(root) {
		return fmt.Errorf("%w: models root %q is not absolute", ErrNotModelFolder, root)
	}
	if err := fileid.OlderPath(root); err != nil {
		return fmt.Errorf("%w: models root %s: %v", ErrNotModelFolder, root, err)
	}
	h, err := fileid.Open(context.Background(), fileid.Self, root, fileid.Options{Links: fileid.RefuseLinks})
	if err != nil {
		return fmt.Errorf("%w: models root %s: %v", ErrNotModelFolder, root, err)
	}
	defer h.Close()
	if !h.FileID().IsDir() || !identity.SamePathName(h.FileID().Path(), filepath.Clean(root)) {
		return fmt.Errorf("%w: root does not name its final folder", ErrNotModelFolder)
	}
	if err := checkModelRootAt(h); err != nil {
		return fmt.Errorf("%w: models root %s: %v", ErrNotModelFolder, root, err)
	}
	return nil
}

// under reports whether p is one of roots or lies below one, by native identity.
// A root that cannot be compared,
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
	if err := fileid.OlderPath(p); err != nil {
		return false, err
	}
	if err := fileid.OlderPath(root); err != nil {
		return false, err
	}
	h, err := fileid.Open(context.Background(), fileid.Self, p, fileid.Options{})
	if err != nil {
		return false, err
	}
	defer h.Close()
	r, err := fileid.Open(context.Background(), fileid.Self, root, fileid.Options{})
	if err != nil {
		return false, err
	}
	defer r.Close()
	relation, err := h.Relate(r)
	return relation.Kind != fileid.RelationOutside && err == nil, err
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
