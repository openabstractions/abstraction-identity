//go:build unix

package privatedir

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/openabstractions/abstraction-identity/fileid"
	"golang.org/x/sys/unix"
)

// afterScan, set by tests only, runs once every entry is held and judged,
// before the first mode is written.
var afterScan func()

// protectModels opens every entry below dir as itself and holds it: each
// child is judged with fstatat from its parent's descriptor (no link
// followed) and refused unless it is a folder or a regular file, so a link,
// a device or a pipe is never opened; it is then opened with openat from
// that same descriptor and refused when it is not the entry judged. An
// entry another account owns, and a file whose names cannot all be accounted
// for beneath the held admitted roots, are refused before anything changes. It then
// clears every group and other write bit through each entry's own
// descriptor (fchmod).
func protectModelsAt(dir fileid.Handle, roots []fileid.Handle) error {
	type held struct {
		path   string
		fd     int
		dir    bool
		mode   uint32
		stat   unix.Stat_t
		parent int
		name   string
	}
	var all []held
	defer func() {
		for _, e := range all {
			//unchecked: read-only descriptors; a failed close changes nothing written
			unix.Close(e.fd)
		}
	}()
	judge := func(p string, st *unix.Stat_t) error {
		switch {
		case st.Mode&unix.S_IFMT == unix.S_IFLNK:
			return fmt.Errorf("%s is a link", p)
		case st.Mode&unix.S_IFMT != unix.S_IFDIR && st.Mode&unix.S_IFMT != unix.S_IFREG:
			return fmt.Errorf("%s is neither a folder nor a file", p)
		case int(st.Uid) != os.Getuid():
			return fmt.Errorf("%s is not owned by this account", p)
		}
		return nil
	}
	// open opens name in the folder parent holds (parent < 0: the path
	// itself) after judging it unopened.
	open := func(parent int, p, name string) (held, error) {
		var before unix.Stat_t
		if err := unix.Fstatat(parent, name, &before, unix.AT_SYMLINK_NOFOLLOW); err != nil {
			return held{}, err
		}
		if err := judge(p, &before); err != nil {
			return held{}, err
		}
		flags := unix.O_RDONLY | unix.O_NOFOLLOW | unix.O_NONBLOCK | unix.O_CLOEXEC
		if before.Mode&unix.S_IFMT == unix.S_IFDIR {
			flags |= unix.O_DIRECTORY
		}
		fd, err := unix.Openat(parent, name, flags, 0)
		if err != nil {
			if errors.Is(err, unix.ELOOP) {
				return held{}, fmt.Errorf("%s is a link", p)
			}
			return held{}, err
		}
		var st unix.Stat_t
		if err := unix.Fstat(fd, &st); err != nil {
			//unchecked: the stat failure is the error returned
			unix.Close(fd)
			return held{}, err
		}
		e := held{path: p, fd: fd, dir: st.Mode&unix.S_IFMT == unix.S_IFDIR, mode: uint32(st.Mode) & 0o7777, stat: st, parent: parent, name: name}
		all = append(all, e)
		if st.Dev != before.Dev || st.Ino != before.Ino {
			return e, fmt.Errorf("%s changed while it was opened", p)
		}
		return e, judge(p, &st)
	}
	// Reopen the admitted directory itself through its descriptor. No parent
	// path is traversed between admission, enumeration and chmod.
	top, err := open(int(dir.File().Fd()), dir.FileID().Path(), ".")
	if err != nil {
		return err
	}
	if !top.dir {
		return errors.New("it is not a directory")
	}
	for i := 0; i < len(all); i++ {
		if !all[i].dir {
			continue
		}
		fd, err := unix.Dup(all[i].fd)
		if err != nil {
			return err
		}
		listing := os.NewFile(uintptr(fd), all[i].path)
		children, err := listing.ReadDir(-1)
		closeErr := listing.Close()
		if err != nil {
			return err
		}
		if closeErr != nil {
			return closeErr
		}
		for _, c := range children {
			if _, err := open(all[i].fd, filepath.Join(all[i].path, c.Name()), c.Name()); err != nil {
				return err
			}
		}
	}
	targets := len(all)
	// Inventory each physical directory once, including overlapping roots.
	// All opens remain relative to admitted descriptors; no link is followed.
	type inode struct{ dev, ino uint64 }
	key := func(st unix.Stat_t) inode { return inode{uint64(st.Dev), uint64(st.Ino)} }
	names := make(map[inode]uint64)
	visited := make(map[inode]bool)
	var inventory func(held) error
	inventory = func(parent held) error {
		k := key(parent.stat)
		if visited[k] {
			return nil
		}
		visited[k] = true
		fd, err := unix.Openat(parent.fd, ".", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
		if err != nil {
			return err
		}
		listing := os.NewFile(uintptr(fd), parent.path)
		children, err := listing.ReadDir(-1)
		closeErr := listing.Close()
		if err != nil {
			return err
		}
		if closeErr != nil {
			return closeErr
		}
		for _, child := range children {
			e, err := open(parent.fd, filepath.Join(parent.path, child.Name()), child.Name())
			if err != nil {
				return err
			}
			if e.dir {
				if err := inventory(e); err != nil {
					return err
				}
			} else {
				names[key(e.stat)]++
			}
		}
		return nil
	}
	needsInventory := false
	for _, e := range all[:targets] {
		needsInventory = needsInventory || (!e.dir && e.stat.Nlink > 1)
	}
	if needsInventory {
		for _, root := range roots {
			e, err := open(int(root.File().Fd()), root.FileID().Path(), ".")
			if err != nil {
				return err
			}
			if err := inventory(e); err != nil {
				return err
			}
		}
	}
	if afterScan != nil {
		afterScan()
	}
	// Recheck every held observation before the first effect, including the
	// inventory. An unaccounted alias or changed count refuses the batch.
	validate := func(e held) error {
		var st unix.Stat_t
		if err := unix.Fstatat(e.parent, e.name, &st, unix.AT_SYMLINK_NOFOLLOW); err != nil {
			return err
		}
		if key(st) != key(e.stat) {
			return fmt.Errorf("%s changed at its held parent", e.path)
		}
		if err := unix.Fstat(e.fd, &st); err != nil {
			return err
		}
		if err := judge(e.path, &st); err != nil {
			return err
		}
		if st.Nlink != e.stat.Nlink {
			return fmt.Errorf("%s changed its names", e.path)
		}
		if !e.dir && needsInventory && names[key(st)] != uint64(st.Nlink) {
			return fmt.Errorf("%s has %d names; admitted roots account for %d", e.path, st.Nlink, names[key(st)])
		}
		return nil
	}
	for _, e := range all {
		if err := validate(e); err != nil {
			return err
		}
	}
	for _, e := range all[:targets] {
		if err := validate(e); err != nil {
			return err
		}
		if err := unix.Fchmod(e.fd, e.mode&^0o022); err != nil {
			return fmt.Errorf("%s: %w", e.path, err)
		}
		var st unix.Stat_t
		if err := unix.Fstat(e.fd, &st); err != nil {
			return err
		}
		if err := judge(e.path, &st); err != nil {
			return err
		}
		if st.Nlink != e.stat.Nlink {
			return fmt.Errorf("%s changed its names during protection", e.path)
		}
		if st.Mode&0o022 != 0 {
			return fmt.Errorf("%s still permits group or other writes", e.path)
		}
	}
	return nil
}

func modelKnownFolders() []string {
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return []string{""}
	}
	known := []string{home}
	for _, sub := range []string{"Documents", "Desktop", "Downloads", "Library", ".local", filepath.Join(".local", "share"), ".config"} {
		known = append(known, filepath.Join(home, sub))
	}
	return known
}

// checkModels refuses dir unless it is a directory reached through no link,
// owned by this account, with no group or other write bit.
func checkModelsAt(dir fileid.Handle) error {
	var st unix.Stat_t
	if err := unix.Fstat(int(dir.File().Fd()), &st); err != nil {
		return err
	}
	switch {
	case st.Mode&unix.S_IFMT == unix.S_IFLNK:
		return errors.New("it is a link")
	case st.Mode&unix.S_IFMT != unix.S_IFDIR:
		return errors.New("it is not a directory")
	case int(st.Uid) != os.Getuid():
		return errors.New("it is not owned by this account")
	case st.Mode&0o022 != 0:
		return fmt.Errorf("its mode %#o lets a group or others write", st.Mode&0o7777)
	}
	return nil
}
