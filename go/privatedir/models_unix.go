//go:build unix

package privatedir

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

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
// entry another account owns, and a file of more than one name, whose other
// names cannot be listed here, are refused before anything changes. It then
// clears every group and other write bit through each entry's own
// descriptor (fchmod).
func protectModels(dir string, _ []string) error {
	type held struct {
		path string
		fd   int
		dir  bool
		mode uint32
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
		case st.Mode&unix.S_IFMT == unix.S_IFREG && st.Nlink > 1:
			return fmt.Errorf("%s has %d names, which cannot be listed here", p, st.Nlink)
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
		e := held{path: p, fd: fd, dir: st.Mode&unix.S_IFMT == unix.S_IFDIR, mode: uint32(st.Mode) & 0o7777}
		all = append(all, e)
		if st.Dev != before.Dev || st.Ino != before.Ino {
			return e, fmt.Errorf("%s changed while it was opened", p)
		}
		return e, judge(p, &st)
	}
	top, err := open(unix.AT_FDCWD, dir, dir)
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
		children, err := os.ReadDir(all[i].path)
		if err != nil {
			return err
		}
		for _, c := range children {
			if _, err := open(all[i].fd, filepath.Join(all[i].path, c.Name()), c.Name()); err != nil {
				return err
			}
		}
	}
	if afterScan != nil {
		afterScan()
	}
	for _, e := range all {
		if err := unix.Fchmod(e.fd, e.mode&^0o022); err != nil {
			return fmt.Errorf("%s: %w", e.path, err)
		}
	}
	return nil
}

// checkModels refuses dir unless it is a directory reached through no link,
// owned by this account, with no group or other write bit.
func checkModels(dir string) error {
	var st unix.Stat_t
	if err := unix.Lstat(dir, &st); err != nil {
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

// checkRoot refuses this account's home, a folder holding it, its usual
// document, desktop, download and application-data folders, a link at root
// or above it, and a root that does not resolve to itself.
func checkRoot(root string) error {
	home, err := os.UserHomeDir()
	if err == nil && home != "" {
		home = filepath.Clean(home)
		known := []string{home}
		for _, sub := range []string{"Documents", "Desktop", "Downloads", "Library", ".local", filepath.Join(".local", "share"), ".config"} {
			known = append(known, filepath.Join(home, sub))
		}
		for _, k := range known {
			if root == k {
				return fmt.Errorf("it is the known folder %s", k)
			}
		}
		if holds(root, []string{home}) {
			return fmt.Errorf("it holds this account's home %s", home)
		}
	}
	for p := root; ; p = filepath.Dir(p) {
		var st unix.Stat_t
		if err := unix.Lstat(p, &st); err != nil {
			return fmt.Errorf("%s: %w", p, err)
		}
		if st.Mode&unix.S_IFMT == unix.S_IFLNK {
			return fmt.Errorf("%s is a link", p)
		}
		if filepath.Dir(p) == p {
			break
		}
	}
	final, err := filepath.EvalSymlinks(root)
	if err != nil {
		return err
	}
	if final != root {
		return fmt.Errorf("it resolves to %s", final)
	}
	return nil
}
