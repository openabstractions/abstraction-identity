//go:build darwin

package identity

import (
	"errors"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
)

var errVolumeNotLocal = errors.New("its volume is not a local file system (no MNT_LOCAL)")

// volumeAnswer is the macOS answer for the volume statfs read at p: local
// when it reports MNT_LOCAL. A network volume (SMB, NFS, AFP, WebDAV) does
// not.
func volumeAnswer(_ string, st *unix.Statfs_t) error {
	if st.Flags&unix.MNT_LOCAL == 0 {
		return errVolumeNotLocal
	}
	return nil
}

// systemMountPoints lists the mount points getfsstat reports with
// MNT_NOWAIT, which returns the kernel's cached entries and asks no volume.
func systemMountPoints() ([]string, error) {
	n, err := unix.Getfsstat(nil, unix.MNT_NOWAIT)
	if err != nil {
		return nil, err
	}
	buf := make([]unix.Statfs_t, n+8)
	n, err = unix.Getfsstat(buf, unix.MNT_NOWAIT)
	if err != nil {
		return nil, err
	}
	points := make([]string, 0, n)
	for i := range buf[:n] {
		points = append(points, unix.ByteSliceToString(buf[i].Mntonname[:]))
	}
	return points, nil
}

// dataVolume is where the read-only system volume's firmlinks lead.
const dataVolume = "/System/Volumes/Data"

var (
	// firmlinksFile lists the system volume's firmlinks, one per line: the
	// path on the system volume, a tab, the path relative to dataVolume.
	firmlinksFile = "/usr/share/firmlinks"
	// rootFolder is the folder whose symbolic links are aliases.
	rootFolder = "/"
)

// systemRootAliases lists macOS's other spellings of paths below the root:
// every firmlink in firmlinksFile (/Users is /System/Volumes/Data/Users) and
// every symbolic link directly in the root folder (/home leads to
// /System/Volumes/Data/home, /var to private/var). Both live on the sealed
// system volume, which is local. The root's entries are read by name and
// type, and only the links among them are read, so no mount point below the
// root is looked up.
func systemRootAliases() ([]alias, error) {
	var aliases []alias
	data, err := os.ReadFile(firmlinksFile)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	for _, line := range strings.Split(string(data), "\n") {
		from, to, ok := strings.Cut(strings.TrimSpace(line), "\t")
		if !ok || !strings.HasPrefix(from, "/") || from == "/" || to == "" {
			continue
		}
		aliases = append(aliases, alias{from: filepath.Clean(from), to: filepath.Join(dataVolume, to)})
	}
	entries, err := os.ReadDir(rootFolder)
	if err != nil {
		return aliases, nil
	}
	for _, e := range entries {
		if e.Type()&os.ModeSymlink == 0 {
			continue
		}
		link := filepath.Join(rootFolder, e.Name())
		target, err := os.Readlink(link)
		if err != nil {
			continue
		}
		if !filepath.IsAbs(target) {
			target = filepath.Join(rootFolder, target)
		}
		if target = filepath.Clean(target); target != "/" {
			aliases = append(aliases, alias{from: filepath.Join("/", e.Name()), to: target})
		}
	}
	return aliases, nil
}
