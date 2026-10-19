package fileid

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"path/filepath"
	"strings"
)

// StoredFileID is a FileID a store keeps: the key and the final path it was
// resolved at. Its one way back to a FileID is Revalidate. A key holds
// within one host and is never sent to another (oa-remote@1 carries none).
type StoredFileID struct {
	key  string
	path string
}

// Stored is the StoredFileID of f. A Volatile key is refused with
// ErrVolatile: its file system may give the ID to another file after a
// remount or a rename, and an authority store must not match that file.
func (f FileID) Stored() (StoredFileID, error) {
	if f.IsZero() {
		return StoredFileID{}, ErrNoFile
	}
	if f.durability != Persistent {
		return StoredFileID{}, fmt.Errorf("%w: %s", ErrVolatile, f.path)
	}
	return StoredFileID{key: f.key, path: f.path}, nil
}

// Path is the final path the key was resolved at, for display and for
// Revalidate to look at first, spelled as exactPath spells it.
func (s StoredFileID) Path() string { return exactPath(s.path) }

const storedVersion = "fileid1"

// String is the stored text form: a version, the key and the path,
// separated by '|'. ParseStoredFileID reads it back.
func (s StoredFileID) String() string {
	return storedVersion + "|" + s.key + "|" + s.path
}

// ParseStoredFileID reads the text String wrote. It checks the form only;
// Revalidate is the check against the file system.
func ParseStoredFileID(text string) (StoredFileID, error) {
	parts := strings.SplitN(text, "|", 3)
	if len(parts) != 3 || parts[0] != storedVersion {
		return StoredFileID{}, fmt.Errorf("fileid: %q is not a stored file ID", text)
	}
	key, path := parts[1], parts[2]
	if !validKey(key) || !filepath.IsAbs(path) || strings.ContainsAny(path, "\x00\r\n") {
		return StoredFileID{}, fmt.Errorf("fileid: %q is not a stored file ID", text)
	}
	return StoredFileID{key: key, path: path}, nil
}

// validKey reports whether key has the form a FileID key has: hex digits on
// both sides of one dash.
func validKey(key string) bool {
	a, b, ok := strings.Cut(key, "-")
	if !ok || a == "" || b == "" {
		return false
	}
	for _, r := range a + b {
		if !(r >= '0' && r <= '9' || r >= 'a' && r <= 'f') {
			return false
		}
	}
	return true
}

// State is what Revalidate found.
type State int

const (
	// StateSame: the stored path still names the stored file.
	StateSame State = iota
	// StateReplaced: another file now has the stored path, as after a new
	// file was renamed over it.
	StateReplaced
	// StateGone: nothing has the stored path, and the file was not found
	// elsewhere.
	StateGone
	// StateMoved: the stored file was found by its ID at another path. Only
	// Windows answers it, by opening the file by ID on its volume; on Linux
	// opening by handle needs CAP_DAC_READ_SEARCH, so a moved file reads
	// gone.
	StateMoved
)

func (s State) String() string {
	switch s {
	case StateSame:
		return "same"
	case StateReplaced:
		return "replaced"
	case StateMoved:
		return "moved"
	}
	return "gone"
}

// Revalidate checks a stored file ID against the file system, resolving its
// path in this process's view. It answers the file now at the path and
// StateSame or StateReplaced; StateMoved with the file at its new path; or a
// zero FileID and StateGone. A record never re-points silently: a caller
// decides what each state means for it. An error is a resolution the file
// system refused, never a state.
func Revalidate(ctx context.Context, s StoredFileID) (FileID, State, error) {
	if s.key == "" {
		return FileID{}, StateGone, ErrNoFile
	}
	id, err := Resolve(ctx, Self, exactPath(s.path), Options{})
	switch {
	case err == nil && id.key == s.key:
		return id, StateSame, nil
	case err == nil:
		return id, StateReplaced, nil
	case !errors.Is(err, fs.ErrNotExist):
		return FileID{}, StateGone, err
	}
	if moved, ok := openByID(ctx, s); ok && moved.key == s.key {
		return moved, StateMoved, nil
	}
	return FileID{}, StateGone, nil
}
