//go:build darwin || linux

package fileid

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
)

// The POSIX walk opens each component with openat relative to the folder
// above it and O_NOFOLLOW, reads a symbolic link with readlinkat, and walks
// ".." from the folder a link led to, as the kernel does. It keeps the
// descriptor's filesystem and current kernel name under the volume deadline.
// A cached spelling selects only a probe quota bucket; it supplies no locality
// or FileID path answer. Candidate/link-target checks use that observation
// before lookup, and every opened descriptor is checked in its own right.

const maxLinkHops = 40

// betweenStatAndOpen, when set, runs between the walk's stat of a component
// and its open; tests replace the name there.
var betweenStatAndOpen func(here string)

type walkState struct {
	ctx   context.Context
	opt   Options
	base  string   // the display spelling of dirs[0]
	dirs  []int    // the folder stack, the walk's start first
	names []string // the names of dirs[1:]
	hops  int
	last  string // the spelling of the file walk returned
}

func (w *walkState) top() int { return w.dirs[len(w.dirs)-1] }

func (w *walkState) spelled() string {
	if len(w.names) == 0 {
		return w.base
	}
	return filepath.Join(append([]string{w.base}, w.names...)...)
}

func (w *walkState) close() {
	for _, fd := range w.dirs {
		unix.Close(fd)
	}
	w.dirs, w.names = nil, nil
}

func (w *walkState) toRoot() error {
	w.close()
	observeOpen("/")
	fd, err := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return &pathError{op: "open", path: "/", err: err}
	}
	w.dirs, w.base = []int{fd}, "/"
	return nil
}

func splitPath(p string) []string {
	return strings.FieldsFunc(p, func(r rune) bool { return r == '/' })
}

// untilDotDot is path up to its first ".." component, which the kernel walks
// from wherever the components before it led. The preliminary refusal marker
// uses only this prefix. A path starting with ".." gives ".".
func untilDotDot(path string) string {
	for i := 0; i < len(path); {
		j := strings.IndexByte(path[i:], '/')
		end := len(path)
		if j >= 0 {
			end = i + j
		}
		if path[i:end] == ".." {
			if i == 0 {
				return "."
			}
			return path[:i]
		}
		i = end + 1
	}
	return path
}

// spellingLocal preserves the inert refusal seam before lookup.
// Actual volume admission belongs to held descriptors and non-link candidates;
// querying the whole input by path would follow an unclassified link target.
func spellingLocal(path string) error {
	abs, err := filepath.Abs(untilDotDot(path))
	if err != nil {
		return &NotLocalPathError{Path: path, Reason: err.Error()}
	}
	if markedNetwork(abs) {
		return &NotLocalPathError{Path: path, Reason: "a network volume"}
	}
	return nil
}

func open(ctx context.Context, path string, opt Options) (Handle, error) {
	if _, err := withoutStream(path); err != nil {
		return Handle{}, err
	}
	if err := spellingLocal(path); err != nil {
		return Handle{}, err
	}
	abs, err := absolute(path)
	if err != nil {
		return Handle{}, err
	}
	w := &walkState{ctx: ctx, opt: opt}
	defer w.close()
	if err := w.toRoot(); err != nil {
		return Handle{}, err
	}
	fd, err := w.walk(splitPath(abs))
	if err != nil {
		return Handle{}, err
	}
	return describe(fd, w.last)
}

// walk opens names below the top of the folder stack and returns a
// descriptor of the last, which the caller owns.
func (w *walkState) walk(names []string) (int, error) {
	for {
		for len(names) > 0 && (names[0] == "" || names[0] == ".") {
			names = names[1:]
		}
		if len(names) == 0 {
			fd, err := unix.FcntlInt(uintptr(w.top()), unix.F_DUPFD_CLOEXEC, 0)
			if err != nil {
				return -1, err
			}
			w.last = w.spelled()
			return fd, nil
		}
		if err := w.ctx.Err(); err != nil {
			return -1, err
		}
		name := names[0]
		names = names[1:]
		if name == ".." {
			// A rename can change the held folder's parent. Ask the kernel
			// through that descriptor; an earlier ancestor stack is stale.
			// Beneath never reaches here: SafeName refuses parent syntax.
			current, _, err := descriptorLocal(w.top(), w.spelled())
			if err != nil {
				return -1, err
			}
			parent, err := unix.Openat(w.top(), "..", openFlags(false)|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
			if err != nil {
				return -1, &pathError{op: "parent", path: current, err: err}
			}
			observed, _, err := descriptorLocal(parent, current+"/..")
			if err != nil {
				unix.Close(parent)
				return -1, err
			}
			w.close()
			w.dirs, w.base = []int{parent}, observed
			continue
		}
		current, _, err := descriptorLocal(w.top(), w.spelled())
		if err != nil {
			return -1, err
		}
		here := filepath.Join(current, name)
		if err := spellingLocal(here); err != nil {
			return -1, err
		}
		st, err := descriptorChildStat(w.top(), name, here)
		if err != nil {
			return -1, &pathError{op: "stat", path: here, err: err}
		}
		if st.Mode&unix.S_IFMT == unix.S_IFLNK {
			observeOpen(here)
			if w.opt.Links == RefuseLinks {
				return -1, fmt.Errorf("%w: %s is a symbolic link", ErrLink, here)
			}
			target, err := readlinkat(w.top(), name)
			if err != nil {
				return -1, &pathError{op: "read the link", path: here, err: err}
			}
			if w.hops++; w.hops > maxLinkHops {
				return -1, &pathError{op: "follow", path: here, err: unix.ELOOP}
			}
			// The target replaces the physical path: absolute, or relative
			// to the link's own folder. Its part before any ".." is checked
			// here, so a refusal names the target; the walk checks each
			// folder after that as it reaches it.
			check := target
			if !strings.HasPrefix(target, "/") {
				check = current + "/" + target
			}
			// A link's target passes the stream refusal a typed path passes
			// (a macOS resource fork; nothing on Linux).
			if _, err := withoutStream(check); err != nil {
				return -1, fmt.Errorf("%s is a link: %w", here, err)
			}
			if err := spellingLocal(check); err != nil {
				return -1, err
			}
			if strings.HasPrefix(target, "/") {
				if err := w.toRoot(); err != nil {
					return -1, err
				}
			}
			names = append(splitPath(target), names...)
			continue
		}
		if err := localPath(here); err != nil {
			return -1, err
		}
		observeOpen(here)
		last := len(names) == 0
		if betweenStatAndOpen != nil {
			betweenStatAndOpen(here)
		}
		fd, err := unix.Openat(w.top(), name, openFlags(last && w.opt.Read)|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		if err != nil {
			if err == unix.ELOOP {
				return -1, fmt.Errorf("%w: %s became a symbolic link while it was opened", ErrLink, here)
			}
			return -1, &pathError{op: "open", path: here, err: err}
		}
		// O_PATH with O_NOFOLLOW opens a symbolic link itself where O_RDONLY
		// fails with ELOOP: a name replaced by a link after the stat above
		// is the same race.
		var opened unix.Stat_t
		if err := unix.Fstat(fd, &opened); err != nil {
			unix.Close(fd)
			return -1, &pathError{op: "stat", path: here, err: err}
		}
		if opened.Mode&unix.S_IFMT == unix.S_IFLNK {
			unix.Close(fd)
			return -1, fmt.Errorf("%w: %s became a symbolic link while it was opened", ErrLink, here)
		}
		if last {
			w.last = here
			return fd, nil
		}
		w.dirs = append(w.dirs, fd)
		w.names = append(w.names, name)
	}
}

func readlinkat(dir int, name string) (string, error) {
	for size := 256; ; size *= 2 {
		buf := make([]byte, size)
		n, err := unix.Readlinkat(dir, name, buf)
		if err != nil {
			return "", err
		}
		if n < size {
			return string(buf[:n]), nil
		}
	}
}

// describe reads the FileID and kernel name of fd. name is only a display
// hint for failures/quota selection; the returned path is descriptor-derived.
func describe(fd int, name string) (Handle, error) {
	fail := func(err error) (Handle, error) {
		unix.Close(fd)
		return Handle{}, err
	}
	if name == "" {
		name = "/"
	}
	observed, volume, err := descriptorLocal(fd, name)
	if err != nil {
		return fail(err)
	}
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return fail(&pathError{op: "stat", path: observed, err: err})
	}
	id := FileID{
		key:        deviceInodeKey(uint64(st.Dev), uint64(st.Ino)),
		path:       observed,
		durability: durabilityOf(&volume),
		links:      int(st.Nlink),
		dir:        st.Mode&unix.S_IFMT == unix.S_IFDIR,
	}
	return Handle{f: os.NewFile(uintptr(fd), observed), id: id}, nil
}

func fdOf(h Handle) int { return int(h.f.Fd()) }

func beneath(start Handle, names []string, opt Options) (Handle, error) {
	fd, err := unix.FcntlInt(start.File().Fd(), unix.F_DUPFD_CLOEXEC, 0)
	if err != nil {
		return Handle{}, err
	}
	w := &walkState{ctx: context.Background(), opt: opt, dirs: []int{fd}, base: start.id.path}
	defer w.close()
	out, err := w.walk(names)
	if err != nil {
		return Handle{}, err
	}
	return describe(out, w.last)
}

func createExclusive(dir Handle, name string) (Handle, error) {
	current, _, err := descriptorLocal(fdOf(dir), dir.id.path)
	if err != nil {
		return Handle{}, err
	}
	here := filepath.Join(current, name)
	observeOpen(here)
	fd, err := unix.Openat(fdOf(dir), name, unix.O_RDWR|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0o600)
	if err != nil {
		return Handle{}, &pathError{op: "create", path: here, err: err}
	}
	return describe(fd, here)
}

// leafName reads nothing on POSIX: the name is the name, and a folder
// compares names by their bytes. A case-insensitive APFS volume is the
// pending-name step's (PT-5c, M4).
func leafName(folder Handle, name string) (string, bool, error) {
	return name, true, nil
}

// openByID cannot find a moved file without CAP_DAC_READ_SEARCH
// (open_by_handle_at), so a moved file reads gone.
func openByID(context.Context, StoredFileID) (FileID, bool) { return FileID{}, false }
