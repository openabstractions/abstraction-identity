package identity

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
)

// Python reads the pyvenv.cfg beside its program, or else the one in the
// folder above, and runs from the `home` folder it names (VISION 2026-10-07;
// research/python-identity/FINDINGS.md). A program that is the same file as a
// file in that home, such as a hard link to its python.exe or a Linux venv's
// symbolic link, is the shared interpreter under another name. A program
// that is no file of that home and sits beside its own pyvenv.cfg is an
// application's own interpreter copy.

// venvConfigLimit bounds the pyvenv.cfg read; Python's own files are a few
// hundred bytes.
const venvConfigLimit = 64 << 10

// venvState is what the pyvenv.cfg Python reads for a program says about it.
type venvState int

const (
	// venvNone: no pyvenv.cfg beside or above the program, or one that names
	// no home or a home that does not exist; the program is judged by its
	// name and image alone.
	venvNone venvState = iota
	// venvHomeFile: the program is the same file as a file in the home the
	// config names, so it is the shared interpreter.
	venvHomeFile
	// venvOwnCopy: the program has its own config whose home names another
	// folder, and it is no file of that home.
	venvOwnCopy
	// venvUnverified: a config exists but the file Python reads, its home or
	// the program cannot be verified: a config that is a link, no regular
	// file, unreadable or over 64 KiB; a home that is relative or not on a
	// local drive (LocalPath), or that cannot be listed; a program whose file
	// identity cannot be read. It reads as the shared interpreter, so every
	// caller fails closed the same way.
	venvUnverified
)

// SharedInterpreterVenv is the pyvenv.cfg rule alone (ID-I1): nil when the
// config Python reads for program proves it no shared interpreter (there is
// none, it names no home or a missing one, or program is no file of its
// home), and otherwise an error saying why: program is the same file as a
// file in that home, or the config, its home or program cannot be verified.
// ClassifyProgram reads every such program as a shared interpreter; an
// application registration refuses it. A program that is not an absolute
// path on a local drive cannot be verified.
func SharedInterpreterVenv(program string) error {
	if !filepath.IsAbs(program) {
		return fmt.Errorf("the program %s is not an absolute path", program)
	}
	if err := LocalPath(program); err != nil {
		return fmt.Errorf("the program %s is not on a local drive: %w", program, err)
	}
	_, err := readVenv(program)
	return err
}

// venvScan is one home scan: the program's state and, for venvHomeFile, the
// home file it is.
type venvScan struct {
	state  venvState
	shared string
}

// venvScans caches a home scan by its inputs: the program's file identity,
// the home folder and the home folder's modification time, which a new,
// removed or replaced entry changes. A scan answers whether a regular file
// of home has that identity.
var venvScans fileCache[venvScan]

// venvHomeScan is the one home listing readVenv makes; tests count it.
var venvHomeScan = scanVenvHome

// readVenv reports the program's venv state, with the reason for
// venvHomeFile and venvUnverified. Nothing in a home that is not an absolute
// path on a local drive is opened.
func readVenv(program string) (venvState, error) {
	home, config, err := venvHome(program)
	if err != nil {
		return venvUnverified, err
	}
	if home == "" {
		return venvNone, nil
	}
	if !filepath.IsAbs(home) {
		return venvUnverified, fmt.Errorf("%s names a home folder that is not an absolute path", config)
	}
	if err := LocalPath(home); err != nil {
		return venvUnverified, fmt.Errorf("%s names a home folder that is not on a local drive: %w", config, err)
	}
	key, err := FileKey(program)
	if err != nil {
		return venvUnverified, fmt.Errorf("the program %s could not be read: %w", program, err)
	}
	homeInfo, err := os.Stat(home)
	if errors.Is(err, fs.ErrNotExist) {
		return venvNone, nil // Python could not run from it either
	}
	if err != nil {
		return venvUnverified, fmt.Errorf("the home folder %s that %s names could not be read: %w", home, config, err)
	}
	stamp := key + "|" + home + "|" + strconv.FormatInt(homeInfo.ModTime().UnixNano(), 10)
	scan, ok := venvScans.get(stamp)
	if !ok {
		scan, err = venvHomeScan(home, key)
		if err != nil {
			return venvUnverified, fmt.Errorf("the home folder %s that %s names could not be read: %w", home, config, err)
		}
		venvScans.put(stamp, scan)
	}
	if scan.state == venvHomeFile {
		return venvHomeFile, fmt.Errorf("the program %s is the same file as the shared interpreter %s; an application's interpreter is a copy inside its own folder", program, scan.shared)
	}
	return scan.state, nil
}

// scanVenvHome reports whether the program with file identity key is a
// regular file of home, and which.
func scanVenvHome(home, key string) (venvScan, error) {
	entries, err := os.ReadDir(home)
	if errors.Is(err, fs.ErrNotExist) {
		return venvScan{state: venvNone}, nil
	}
	if err != nil {
		return venvScan{}, err
	}
	for _, entry := range entries {
		if !entry.Type().IsRegular() {
			continue
		}
		shared := filepath.Join(home, entry.Name())
		if other, err := FileKey(shared); err == nil && other == key {
			return venvScan{state: venvHomeFile, shared: shared}, nil
		}
	}
	return venvScan{state: venvOwnCopy}, nil
}

// venvHome returns the home value of the pyvenv.cfg Python reads for program
// and that file's path, or "" when there is none. A pyvenv.cfg that is a link
// or no regular file is an error: the file Python reads could differ from
// the one checked here, or name a home in another folder's venv.
func venvHome(program string) (home, config string, err error) {
	for _, folder := range []string{filepath.Dir(program), filepath.Dir(filepath.Dir(program))} {
		config = filepath.Join(folder, "pyvenv.cfg")
		info, err := os.Lstat(config)
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err != nil || !info.Mode().IsRegular() {
			return "", config, fmt.Errorf("%s is a link or not a file", config)
		}
		file, err := os.Open(config)
		if err != nil {
			return "", config, fmt.Errorf("%s could not be read: %w", config, err)
		}
		data, err := io.ReadAll(io.LimitReader(file, venvConfigLimit+1))
		file.Close()
		if err != nil || len(data) > venvConfigLimit {
			return "", config, fmt.Errorf("%s could not be read or is over 64 KiB", config)
		}
		return venvConfigHome(data), config, nil
	}
	return "", "", nil
}

// venvConfigHome is the value of the first `home = ...` line, as Python's
// getpath reads it: the key trimmed and compared without regard to ASCII
// case, the value trimmed.
func venvConfigHome(data []byte) string {
	data = bytes.TrimPrefix(data, []byte("\xef\xbb\xbf"))
	for _, line := range bytes.Split(data, []byte("\n")) {
		key, value, found := bytes.Cut(line, []byte("="))
		if found && homeKey(bytes.TrimSpace(key)) {
			return string(bytes.TrimSpace(value))
		}
	}
	return ""
}

// homeKey reports whether a pyvenv.cfg key is "home" in any ASCII case; the
// key is a configuration word, no path.
func homeKey(key []byte) bool {
	const want = "home"
	if len(key) != len(want) {
		return false
	}
	for i := range key {
		if key[i]|0x20 != want[i] {
			return false
		}
	}
	return true
}
