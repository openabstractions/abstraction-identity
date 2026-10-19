package profile

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

func probeView() (View, error) {
	root := os.Getenv("LOCALAPPDATA")
	if root == "" {
		return View{}, errors.New("bootstrap: profile view: LOCALAPPDATA is not set")
	}
	return probeProfile(root, func(path string) error {
		f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
		if err != nil {
			return err
		}
		return f.Close()
	})
}

// probeProfile creates one uniquely named empty file directly in root, which is
// %LOCALAPPDATA% and always exists, so no folder is created in a package's copy.
// A virtualized create lands in Packages\<family>\LocalCache\Local, where the
// probe then finds it. Both copies are removed.
func probeProfile(root string, create func(string) error) (View, error) {
	nonce := make([]byte, 8)
	if _, err := rand.Read(nonce); err != nil {
		return View{}, fmt.Errorf("bootstrap: profile view: %w", err)
	}
	name := fmt.Sprintf(".oa-profile-%d-%s", os.Getpid(), hex.EncodeToString(nonce))
	probe := filepath.Join(root, name)
	pattern := filepath.Join(root, "Packages", "*", "LocalCache", "Local", name)
	// Deferred as one unconditional cleanup, before checking create's error:
	// a create that fails after already creating the file (for example
	// OpenFile succeeding and Close failing) still leaves a probe file, in
	// root or in a package's redirected copy, and every exit below - the
	// create error, a Glob error, the ambiguous->1 copy case, or a normal
	// return - must remove whatever got created, not just the fully
	// successful path. Removing a file that was never created, or an empty
	// Glob match, is a harmless no-op.
	defer func() {
		//unchecked: see comment above — removing a file that was never created is a harmless no-op
		os.Remove(probe)
		if copies, err := filepath.Glob(pattern); err == nil {
			for _, c := range copies {
				//unchecked: see comment above — removing a file that was never created is a harmless no-op
				os.Remove(c)
			}
		}
	}()
	if err := create(probe); err != nil {
		return View{}, fmt.Errorf("bootstrap: profile view: %w", err)
	}
	copies, err := filepath.Glob(pattern)
	if err != nil {
		return View{}, fmt.Errorf("bootstrap: profile view: %w", err)
	}
	switch len(copies) {
	case 0:
		return View{}, nil
	case 1:
		family := filepath.Base(filepath.Dir(filepath.Dir(filepath.Dir(copies[0]))))
		return View{Virtualized: true, Family: family}, nil
	default:
		return View{}, fmt.Errorf("bootstrap: profile view: the probe appears in %d package copies: %s", len(copies), strings.Join(copies, ", "))
	}
}
