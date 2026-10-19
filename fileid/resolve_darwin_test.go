package fileid

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A resource fork is a data stream of its own under the file's FileID, so a
// path through "..namedfork" is refused before anything is opened (ID-F4).
func TestAResourceForkIsRefusedBeforeAnyOpen(t *testing.T) {
	f := writeFile(t, filepath.Join(t.TempDir(), "file.txt"), "visible")
	opened := 0
	stop, ok := ObserveOpens(func(string) { opened++ })
	if !ok {
		t.Fatal("another observer is set")
	}
	defer stop()
	for _, p := range []string{f + "/..namedfork/rsrc", f + "/..namedfork/data"} {
		if _, err := Resolve(bg, Self, p, Options{Read: true}); !errors.Is(err, ErrUnsafeName) {
			t.Errorf("Resolve %s: %v, want ErrUnsafeName", p, err)
		}
	}
	if opened != 0 {
		t.Errorf("%d opens happened for a resource fork", opened)
	}
}

// A symbolic link whose target runs through "..namedfork" is refused before
// the fork is opened: a link's target passes the refusal a typed path passes.
func TestAResourceForkThroughALinkIsRefusedBeforeAnyOpen(t *testing.T) {
	dir := t.TempDir()
	f := writeFile(t, filepath.Join(dir, "file.txt"), "visible")
	links := map[string]string{"absolute": f + "/..namedfork/rsrc", "relative": "file.txt/..namedfork/rsrc"}
	for name, target := range links {
		if err := os.Symlink(target, filepath.Join(dir, name)); err != nil {
			t.Fatal(err)
		}
	}
	var opened []string
	stop, ok := ObserveOpens(func(p string) { opened = append(opened, p) })
	if !ok {
		t.Fatal("another observer is set")
	}
	defer stop()
	for name := range links {
		if _, err := Resolve(bg, Self, filepath.Join(dir, name), Options{Read: true}); !errors.Is(err, ErrUnsafeName) {
			t.Errorf("Resolve through the %s link: %v, want ErrUnsafeName", name, err)
		}
	}
	for _, p := range opened {
		if strings.Contains(p, "..namedfork") {
			t.Errorf("the walk opened %s", p)
		}
	}
}
