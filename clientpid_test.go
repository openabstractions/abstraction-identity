package identity

import (
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// ID-L8: no language client exposes a peer's process id or identity from its
// standard library's peer-credential helper. Rust's UCred.pid reads
// LOCAL_PEERPID on macOS, a pid any process can recycle; a client that wants
// a peer's identity asks the Go receiver. The C++ server guard's own pinned
// check of the server it dials (cpp/src/server_guard.h) is internal and
// exposes nothing.
func TestNoLanguageClientExposesAStdlibPeerPid(t *testing.T) {
	surfaces := []string{"cpp/include", "rust/src", "rust-frame/src", "py/abstraction", "javascript"}
	peerCred := regexp.MustCompile(`(?i)peer_cred|\bUCred\b|LOCAL_PEERPID|getpeereid|SO_PEERCRED|SO_PEERPIDFD|GetNamedPipe(Client|Server)ProcessId|\bpeercred\b`)
	checked := 0
	for _, root := range surfaces {
		err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() {
				if d.Name() == "test" || d.Name() == "tests" || d.Name() == "node_modules" {
					return filepath.SkipDir
				}
				return nil
			}
			switch strings.ToLower(filepath.Ext(path)) {
			case ".rs", ".py", ".js", ".mjs", ".ts", ".h", ".hpp", ".cpp", ".c":
			default:
				return nil
			}
			src, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			checked++
			for i, line := range strings.Split(string(src), "\n") {
				if peerCred.MatchString(line) && !strings.Contains(line, "Linux requires SO_PEERPIDFD") {
					t.Errorf("%s:%d reads a peer credential in a client's public surface: %s", path, i+1, strings.TrimSpace(line))
				}
			}
			return nil
		})
		if err != nil && !os.IsNotExist(err) {
			t.Fatal(err)
		}
	}
	if checked == 0 {
		t.Fatal("no client source was read")
	}
}
