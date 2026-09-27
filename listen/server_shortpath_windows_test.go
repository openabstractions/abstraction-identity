package listen

import (
	"bufio"
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/windows"
)

// copyTestBinary copies the running test binary to dir/name, so a child
// server process can be launched from a chosen spelling of a path, and
// returns the copy's absolute path.
func copyTestBinary(t *testing.T, dir, name string) string {
	t.Helper()
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(self)
	if err != nil {
		t.Fatal(err)
	}
	dst := filepath.Join(dir, name)
	if err := os.WriteFile(dst, data, 0o755); err != nil {
		t.Fatal(err)
	}
	return dst
}

// shortAlias returns the short DOS 8.3 spelling of an existing path, and
// false when the filesystem gives it no alias distinct from path itself.
func shortAlias(t *testing.T, path string) (string, bool) {
	t.Helper()
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		t.Fatal(err)
	}
	buf := make([]uint16, windows.MAX_LONG_PATH)
	n, err := windows.GetShortPathName(p, &buf[0], uint32(len(buf)))
	if err != nil {
		t.Fatal(err)
	}
	if n == 0 || n >= uint32(len(buf)) {
		t.Fatal("short path exceeds buffer")
	}
	short := windows.UTF16ToString(buf[:n])
	if strings.EqualFold(short, path) {
		return "", false
	}
	return short, true
}

// startChildServer launches program as the TestServerChildHelper server,
// listening on endpoint, and returns once it signals READY. The child is
// killed and reaped through t.Cleanup.
func startChildServer(t *testing.T, program, endpoint string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	t.Cleanup(cancel)
	cmd := exec.CommandContext(ctx, program, "-test.run=^TestServerChildHelper$")
	cmd.Env = append(os.Environ(), "OA_SERVER_TRUST_HELPER="+endpoint)
	pipe, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if cmd.Process != nil {
			cmd.Process.Kill()
		}
		cmd.Wait()
	})
	scanner := bufio.NewScanner(pipe)
	if !scanner.Scan() || scanner.Text() != "READY" {
		t.Fatal("child not ready")
	}
}

// A named pipe server's own recorded image path is whatever spelling the
// kernel wrote down when it was created: a short DOS 8.3 alias when it was
// launched that way, unrelated to how the path is ordinarily typed or
// resolved. ServerExpectation.Program is ordinarily the long spelling.
// check() accepts a spaced long path, accepts a short alias of that same
// file, and refuses a lookalike file that shares the real file's base name.
func TestServerExpectationResolvesSpacedAndShortSpellings(t *testing.T) {
	spacedDir := filepath.Join(t.TempDir(), "server copy")
	if err := os.Mkdir(spacedDir, 0o755); err != nil {
		t.Fatal(err)
	}
	real := copyTestBinary(t, spacedDir, "server.exe")
	short, ok := shortAlias(t, real)
	if !ok {
		t.Skip("filesystem has no distinct DOS alias for this file")
	}
	principal := currentServerExpectation(t).Principal

	for _, spelling := range []struct {
		name    string
		program string
	}{
		{"spaced-long-path", real},
		{"short-8.3-alias", short},
	} {
		t.Run(spelling.name, func(t *testing.T) {
			endpoint := framedEndpoint(t)
			startChildServer(t, spelling.program, endpoint)
			e := ServerExpectation{Principal: principal, Program: real}
			client := FrameClient{Endpoint: endpoint, Server: &e, Timeout: 5 * time.Second}
			if _, err := client.ExchangeFrame([]byte("payload")); err != nil {
				t.Fatalf("server launched as %q, expectation %q: %v", spelling.program, real, err)
			}
		})
	}

	t.Run("lookalike-file", func(t *testing.T) {
		otherDir := filepath.Join(t.TempDir(), "lookalike")
		if err := os.Mkdir(otherDir, 0o755); err != nil {
			t.Fatal(err)
		}
		lookalike := copyTestBinary(t, otherDir, "server.exe")
		endpoint := framedEndpoint(t)
		startChildServer(t, lookalike, endpoint)
		e := ServerExpectation{Principal: principal, Program: real}
		client := FrameClient{Endpoint: endpoint, Server: &e, Timeout: 5 * time.Second}
		if _, err := client.ExchangeFrame([]byte("payload")); !errors.Is(err, ErrServerUntrusted) {
			t.Fatalf("server launched as lookalike %q, expectation %q: want trust refusal, got %v", lookalike, real, err)
		}
	})
}
