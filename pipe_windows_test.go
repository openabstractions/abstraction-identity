//go:build windows

package identity

// A real named pipe, built out of the Win32 calls a service would use, so the
// tests exercise the same handle a service would hand to OfHandle. There is no
// pipe library in the dependency list on purpose: this package's whole subject
// is the handle, and a test that borrowed someone else's wrapper would be
// testing the wrapper's handle, not the one under discussion.

import (
	"fmt"
	"os"
	"os/exec"
	"testing"
	"time"

	"golang.org/x/sys/windows"
)

// clientEnv, when set, turns this test binary into the client half. See
// TestMain.
const clientEnv = "IDENTITY_TEST_PIPE_CLIENT"

func pipeName(t *testing.T) string {
	t.Helper()
	return fmt.Sprintf(`\\.\pipe\abstraction-identity-test-%d-%s`, os.Getpid(), t.Name())
}

// listen creates one pipe instance and returns the server handle. Remote
// clients are rejected at the kernel, which is what a service should do and
// what makes the ErrRemotePeer path unreachable here.
func listen(t *testing.T, name string) windows.Handle {
	t.Helper()
	n, err := windows.UTF16PtrFromString(name)
	if err != nil {
		t.Fatal(err)
	}
	h, err := windows.CreateNamedPipe(n,
		windows.PIPE_ACCESS_DUPLEX,
		windows.PIPE_TYPE_BYTE|windows.PIPE_READMODE_BYTE|windows.PIPE_WAIT|windows.PIPE_REJECT_REMOTE_CLIENTS,
		1, 4096, 4096, 0, nil)
	if err != nil {
		t.Fatalf("CreateNamedPipe(%s): %v", name, err)
	}
	t.Cleanup(func() { windows.CloseHandle(h) })
	return h
}

// dial opens the client end from this same process.
func dial(t *testing.T, name string) windows.Handle {
	t.Helper()
	h, err := openClient(name)
	if err != nil {
		t.Fatalf("CreateFile(%s): %v", name, err)
	}
	t.Cleanup(func() { windows.CloseHandle(h) })
	return h
}

func openClient(name string) (windows.Handle, error) {
	n, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return 0, err
	}
	return windows.CreateFile(n, windows.GENERIC_READ|windows.GENERIC_WRITE,
		0, nil, windows.OPEN_EXISTING, 0, 0)
}

// accept blocks until a client is connected and returns the instant it was,
// which is the value Options.ConnectedAt exists for.
func accept(t *testing.T, server windows.Handle) time.Time {
	t.Helper()
	type result struct {
		at  time.Time
		err error
	}
	ch := make(chan result, 1)
	go func() {
		err := windows.ConnectNamedPipe(server, nil)
		ch <- result{time.Now(), err}
	}()
	select {
	case r := <-ch:
		// ERROR_PIPE_CONNECTED means the client won the race to open the
		// pipe before ConnectNamedPipe was called. It is a success.
		if r.err != nil && r.err != windows.ERROR_PIPE_CONNECTED {
			t.Fatalf("ConnectNamedPipe: %v", r.err)
		}
		return r.at
	case <-time.After(20 * time.Second):
		t.Fatal("no client connected within 20s")
		return time.Time{}
	}
}

func readFrom(t *testing.T, h windows.Handle) []byte {
	t.Helper()
	buf := make([]byte, 512)
	var n uint32
	if err := windows.ReadFile(h, buf, &n, nil); err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	return buf[:n]
}

// startChildClient runs this test binary again, in client mode, so the peer is
// a genuinely different process with its own pid - which is the only way to
// tell a correct answer from one that happens to describe the test itself.
func startChildClient(t *testing.T, name, payload string) *exec.Cmd {
	t.Helper()
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(exe)
	cmd.Env = append(os.Environ(), clientEnv+"="+name, clientEnv+"_PAYLOAD="+payload)
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cmd.Wait() })
	return cmd
}

// TestMain turns this binary into the pipe client when the environment says
// so, and otherwise runs the tests.
func TestMain(m *testing.M) {
	if name := os.Getenv(clientEnv); name != "" {
		os.Exit(runChildClient(name, os.Getenv(clientEnv+"_PAYLOAD")))
	}
	os.Exit(m.Run())
}

func runChildClient(name, payload string) int {
	deadline := time.Now().Add(15 * time.Second)
	var h windows.Handle
	var err error
	for {
		h, err = openClient(name)
		if err == nil {
			break
		}
		if time.Now().After(deadline) {
			fmt.Fprintf(os.Stderr, "child: could not open %s: %v\n", name, err)
			return 1
		}
		time.Sleep(5 * time.Millisecond)
	}
	defer windows.CloseHandle(h)

	var n uint32
	if err := windows.WriteFile(h, []byte(payload), &n, nil); err != nil {
		fmt.Fprintf(os.Stderr, "child: write: %v\n", err)
		return 1
	}
	if victim := os.Getenv(driftEnv); victim != "" {
		if err := driftToSignedProgram(h, victim); err != nil {
			fmt.Fprintf(os.Stderr, "child: drift: %v\n", err)
		}
	}
	// Stay alive long enough for the server to resolve the identity while
	// the process still exists. A peer that exits first is a real case, and
	// it has its own test.
	time.Sleep(3 * time.Second)
	return 0
}
