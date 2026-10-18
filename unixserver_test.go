//go:build windows || linux

package identity

import (
	"bufio"
	"errors"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestUnixServerHelperProcess is the child the ID-T8 tests start: it listens
// on the AF_UNIX path it is given, prints one line once it listens, and
// accepts until it is killed.
func TestUnixServerHelperProcess(t *testing.T) {
	path := os.Getenv("OA_IDENTITY_UNIX_SERVER")
	if path == "" {
		return
	}
	l, err := net.Listen("unix", path)
	if err != nil {
		os.Exit(2)
	}
	os.Stdout.WriteString("listening\n")
	for {
		c, err := l.Accept()
		if err != nil {
			os.Exit(0)
		}
		go func() { time.Sleep(10 * time.Second); c.Close() }()
	}
}

// socketPath is a socket path in a short private folder of the temporary
// directory; t.TempDir's names can pass the 108-byte AF_UNIX limit.
func socketPath(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "oa-us")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return filepath.Join(dir, "s.sock")
}

// unixServerChild starts the helper on path and returns once it listens.
func unixServerChild(t *testing.T, path string) *exec.Cmd {
	t.Helper()
	child := exec.Command(os.Args[0], "-test.run=^TestUnixServerHelperProcess$")
	child.Env = append(os.Environ(), "OA_IDENTITY_UNIX_SERVER="+path)
	stdout, err := child.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := child.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = child.Process.Kill(); _ = child.Wait() })
	line, err := bufio.NewReader(stdout).ReadString('\n')
	if err != nil || strings.TrimSpace(line) != "listening" {
		t.Fatalf("the helper did not listen on %s: %q %v", path, line, err)
	}
	return child
}

// ID-T8: a dialed AF_UNIX connection binds the process that listens at the
// far end, at bound or better, before a byte is sent.
func TestBindUnixServerNamesTheListeningProcess(t *testing.T) {
	path := socketPath(t)
	child := unixServerChild(t, path)
	conn, err := net.Dial("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	binding, err := BindUnixServer(conn, &Options{ConnectedAt: time.Now(), SkipCodeSignature: true})
	if err != nil {
		t.Fatal(err)
	}
	defer binding.Close()
	peer, err := binding.Peer()
	if err != nil {
		t.Fatal(err)
	}
	process, proof := peer.Process.Get()
	if proof < ProofBound || process.PID != child.Process.Pid || process.Recycled {
		t.Fatalf("bound %+v at %s, wanted the listening child %d at bound or better", process, proof, child.Process.Pid)
	}
	if process.PID == os.Getpid() {
		t.Fatal("the binding named the dialing process, not the listener")
	}
	if alive, err := binding.Alive(); err != nil || !alive {
		t.Fatalf("the listener reads not alive: %v %v", alive, err)
	}
	if peer.Transport != string(TransportUnix) {
		t.Fatalf("transport %q", peer.Transport)
	}
}

// ID-T8: the binding names whichever process listens on the path, so a
// second listener on the same name is told apart from the first by its
// process id.
func TestBindUnixServerTellsTwoListenersApart(t *testing.T) {
	first, second := socketPath(t), socketPath(t)
	a := unixServerChild(t, first)
	b := unixServerChild(t, second)
	for path, want := range map[string]int{first: a.Process.Pid, second: b.Process.Pid} {
		conn, err := net.Dial("unix", path)
		if err != nil {
			t.Fatal(err)
		}
		binding, err := BindUnixServer(conn, &Options{ConnectedAt: time.Now(), SkipCodeSignature: true})
		if err != nil {
			conn.Close()
			t.Fatal(err)
		}
		peer, err := binding.Peer()
		got, _ := peer.Process.Get()
		binding.Close()
		conn.Close()
		if err != nil || got.PID != want {
			t.Fatalf("%s bound pid %d (%v), wanted %d", path, got.PID, err, want)
		}
	}
}

// ID-T8 scope: a connection that is not AF_UNIX is refused.
func TestBindUnixServerRefusesOtherConnections(t *testing.T) {
	near, far := net.Pipe()
	defer near.Close()
	defer far.Close()
	if _, err := BindUnixServer(near, nil); !errors.Is(err, ErrUnsupportedConn) {
		t.Fatalf("an in-memory connection: %v, wanted ErrUnsupportedConn", err)
	}
}
