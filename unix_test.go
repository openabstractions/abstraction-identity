//go:build linux || darwin

package identity

// The tests both Unix platforms share, and the scaffolding under them.
//
// The peer is always a second process. A test whose peer is the test itself
// cannot tell a correct answer from one that happens to describe the caller,
// which is the failure mode this whole package exists to prevent.

import (
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

const (
	unixClientEnv  = "IDENTITY_TEST_UNIX_CLIENT"
	unixPayloadEnv = "IDENTITY_TEST_UNIX_PAYLOAD"
	unixLingerEnv  = "IDENTITY_TEST_UNIX_LINGER"
)

// TestMain turns this binary into the socket client when the environment says
// so, and otherwise runs the tests.
func TestMain(m *testing.M) {
	if ran, code := attackHelperMain(); ran {
		os.Exit(code)
	}
	if path := os.Getenv(unixClientEnv); path != "" {
		os.Exit(runChildClient(path, os.Getenv(unixPayloadEnv), os.Getenv(unixLingerEnv) != ""))
	}
	os.Exit(m.Run())
}

func runChildClient(path, payload string, linger bool) int {
	deadline := time.Now().Add(15 * time.Second)
	var c net.Conn
	var err error
	for {
		c, err = net.Dial("unix", path)
		if err == nil {
			break
		}
		if time.Now().After(deadline) {
			fmt.Fprintf(os.Stderr, "child: could not dial %s: %v\n", path, err)
			return 1
		}
		time.Sleep(5 * time.Millisecond)
	}
	if _, err := c.Write([]byte(payload)); err != nil {
		fmt.Fprintf(os.Stderr, "child: write: %v\n", err)
		return 1
	}
	if linger {
		// Stay alive while the server resolves the identity. A peer that
		// exits first is a real case and has its own test.
		time.Sleep(3 * time.Second)
	}
	c.Close()
	return 0
}

func listenUnix(t *testing.T) (*net.UnixListener, string) {
	t.Helper()
	// A short directory: sun_path is 104-108 bytes and t.TempDir() plus a
	// long test name overruns it.
	dir, err := os.MkdirTemp("", "idt")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	path := filepath.Join(dir, "s")
	l, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	return l, path
}

func startChildClient(t *testing.T, path, payload string, linger bool) *exec.Cmd {
	t.Helper()
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(exe)
	cmd.Env = append(os.Environ(), unixClientEnv+"="+path, unixPayloadEnv+"="+payload)
	if linger {
		cmd.Env = append(cmd.Env, unixLingerEnv+"=1")
	}
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cmd.Process.Kill(); cmd.Wait() })
	return cmd
}

// acceptAndRead accepts one connection in the order a service would: accept,
// note the time on the next line, read one bounded frame, and only then ask who
// is on the other end.
func acceptAndRead(t *testing.T, l *net.UnixListener) (*net.UnixConn, time.Time, string) {
	t.Helper()
	l.SetDeadline(time.Now().Add(15 * time.Second))
	c, err := l.AcceptUnix()
	if err != nil {
		t.Fatal(err)
	}
	at := time.Now()
	t.Cleanup(func() { c.Close() })

	c.SetReadDeadline(time.Now().Add(10 * time.Second))
	buf := make([]byte, 256)
	n, err := c.Read(buf)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	return c, at, string(buf[:n])
}

func identify(t *testing.T, c net.Conn, at time.Time) *Peer {
	t.Helper()
	p, err := OfConn(c, &Options{ConnectedAt: at})
	if err != nil {
		t.Fatalf("OfConn: %v", err)
	}
	t.Logf("peer: %v", p)
	for _, n := range p.Notes {
		t.Logf("  note: %s", n)
	}
	return p
}

func sameFile(a, b string) bool {
	fa, err := os.Stat(a)
	if err != nil {
		return false
	}
	fb, err := os.Stat(b)
	if err != nil {
		return false
	}
	return os.SameFile(fa, fb)
}

// TestUnixPeerIsTheKernelsAnswer is the end-to-end case: a different process
// connects, and every attribute must come back at the strength this platform
// advertises, describing the child and not the test.
func TestUnixPeerIsTheKernelsAnswer(t *testing.T) {
	l, path := listenUnix(t)
	cmd := startChildClient(t, path, "hello", true)
	c, at, frame := acceptAndRead(t, l)
	if frame != "hello" {
		t.Fatalf("frame = %q", frame)
	}
	p := identify(t, c, at)

	if p.Transport != "unix" {
		t.Errorf("transport = %q", p.Transport)
	}

	user, err := p.User.AtLeast(ProofKernel)
	if err != nil {
		t.Fatalf("user: %v", err)
	}
	if user.Kind != "posix" || user.UID != os.Getuid() {
		t.Errorf("user = %v, want uid=%d", user, os.Getuid())
	}

	proc, err := p.Process.AtLeast(Ceiling().Best.Process)
	if err != nil {
		t.Fatalf("process: the ceiling promises %s and the peer delivered less: %v", Ceiling().Best.Process, err)
	}
	if proc.PID != cmd.Process.Pid {
		t.Errorf("pid = %d, want the child's %d", proc.PID, cmd.Process.Pid)
	}
	if proc.Recycled {
		t.Error("a live child was reported as a recycled pid")
	}

	want := Ceiling().Best.Path
	got, err := p.Path.AtLeast(want)
	if err != nil {
		t.Fatalf("path: the ceiling promises %s and the peer delivered less: %v", want, err)
	}
	exe, _ := os.Executable()
	if !sameFile(got, exe) {
		t.Errorf("path = %q, want the test binary %q", got, exe)
	}
}

// TestIdentifiesBeforeAnythingIsRead is the contrast with Windows, which
// refuses to identify a pipe client until the server has completed a read. On
// both Unix platforms the credentials are on the socket at accept, so a service
// can decide before it takes a single byte from the caller.
func TestIdentifiesBeforeAnythingIsRead(t *testing.T) {
	l, path := listenUnix(t)
	startChildClient(t, path, "hello", true)

	l.SetDeadline(time.Now().Add(15 * time.Second))
	c, err := l.AcceptUnix()
	if err != nil {
		t.Fatal(err)
	}
	at := time.Now()
	defer c.Close()

	p, err := OfConn(c, &Options{ConnectedAt: at})
	if errors.Is(err, ErrMustReadFirst) {
		t.Fatal("ErrMustReadFirst is a Windows condition and must not appear on a unix socket")
	}
	if err != nil {
		t.Fatalf("OfConn before any read: %v", err)
	}
	if _, err := p.User.AtLeast(ProofKernel); err != nil {
		t.Errorf("user before any read: %v", err)
	}
}

// TestClaimedIdentityIsIgnored: two peers, two different lies in the payload,
// and the derived identity must be identical. There is no API that accepts a
// claim, and this asserts that none crept in.
func TestClaimedIdentityIsIgnored(t *testing.T) {
	l, path := listenUnix(t)

	var users []User
	var paths []string
	for _, lie := range []string{`{"owner":"root"}`, `{"owner":"LogViewer","uid":0}`} {
		startChildClient(t, path, lie, true)
		c, at, frame := acceptAndRead(t, l)
		if frame != lie {
			t.Fatalf("frame = %q, want %q", frame, lie)
		}
		p := identify(t, c, at)
		u, err := p.User.AtLeast(ProofKernel)
		if err != nil {
			t.Fatalf("user: %v", err)
		}
		users = append(users, u)
		got, _ := p.Path.Get()
		paths = append(paths, got)
	}

	if users[0] != users[1] {
		t.Errorf("two payloads produced two users: %v and %v", users[0], users[1])
	}
	if paths[0] != paths[1] {
		t.Errorf("two payloads produced two paths: %q and %q", paths[0], paths[1])
	}
}

// TestListeningSocketIsRefused: peer credentials on a listening socket describe
// this service, not a caller. Answering them as if they described a caller
// would authorise everything.
func TestListeningSocketIsRefused(t *testing.T) {
	l, _ := listenUnix(t)
	f, err := l.File()
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	if _, err := OfHandle(Handle(f.Fd()), nil); !errors.Is(err, ErrNotServerEnd) {
		t.Errorf("OfHandle(listener) = %v, want ErrNotServerEnd", err)
	}
}

// TestLoopbackTCPIsRefused: a local TCP connection carries no peer credentials
// at all, and "127.0.0.1" is not an identity.
func TestLoopbackTCPIsRefused(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	go func() {
		if c, err := net.Dial("tcp", l.Addr().String()); err == nil {
			time.Sleep(time.Second)
			c.Close()
		}
	}()
	c, err := l.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	if _, err := OfConn(c, nil); !errors.Is(err, ErrUnsupportedConn) {
		t.Errorf("OfConn(tcp) = %v, want ErrUnsupportedConn", err)
	}
}
