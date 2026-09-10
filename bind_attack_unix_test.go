//go:build linux || darwin

package identity

// The scaffolding for the two impersonation attacks, which are not the same
// attack.
//
// On Linux the peer that connected is the peer for ever: SO_PEERCRED and
// SO_PEERPIDFD are derived from the connection and no later writer can displace
// them. The only way to become another program is execve, in place, keeping the
// pid. That is execDriftHelper.
//
// On macOS the peer is whoever wrote last, so the attack does not need to touch
// the connecting process at all: a second process that already existed writes
// one byte and inherits the whole answer, signature included. That is
// preForkedHelper, and it is the shape measured in probe-evidence.txt
// experiment 2.

import (
	"net"
	"os"
	"os/exec"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

const (
	execDriftEnv  = "IDENTITY_TEST_EXEC_DRIFT"
	preForkedEnv  = "IDENTITY_TEST_PRE_FORKED"
	attackGoFD    = 3
	attackReadyFD = 4
)

// attackHelperMain runs the helper half when the environment selects it. It is
// called from TestMain in unix_test.go, before the test framework starts.
func attackHelperMain() (ran bool, code int) {
	switch {
	case os.Getenv(execDriftEnv) != "":
		return true, runExecDriftHelper(os.Getenv(execDriftEnv))
	case os.Getenv(preForkedEnv) != "":
		return true, runPreForkedHelper()
	}
	return false, 0
}

// runExecDriftHelper connects as this test binary and then, on the signal,
// replaces itself with /bin/cat while holding the connection open. Its pid,
// its start time and the kernel's record of who connected are all unchanged;
// only /proc/<pid>/exe moves.
func runExecDriftHelper(path string) int {
	c, err := net.Dial("unix", path)
	if err != nil {
		return 1
	}
	f, err := c.(*net.UnixConn).File()
	if err != nil {
		return 1
	}
	// Go sets FD_CLOEXEC on everything it opens. The connection has to
	// outlive the exec or the service simply sees a hangup.
	if _, err := unix.FcntlInt(f.Fd(), unix.F_SETFD, 0); err != nil {
		return 1
	}
	c.Close()

	os.NewFile(attackReadyFD, "ready").Write([]byte{1})
	if _, err := os.NewFile(attackGoFD, "go").Read(make([]byte, 1)); err != nil {
		return 1
	}
	unix.Exec("/bin/cat", []string{"cat"}, os.Environ())
	return 1
}

// runPreForkedHelper is handed an unconnected socket on its stdout by a parent
// that has not connected it yet, so it exists, with its start time stamped,
// before the connection does. On the signal it becomes /bin/cat, and the first
// byte the parent pushes through its stdin is a write to the socket from a
// process that was never the peer.
func runPreForkedHelper() int {
	os.NewFile(attackReadyFD, "ready").Write([]byte{1})
	if _, err := os.NewFile(attackGoFD, "go").Read(make([]byte, 1)); err != nil {
		return 1
	}
	unix.Exec("/bin/cat", []string{"cat"}, os.Environ())
	return 1
}

// attacker is the test-side half: it starts a helper, and releases it into the
// exec at the moment the test chooses.
type attacker struct {
	cmd      *exec.Cmd
	goWrite  *os.File
	catStdin *os.File
}

func (a *attacker) release(t *testing.T) {
	t.Helper()
	if _, err := a.goWrite.Write([]byte{1}); err != nil {
		t.Fatalf("releasing the helper into exec: %v", err)
	}
}

// speak makes the helper, now /bin/cat, write to the socket. Only macOS cares.
func (a *attacker) speak(t *testing.T, s string) {
	t.Helper()
	if _, err := a.catStdin.Write([]byte(s)); err != nil {
		t.Fatalf("pushing bytes through cat: %v", err)
	}
}

func (a *attacker) pid() int { return a.cmd.Process.Pid }

// startAttacker starts the test binary in one of the two helper modes and
// blocks until it reports that it is in position. env selects the mode; stdout,
// when non-nil, is the file the helper inherits as fd 1.
func startAttacker(t *testing.T, env string, value string, stdout *os.File) *attacker {
	t.Helper()

	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	goRead, goWrite, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	readyRead, readyWrite, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	catRead, catWrite, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}

	cmd := exec.Command(exe)
	cmd.Env = append(os.Environ(), env+"="+value)
	cmd.Stdin = catRead
	cmd.Stdout = stdout
	cmd.Stderr = os.Stderr
	cmd.ExtraFiles = []*os.File{goRead, readyWrite}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	goRead.Close()
	readyWrite.Close()
	catRead.Close()
	t.Cleanup(func() {
		cmd.Process.Kill()
		cmd.Wait()
		goWrite.Close()
		catWrite.Close()
		readyRead.Close()
	})

	readyRead.SetReadDeadline(time.Now().Add(15 * time.Second))
	if _, err := readyRead.Read(make([]byte, 1)); err != nil {
		t.Fatalf("the helper never reported itself in position: %v", err)
	}
	return &attacker{cmd: cmd, goWrite: goWrite, catStdin: catWrite}
}

// acceptOnly accepts, and reads nothing. A service that means to bind its peer
// does exactly this: the identity is taken before the first byte, because on
// macOS the first byte is what moves the answer.
func acceptOnly(t *testing.T, l *net.UnixListener) (*net.UnixConn, time.Time) {
	t.Helper()
	l.SetDeadline(time.Now().Add(15 * time.Second))
	c, err := l.AcceptUnix()
	if err != nil {
		t.Fatal(err)
	}
	at := time.Now()
	t.Cleanup(func() { c.Close() })
	return c, at
}

func bindOrFail(t *testing.T, c net.Conn, at time.Time) *Binding {
	t.Helper()
	b, err := BindConn(c, &Options{ConnectedAt: at})
	if err != nil {
		t.Fatalf("Bind at accept: %v", err)
	}
	t.Cleanup(func() { b.Close() })
	t.Logf("bound at accept: %v", b.Captured())
	return b
}

// waitForExe blocks until pid is running want, using each platform's own way
// of asking. It is how a test confirms the attack landed before it checks
// whether the defence caught it.
func waitForExe(t *testing.T, pid int, want string) {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for {
		got, err := execPathOf(pid)
		if err == nil && got == want {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("the helper never became %s; it is %q (%v)", want, got, err)
		}
		time.Sleep(2 * time.Millisecond)
	}
}
