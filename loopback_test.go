//go:build windows || linux

package identity

import (
	"bufio"
	"errors"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"
)

func listenLoopback(t *testing.T) net.Listener {
	t.Helper()
	l, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	return l
}

func sameExecutable(t *testing.T, got string) bool {
	t.Helper()
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	a, errA := filepath.EvalSymlinks(self)
	b, errB := filepath.EvalSymlinks(got)
	if errA != nil || errB != nil {
		return strings.EqualFold(filepath.Clean(self), filepath.Clean(got))
	}
	return strings.EqualFold(a, b)
}

// An honest peer in this process is bound to this process, at the rung the
// ceiling advertises, and stays bound across rechecks.
func TestBindLoopbackNamesTheConnectingProcess(t *testing.T) {
	l := listenLoopback(t)
	client, err := net.Dial("tcp4", l.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	conn, err := l.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	b, err := BindLoopback(conn, &Options{ConnectedAt: time.Now(), SkipCodeSignature: true})
	if err != nil {
		t.Fatalf("BindLoopback: %v", err)
	}
	defer b.Close()
	for i := 0; i < 3; i++ {
		p, err := b.Peer()
		if err != nil {
			t.Fatalf("an honest peer was refused on check %d: %v", i, err)
		}
		process, _ := p.Process.Get()
		path, _ := p.Path.Get()
		if process.PID != os.Getpid() || !sameExecutable(t, path) {
			t.Fatalf("bound pid %d path %q; this process is pid %d", process.PID, path, os.Getpid())
		}
		if p.Transport != TransportLoopback {
			t.Fatalf("transport %q", p.Transport)
		}
	}
	best := LoopbackCeiling().Best
	if err := b.Check(Need{User: best.User, Process: best.Process, Path: best.Path}); err != nil {
		t.Fatalf("an honest peer failed the ceiling this platform advertises: %v", err)
	}
	t.Logf("rung %s", b.Captured().Rung())
}

// A connection that is not TCP names no loopback peer.
func TestBindLoopbackRefusesAnUnsupportedConnection(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	if _, err := BindLoopback(a, nil); !errors.Is(err, ErrUnsupportedConn) {
		t.Fatalf("a pipe connection: %v", err)
	}
}

// The handle-passing attack: a program connects, the binding names it, and it
// passes the connected socket to another process and exits. The connection is
// still established, and the binding refuses instead of answering for the
// process now holding the socket.
func TestBindLoopbackRefusesAPassedSocket(t *testing.T) {
	l := listenLoopback(t)
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	passer := exec.Command(exe)
	passer.Env = append(os.Environ(), loopbackPassEnv+"="+l.Addr().String())
	passer.Stderr = os.Stderr
	stdin, err := passer.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	stdout, err := passer.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := passer.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { passer.Process.Kill(); passer.Wait() })
	lines := bufio.NewReader(stdout)
	conn, err := l.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	at := time.Now()
	b, err := BindLoopback(conn, &Options{ConnectedAt: at, SkipCodeSignature: true})
	if err != nil {
		t.Fatalf("BindLoopback before the pass: %v", err)
	}
	defer b.Close()
	bound, _ := b.Captured().Process.Get()
	if line, _ := lines.ReadString('\n'); strings.TrimSpace(line) != "pid "+strconv.Itoa(passer.Process.Pid) || bound.PID != passer.Process.Pid {
		t.Fatalf("bound pid %d; the passer reported %q and is pid %d", bound.PID, line, passer.Process.Pid)
	}
	if _, err := b.Peer(); err != nil {
		t.Fatalf("the passer was refused before passing: %v", err)
	}
	if _, err := io.WriteString(stdin, "go\n"); err != nil {
		t.Fatal(err)
	}
	line, _ := lines.ReadString('\n')
	holder, err := strconv.Atoi(strings.TrimPrefix(strings.TrimSpace(line), "holder "))
	if err != nil {
		t.Fatalf("passer reported %q", line)
	}
	t.Cleanup(func() {
		if p, err := os.FindProcess(holder); err == nil {
			p.Kill()
			p.Release()
		}
	})
	if err := passer.Wait(); err != nil {
		t.Fatalf("passer: %v", err)
	}
	deadline := time.Now().Add(10 * time.Second)
	for {
		_, err := b.Peer()
		if errors.Is(err, ErrPeerMoved) {
			t.Logf("the binding refuses: %v", err)
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("the binding still answers after the socket was passed to pid %d: %v", holder, err)
		}
		time.Sleep(20 * time.Millisecond)
	}
	// A fresh binding never answers for the passer. Windows reads the creator
	// from the owner table and refuses it; Linux finds the one process that
	// holds the socket now, which is the holder, never the program that
	// connected.
	fresh, err := BindLoopback(conn, &Options{ConnectedAt: at, SkipCodeSignature: true})
	if runtime.GOOS == "windows" {
		if !errors.Is(err, ErrPeerMoved) {
			t.Fatalf("a fresh binding of the passed socket: %v", err)
		}
		t.Logf("a fresh binding refuses: %v", err)
		return
	}
	if err != nil {
		t.Fatalf("a fresh binding of the socket its holder alone holds: %v", err)
	}
	defer fresh.Close()
	if now, _ := fresh.Captured().Process.Get(); now.PID != holder {
		t.Fatalf("a fresh binding named pid %d; the socket is held by pid %d alone", now.PID, holder)
	}
	t.Logf("a fresh binding names the holder, pid %d", holder)
}
