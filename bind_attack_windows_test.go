//go:build windows

package identity

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/windows"
)

// The macOS attack, run against Windows, where it must not work.
//
// On macOS a caller connects and then hands the connected socket to a
// system-signed program; that program writes one byte and inherits the whole
// answer, code signature included. Measured, twice, on 15.7.4.
//
// The same move here is: open the pipe, then hand the client handle to
// cmd.exe - Microsoft-signed, in System32 - and let it do the writing. The
// service must still name the process that opened the pipe. Two properties
// make that true and both are asserted, so a Windows that loses either one
// fails this test rather than silently widening the hole:
//
//   - the kernel writes the client's process id onto the pipe instance when
//     the client opens it, and no later writer displaces it;
//   - a Windows process cannot replace its own image, so there is no execve
//     equivalent to reach for once the id is fixed.
func TestHandingThePipeToASignedProgramDoesNotMoveTheAnswer(t *testing.T) {
	victim := filepath.Join(os.Getenv("SystemRoot"), "System32", "cmd.exe")
	if _, err := os.Stat(victim); err != nil {
		t.Skipf("no cmd.exe to impersonate: %v", err)
	}

	name := pipeName(t)
	server := listen(t, name)
	child := startDriftingClient(t, name, victim)
	at := accept(t, server)

	if got := string(readFrom(t, server)); got != "hello" {
		t.Fatalf("read %q", got)
	}

	b, err := Bind(Handle(server), &Options{ConnectedAt: at})
	if err != nil {
		t.Fatalf("Bind: %v", err)
	}
	t.Cleanup(func() { b.Close() })
	t.Logf("bound: %v", b.Captured())

	bound, _ := b.Captured().Process.Get()
	if bound.PID != child.Process.Pid {
		t.Fatalf("the binding named pid %d; the client was pid %d", bound.PID, child.Process.Pid)
	}
	path, _ := b.Captured().Path.Get()
	if strings.EqualFold(path, victim) {
		t.Fatalf("the client was already %s; this test proves nothing", victim)
	}

	// The child has already handed its pipe handle to cmd.exe and let cmd.exe
	// write through it. Whether that write arrives is not the assertion;
	// whether it moves the service's answer is. Drain it so the read above
	// is not what a later call is answering about.
	drainFor(t, server, 2*time.Second)

	t.Run("the lookup is not moved", func(t *testing.T) {
		p, err := OfHandle(Handle(server), &Options{ConnectedAt: at})
		if err != nil {
			t.Fatalf("OfHandle: %v", err)
		}
		got, _ := p.Process.Get()
		if got.PID != child.Process.Pid {
			t.Fatalf("the pipe now names pid %d; the client was pid %d", got.PID, child.Process.Pid)
		}
		if now, _ := p.Path.Get(); strings.EqualFold(now, victim) {
			t.Fatalf("the answer drifted to %s, which is the macOS defeat reproduced on Windows", victim)
		}
	})

	t.Run("the binding still answers", func(t *testing.T) {
		p, err := b.Peer()
		if err != nil {
			t.Fatalf("the binding refused an honest peer: %v", err)
		}
		got, _ := p.Process.Get()
		if got.PID != child.Process.Pid {
			t.Fatalf("the binding drifted to pid %d", got.PID)
		}
	})
}

// TestTheBindingOutlivesThePeerItNamed is the reuse half, and the reason the
// process handle is held rather than reopened.
//
// A pid lookup after the peer exits reaches either nothing or a successor. A
// held handle keeps the process object alive, so the pid cannot be reassigned
// and the captured answer stays available and stays true.
func TestTheBindingOutlivesThePeerItNamed(t *testing.T) {
	name := pipeName(t)
	server := listen(t, name)
	child := startChildClient(t, name, "hello")
	at := accept(t, server)
	readFrom(t, server)

	b, err := Bind(Handle(server), &Options{ConnectedAt: at})
	if err != nil {
		t.Fatalf("Bind: %v", err)
	}
	t.Cleanup(func() { b.Close() })

	want, _ := b.Captured().Path.Get()
	child.Process.Wait()

	deadline := time.Now().Add(10 * time.Second)
	for {
		live, err := b.Alive()
		if err != nil {
			t.Fatalf("Alive: %v", err)
		}
		if !live {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the peer never exited")
		}
		time.Sleep(5 * time.Millisecond)
	}

	p, err := b.Peer()
	if err != nil {
		t.Fatalf("an exited peer invalidated the binding: %v", err)
	}
	got, proof := p.Path.Get()
	if got != want {
		t.Fatalf("the binding now says %q; it captured %q", got, want)
	}
	if proof < ProofBound {
		t.Fatalf("the captured path came back at %s", proof)
	}
	t.Logf("after the peer exited the binding still says path=%q at %s", got, proof)
}

func TestWindowsCeilingNamesItsBinding(t *testing.T) {
	l := Ceiling()
	if l.Transport != "npipe" {
		t.Fatalf("transport is %q", l.Transport)
	}
	if !l.Bindable {
		t.Fatalf("Windows can bind a peer; Ceiling says it cannot: %s", l.Binding)
	}
	if l.Binding == "" {
		t.Fatal("Ceiling did not say what binds a peer here")
	}
	t.Logf("%v", l)
}

// TestBindRefusesTheClientEndAndTheListener keeps Bind from inheriting a
// weakness OfHandle does not have: answering about the service itself.
func TestBindRefusesTheClientEndAndTheListener(t *testing.T) {
	name := pipeName(t)
	server := listen(t, name)
	client := dial(t, name)

	if _, err := Bind(Handle(client), &Options{}); !errors.Is(err, ErrNotServerEnd) {
		t.Fatalf("Bind on the client end returned %v; expected ErrNotServerEnd", err)
	}
	_ = server
}

// driftEnv, when set, makes the child hand its pipe handle to the named signed
// program and let that program do the writing. It is the Windows spelling of
// the macOS socket-owner drift.
const driftEnv = "IDENTITY_TEST_PIPE_DRIFT"

func startDriftingClient(t *testing.T, name, victim string) *exec.Cmd {
	t.Helper()
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(exe)
	cmd.Env = append(os.Environ(),
		clientEnv+"="+name, clientEnv+"_PAYLOAD=hello", driftEnv+"="+victim)
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cmd.Process.Kill(); cmd.Wait() })
	return cmd
}

// driftToSignedProgram runs victim with the connected pipe as its stdout, so
// the bytes on the wire come from a Microsoft-signed process that never opened
// the pipe.
func driftToSignedProgram(h windows.Handle, victim string) error {
	f := os.NewFile(uintptr(h), "pipe")
	cmd := exec.Command(victim, "/c", "echo i-am-cmd")
	cmd.Stdout = f
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return err
	}
	return nil
}

func drainFor(t *testing.T, h windows.Handle, d time.Duration) {
	t.Helper()
	ch := make(chan string, 1)
	go func() {
		buf := make([]byte, 512)
		var n uint32
		if err := windows.ReadFile(h, buf, &n, nil); err != nil {
			ch <- ""
			return
		}
		ch <- string(buf[:n])
	}()
	select {
	case s := <-ch:
		t.Logf("the signed program wrote %q through the pipe it never opened", strings.TrimSpace(s))
	case <-time.After(d):
		t.Log("the signed program's write never arrived; the answer must still not have moved")
	}
}
