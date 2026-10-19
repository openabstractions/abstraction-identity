//go:build linux

package identity

import (
	"bufio"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"testing"
	"time"
)

// Two separately dialed connections to one real child listener must carry
// the same process generation. Provider clients compare this exact timestamp
// before sending HTTP bytes.
func TestBindLoopbackServerKeepsChildGenerationAcrossDials(t *testing.T) {
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	child := exec.Command(exe)
	child.Env = append(os.Environ(), loopbackServerEnv+"=1")
	child.Stderr = os.Stderr
	stdout, err := child.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := child.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = child.Process.Kill(); _ = child.Wait() })
	lines := bufio.NewReader(stdout)
	line, err := lines.ReadString('\n')
	if err != nil {
		t.Fatal(err)
	}
	var pid int
	var address string
	if _, err := fmt.Sscanf(line, "server %d %s", &pid, &address); err != nil {
		t.Fatalf("child announcement %q: %v", line, err)
	}
	bind := func() Process {
		conn, err := net.Dial("tcp4", address)
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		waitLoopbackAccepted(t, lines, conn)
		b, err := BindLoopbackServer(conn, &Options{ConnectedAt: time.Now(), SkipCodeSignature: true})
		if err != nil {
			t.Fatal(err)
		}
		defer b.Close()
		peer, err := b.Peer()
		if err != nil {
			t.Fatal(err)
		}
		process, proof := peer.Process.Get()
		if proof < ProofBound || process.PID != pid || process.PID == os.Getpid() || process.StartTime.IsZero() {
			t.Fatalf("bound %+v at proof %v; want child pid %d", process, proof, pid)
		}
		return process
	}
	first := bind()
	time.Sleep(25 * time.Millisecond)
	second := bind()
	if !first.StartTime.Equal(second.StartTime) {
		t.Fatalf("same listener pid %d has unstable generation: %s then %s", pid, first.StartTime.Format(time.RFC3339Nano), second.StartTime.Format(time.RFC3339Nano))
	}
}

// A connected socket queued before Accept has no child descriptor holder.
// Refusal is required until the fixture acknowledges owning that descriptor.
func TestBindLoopbackServerRefusesUntilChildAccepts(t *testing.T) {
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	child := exec.Command(exe)
	child.Env = append(os.Environ(), loopbackServerEnv+"=gated")
	child.Stderr = os.Stderr
	gate, err := child.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	defer gate.Close()
	stdout, err := child.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := child.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = child.Process.Kill(); _ = child.Wait() })
	lines := bufio.NewReader(stdout)
	line, err := lines.ReadString('\n')
	if err != nil {
		t.Fatal(err)
	}
	var pid int
	var address string
	if _, err := fmt.Sscanf(line, "server %d %s", &pid, &address); err != nil {
		t.Fatal(err)
	}
	conn, err := net.Dial("tcp4", address)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	local, _ := loopbackAddr(conn.LocalAddr())
	remote, _ := loopbackAddr(conn.RemoteAddr())
	before, found, err := socketRow(remote, local)
	t.Logf("before Accept: established=%v inode=%d uid=%d found=%v err=%v", before.established, before.inode, before.uid, found, err)
	if binding, err := BindLoopbackServer(conn, &Options{ConnectedAt: time.Now(), SkipCodeSignature: true}); !errors.Is(err, ErrPeerPending) || !errors.Is(err, ErrPeerGone) {
		if binding != nil {
			binding.Close()
		}
		t.Fatalf("before child Accept: %v, want ErrPeerPending and ErrPeerGone", err)
	}
	if _, err := fmt.Fprintln(gate, "accept"); err != nil {
		t.Fatal(err)
	}
	waitLoopbackAccepted(t, lines, conn)
	after, found, err := socketRow(remote, local)
	t.Logf("after Accept: established=%v inode=%d uid=%d found=%v err=%v", after.established, after.inode, after.uid, found, err)
	binding, err := BindLoopbackServer(conn, &Options{ConnectedAt: time.Now(), SkipCodeSignature: true})
	if err != nil {
		t.Fatal(err)
	}
	defer binding.Close()
	peer, err := binding.Peer()
	if err != nil {
		t.Fatal(err)
	}
	if process, proof := peer.Process.Get(); proof < ProofBound || process.PID != pid {
		t.Fatalf("after child Accept: %+v at %v, want child pid %d", process, proof, pid)
	}
}
