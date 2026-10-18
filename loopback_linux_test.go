//go:build linux

package identity

import (
	"bufio"
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
	line, err := bufio.NewReader(stdout).ReadString('\n')
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
