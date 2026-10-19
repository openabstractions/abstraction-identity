//go:build darwin && cgo

package identity

import (
	"context"
	"errors"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestStartedProcessFixture(t *testing.T) {
	role := os.Getenv("OA_STARTED_ROLE")
	if role == "" {
		return
	}
	dir := os.Getenv("OA_STARTED_DIR")
	if !filepath.IsAbs(dir) {
		t.Fatal("fixture needs an owned absolute directory")
	}
	if role == "after" {
		pinFixtureWrite(t, filepath.Join(dir, "after"), "same-image exec")
		pinFixtureWait(t, filepath.Join(dir, "finish"))
		return
	}
	if role != "child" {
		t.Fatal("unknown fixture role")
	}
	pinFixtureWrite(t, filepath.Join(dir, "ready"), strconv.Itoa(os.Getpid()))
	mode := string(pinFixtureWait(t, filepath.Join(dir, "action")))
	if mode == "exec" {
		program, err := os.Executable()
		if err != nil {
			t.Fatal(err)
		}
		err = syscall.Exec(program, []string{program, "-test.run=^TestStartedProcessFixture$", "-test.timeout=20s"}, pinFixtureEnv(map[string]string{"OA_STARTED_ROLE": "after"}))
		t.Fatalf("exec returned: %v", err)
	}
	if mode != "exit" {
		t.Fatal("unknown fixture action")
	}
}

func TestBindStartedProcessOccurrence(t *testing.T) {
	for _, mode := range []string{"exit", "exec"} {
		t.Run(mode, func(t *testing.T) {
			dir := t.TempDir()
			program, err := os.Executable()
			if err != nil {
				t.Fatal(err)
			}
			cmd := exec.Command(program, "-test.run=^TestStartedProcessFixture$", "-test.timeout=20s")
			cmd.Env = pinFixtureEnv(map[string]string{"OA_STARTED_ROLE": "child", "OA_STARTED_DIR": dir})
			if err = cmd.Start(); err != nil {
				t.Fatal(err)
			}
			defer func() { _ = cmd.Process.Kill(); _ = cmd.Wait() }()
			pin, err := BindStartedProcess(cmd.Process)
			if err != nil {
				t.Fatal(err)
			}
			defer pin.Close()
			peer, err := pin.Peer()
			if err != nil {
				t.Fatal(err)
			}
			process, proof := peer.Process.Get()
			user, _ := peer.User.Get()
			if proof != ProofBound || process.PID != cmd.Process.Pid || process.Generation == 0 || !process.StartTime.IsZero() || user.AuditSessionID == 0 || user.UID != os.Geteuid() {
				t.Fatalf("native capture: %+v %+v %v", process, user, proof)
			}
			copyPin, err := pin.Shared().RetainProcess()
			if err != nil {
				t.Fatal(err)
			}
			defer copyPin.Close()
			pin.Close()
			if alive, err := copyPin.Alive(); !alive || err != nil {
				t.Fatalf("duplicate life: %v %v", alive, err)
			}
			pinFixtureWait(t, filepath.Join(dir, "ready"))
			pinFixtureWrite(t, filepath.Join(dir, "action"), mode)
			if mode == "exec" {
				pinFixtureWait(t, filepath.Join(dir, "after"))
			}
			until := time.Now().Add(5 * time.Second)
			for {
				alive, err := copyPin.Alive()
				if err != nil {
					t.Fatal(err)
				}
				if !alive {
					break
				}
				if time.Now().After(until) {
					t.Fatal("old occurrence survived exit/exec")
				}
				time.Sleep(10 * time.Millisecond)
			}
			if historical, err := copyPin.Peer(); err != nil || historical != peer {
				t.Fatalf("historical capture: %v %v", historical, err)
			}
			if _, err = copyPin.RetainProcess(); !errors.Is(err, ErrPeerGone) {
				t.Fatalf("retaining ended occurrence: %v", err)
			}
		})
	}
	self, err := os.FindProcess(os.Getpid())
	if err != nil {
		t.Fatal(err)
	}
	if pin, err := BindStartedProcess(self); pin != nil || err == nil {
		t.Fatalf("arbitrary non-child accepted: %v %v", pin, err)
	}
}

// An untrusted private resource fixture cannot satisfy production platform
// policy. It lets these tests distinguish native occurrence rejection from the
// later trust refusal without adding a trust bypass or test hook to source.
type startedUntrustedResource struct{}

func (*startedUntrustedResource) match(*XPCRequest) (Code, Proof, error) {
	return Code{}, ProofUnmet, ErrNotProven
}
func (*startedUntrustedResource) close() {}

// The isolated native runner registers only a temporary launchd service to run
// this server. Every client is a direct owned child of that server test.
func TestStartedProcessXPCFixture(t *testing.T) {
	role := os.Getenv("OA_STARTED_XPC_ROLE")
	if role == "" {
		return
	}
	dir, service := os.Getenv("OA_STARTED_XPC_DIR"), os.Getenv("OA_STARTED_XPC_SERVICE")
	if !filepath.IsAbs(dir) || !strings.HasPrefix(service, "org.openabstractions.started1474.") {
		t.Fatal("invalid fixture namespace")
	}
	program, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	if role == "client" {
		label := os.Getenv("OA_STARTED_XPC_LABEL")
		pinFixtureWait(t, filepath.Join(dir, label+"-go"))
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		client, err := OpenXPCClient(ctx, service, program, uint32(os.Geteuid()), 1024)
		if err != nil {
			t.Fatal(err)
		}
		defer client.Close()
		if _, _, err = client.Call(ctx, []byte(label), false); err != nil {
			t.Fatal(err)
		}
		pinFixtureWait(t, filepath.Join(dir, "finish"))
		return
	}
	if role != "server" {
		t.Fatal("unknown fixture role")
	}
	listener, err := OpenXPCListener(service, 1024)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	start := func(label string) *exec.Cmd {
		cmd := exec.Command(program, "-test.run=^TestStartedProcessXPCFixture$", "-test.timeout=25s")
		cmd.Env = pinFixtureEnv(map[string]string{"OA_STARTED_XPC_ROLE": "client", "OA_STARTED_XPC_LABEL": label})
		if err := cmd.Start(); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() })
		return cmd
	}
	owned := start("owned")
	pin, err := BindStartedProcess(owned.Process)
	if err != nil {
		t.Fatal(err)
	}
	defer pin.Close()
	evidence := &SealedResourceEvidence{state: &sealedResourceState{native: &startedUntrustedResource{}}}
	defer evidence.Close()
	if _, _, err = evidence.MatchStartedProcess(pin); !errors.Is(err, ErrNotProven) {
		t.Fatalf("untrusted generation accepted: %v", err)
	}
	pinFixtureWrite(t, filepath.Join(dir, "owned-go"), "go")
	request, err := listener.Accept()
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err = evidence.MatchStartedXPCRequest(pin, request); !errors.Is(err, ErrNotProven) {
		t.Fatalf("own occurrence did not reach trust refusal: %v", err)
	}
	if err = request.Reply([]byte("ok")); err != nil {
		t.Fatal(err)
	}
	request.Close()
	if _, _, err = evidence.MatchStartedXPCRequest(pin, request); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("closed request: %v", err)
	}
	start("wrong")
	pinFixtureWrite(t, filepath.Join(dir, "wrong-go"), "go")
	request, err = listener.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer request.Close()
	if _, _, err = evidence.MatchStartedXPCRequest(pin.Shared(), request); !errors.Is(err, ErrNoBinding) {
		t.Fatalf("same-code different child not rejected at occurrence check: %v", err)
	}
	if err = request.Reply([]byte("ok")); err != nil {
		t.Fatal(err)
	}
}
