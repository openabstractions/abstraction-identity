package listen

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	identity "github.com/openabstractions/abstraction-identity"
	"io"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

func currentServerExpectation(t *testing.T) ServerExpectation {
	t.Helper()
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	principal := identity.User{Kind: "posix", UID: os.Getuid()}
	if runtime.GOOS == "windows" {
		u, err := user.Current()
		if err != nil {
			t.Fatal(err)
		}
		principal = identity.User{Kind: "windows", SID: u.Uid}
	}
	return ServerExpectation{Principal: principal, Program: exe}
}

func TestServerExpectationBeforePayload(t *testing.T) {
	for _, mode := range []string{"correct", "wrong-program", "wrong-principal", "wrong-instance", "unverified"} {
		t.Run(mode, func(t *testing.T) {
			endpoint := framedEndpoint(t)
			listener, err := Listen(endpoint)
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			received := make(chan int, 1)
			go func() {
				conn, err := listener.Accept()
				if err != nil {
					received <- 0
					return
				}
				defer conn.Close()
				counter := &serverByteCounter{Reader: conn}
				b, err := readFrame(counter, 1024)
				if err != nil {
					received <- counter.n
					return
				}
				received <- counter.n
				_ = writeFrame(conn, b, 1024)
				var end [1]byte
				conn.Read(end[:])
			}()
			expectation := currentServerExpectation(t)
			switch mode {
			case "wrong-program":
				expectation.Program = filepath.Join(filepath.Dir(expectation.Program), "other-server")
			case "wrong-principal":
				if runtime.GOOS == "windows" {
					expectation.Principal.SID = "S-1-5-18"
				} else {
					expectation.Principal.UID++
				}
			case "wrong-instance":
				expectation.Process = &identity.Process{PID: os.Getpid(), StartTime: time.Unix(1, 0)}
			}
			client := FrameClient{Endpoint: endpoint, Server: &expectation, Timeout: time.Second}
			if mode == "unverified" {
				client.Server = nil
			}
			reply, err := client.ExchangeFrame([]byte("private application payload"))
			if mode == "correct" || mode == "unverified" {
				if runtime.GOOS != "windows" && runtime.GOOS != "linux" && mode == "correct" {
					if !errors.Is(err, ErrServerUntrusted) || !errors.Is(err, identity.ErrNoBinding) {
						t.Fatalf("unsupported proof: %v", err)
					}
				} else if err != nil || !bytes.Equal(reply, []byte("private application payload")) {
					t.Fatalf("reply %q: %v", reply, err)
				}
			} else if !errors.Is(err, ErrServerUntrusted) {
				t.Fatalf("want trust refusal: %v", err)
			}
			select {
			case got := <-received:
				if err != nil && got != 0 {
					t.Fatalf("refused server received %d bytes", got)
				}
			case <-time.After(2 * time.Second):
				t.Fatal("server not released")
			}
		})
	}
}

func TestServerExpectationCancellationAndInvalidInput(t *testing.T) {
	e := currentServerExpectation(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	c := FrameClient{Endpoint: framedEndpoint(t), Server: &e}
	if err := c.WriteFrameContext(ctx, nil); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	e.Program = "relative"
	if err := c.WriteFrame(nil); !errors.Is(err, ErrServerUntrusted) {
		t.Fatal(err)
	}
}

func TestServerExpectationDeadlineDuringResponse(t *testing.T) {
	if runtime.GOOS != "windows" && runtime.GOOS != "linux" {
		t.Skip("server program proof unavailable")
	}
	endpoint := framedEndpoint(t)
	l, err := Listen(endpoint)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	done := make(chan struct{})
	go func() {
		defer close(done)
		c, err := l.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		_, _ = io.Copy(io.Discard, c)
	}()
	e := currentServerExpectation(t)
	client := FrameClient{Endpoint: endpoint, Server: &e, Timeout: 50 * time.Millisecond}
	if _, err := client.ExchangeFrame(nil); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal(err)
	}
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("cancellation retained connection")
	}
}

type serverByteCounter struct {
	io.Reader
	n int
}

func (c *serverByteCounter) Read(b []byte) (int, error) {
	n, err := c.Reader.Read(b)
	c.n += n
	return n, err
}

func TestServerChildHelper(t *testing.T) {
	endpoint := os.Getenv("OA_SERVER_TRUST_HELPER")
	if endpoint == "" {
		return
	}
	l, err := Listen(endpoint)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	os.Stdout.WriteString("READY\n")
	c, err := l.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	counter := &serverByteCounter{Reader: c}
	b, err := readFrame(counter, 1024)
	if err != nil {
		if counter.n != 0 {
			t.Fatalf("refused child received %d bytes", counter.n)
		}
		return
	}
	if err := writeFrame(c, b, 1024); err != nil {
		t.Fatal(err)
	}
	var end [1]byte
	c.Read(end[:])
}

func TestServerChildInstanceAndRetainedProof(t *testing.T) {
	if runtime.GOOS != "windows" && runtime.GOOS != "linux" {
		t.Skip("server program proof unavailable")
	}
	for _, wrong := range []bool{false, true} {
		endpoint := framedEndpoint(t)
		exe, err := os.Executable()
		if err != nil {
			t.Fatal(err)
		}
		childCtx, childCancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer childCancel()
		cmd := exec.CommandContext(childCtx, exe, "-test.run=^TestServerChildHelper$")
		cmd.Env = append(os.Environ(), "OA_SERVER_TRUST_HELPER="+endpoint)
		pipe, err := cmd.StdoutPipe()
		if err != nil {
			t.Fatal(err)
		}
		cmd.Stderr = os.Stderr
		// The server is legitimately created after this earlier operation budget.
		earlier := time.Now()
		if err := cmd.Start(); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			if cmd.Process != nil {
				cmd.Process.Kill()
			}
		})
		scanner := bufio.NewScanner(pipe)
		if !scanner.Scan() || scanner.Text() != "READY" {
			t.Fatal("child not ready")
		}
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		e := currentServerExpectation(t)
		if wrong {
			e.Program = filepath.Join(filepath.Dir(exe), "untrusted-server")
		}
		client := FrameClient{Endpoint: endpoint, Server: &e}
		conn, close, err := client.connect(ctx)
		if wrong {
			if !errors.Is(err, ErrServerUntrusted) {
				t.Fatalf("child program mismatch: %v", err)
			}
		} else {
			if err != nil {
				t.Fatal(err)
			}
			guarded := conn.(*serverConn)
			p, err := guarded.binding.Peer()
			if err != nil {
				t.Fatal(err)
			}
			process, _ := p.Process.Get()
			if process.PID != cmd.Process.Pid {
				t.Fatalf("server PID %d", process.PID)
			}
			if runtime.GOOS == "windows" && process.StartTime.Before(earlier) {
				t.Fatal("fixture child predates operation")
			}
			// A changed retained expectation must be checked before the next write.
			guarded.expectation.Program = filepath.Join(filepath.Dir(exe), "changed-selection")
			if n, err := conn.Write([]byte("secret")); n != 0 || !errors.Is(err, ErrServerUntrusted) {
				t.Fatalf("recheck %d %v", n, err)
			}
			binding := guarded.binding
			if alive, err := binding.Alive(); err != nil || !alive {
				t.Fatalf("retained process unavailable: %v %v", alive, err)
			}
			close()
			close()
			if _, err := binding.Alive(); err == nil {
				t.Fatal("closed binding retained a usable process handle")
			}
		}
		cancel()
		if err := cmd.Wait(); err != nil {
			t.Fatal(err)
		}
	}
}
