//go:build darwin && cgo

package identity

import (
	"context"
	"errors"
	"fmt"
	"html"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

// The isolated Mac caller compiles one additional test binary with this value
// changed by -X. Same-image and different-image exec both keep the actual PID.
var xpcPinFixtureVariant = "one"

func pinFixtureWait(t *testing.T, path string) []byte {
	t.Helper()
	until := time.Now().Add(10 * time.Second)
	for time.Now().Before(until) {
		if b, err := os.ReadFile(path); err == nil {
			return b
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("fixture phase deadline: %s", path)
	return nil
}
func pinFixtureWrite(t *testing.T, path, value string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(value), 0600); err != nil {
		t.Fatal(err)
	}
}
func pinFixtureEnv(values map[string]string) []string {
	var env []string
	for _, line := range os.Environ() {
		key, _, _ := strings.Cut(line, "=")
		if _, replace := values[key]; !replace {
			env = append(env, line)
		}
	}
	for key, value := range values {
		env = append(env, key+"="+value)
	}
	return env
}

func TestXPCProcessPinFixture(t *testing.T) {
	role := os.Getenv("OA_IDENTITY_PIN_ROLE")
	if role == "" {
		return
	}
	dir, service, action := os.Getenv("OA_IDENTITY_PIN_DIR"), os.Getenv("OA_IDENTITY_PIN_SERVICE"), os.Getenv("OA_IDENTITY_PIN_CASE")
	if !filepath.IsAbs(dir) || !strings.HasPrefix(service, "com.openabstractions.test.macProcessPin978.") {
		t.Fatal("invalid fixture namespace")
	}
	phase := func(name string) string { return filepath.Join(dir, name) }
	if role == "after" {
		pinFixtureWrite(t, phase("after"), fmt.Sprintf("%d %s", os.Getpid(), xpcPinFixtureVariant))
		pinFixtureWait(t, phase("finish"))
		return
	}
	if role == "client" {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		program, err := os.Executable()
		if err != nil {
			t.Fatal(err)
		}
		client, err := OpenXPCClient(ctx, service, program, uint32(os.Geteuid()), 1024)
		if err != nil {
			t.Fatal(err)
		}
		_, _, err = client.Call(ctx, []byte("retain"), false)
		client.Close()
		if err != nil {
			t.Fatal(err)
		}
		pinFixtureWrite(t, phase("client-closed"), strconv.Itoa(os.Getpid()))
		pinFixtureWait(t, phase("action"))
		switch action {
		case "alive":
			pinFixtureWait(t, phase("finish"))
			return
		case "exit":
			return
		case "sameexec", "differentexec":
			if action == "differentexec" {
				program = os.Getenv("OA_IDENTITY_PIN_AFTER")
			}
			err = syscall.Exec(program, []string{program, "-test.run=^TestXPCProcessPinFixture$", "-test.timeout=20s"}, pinFixtureEnv(map[string]string{"OA_IDENTITY_PIN_ROLE": "after"}))
			t.Fatalf("exec returned: %v", err)
		default:
			t.Fatal("unknown fixture case")
		}
	}
	if role != "server" {
		t.Fatal("unknown fixture role")
	}
	listener, err := OpenXPCListener(service, 1024)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	request, err := listener.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer request.Close()
	bound, err := BindMessage(request)
	if err != nil {
		t.Fatal(err)
	}
	defer bound.Close()
	captured := bound.Captured()
	pin, err := bound.Shared().RetainProcess()
	if err != nil {
		t.Fatal(err)
	}
	defer pin.Close()
	if pin.BoundAt() != bound.BoundAt() || pin.EvidenceValidUntil() != bound.EvidenceValidUntil() {
		t.Fatal("capture deadline changed")
	}
	if err = request.Reply([]byte("ok")); err != nil {
		t.Fatal(err)
	}
	request.Close()
	bound.Close()
	listener.Close()
	pinFixtureWait(t, phase("client-closed"))
	if _, err = bound.Shared().Peer(); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("retired request binding: %v", err)
	}
	if _, err = BindMessage(request); !errors.Is(err, ErrNoBinding) {
		t.Fatalf("retained pin replaced message evidence: %v", err)
	}
	if peer, err := pin.Peer(); err != nil || peer != captured {
		t.Fatalf("retired owners peer=%v err=%v", peer, err)
	}
	if live, err := pin.Alive(); !live || err != nil {
		t.Fatalf("retired owners alive=%v err=%v", live, err)
	}
	duplicate, err := pin.RetainProcess()
	if err != nil {
		t.Fatal(err)
	}
	defer duplicate.Close()
	pinFixtureWrite(t, phase("action"), action)
	if action == "alive" {
		var wg sync.WaitGroup
		for range 64 {
			wg.Add(1)
			go func() {
				defer wg.Done()
				_, err := pin.Peer()
				if err != nil && !errors.Is(err, net.ErrClosed) {
					t.Error(err)
				}
				live, err := pin.Alive()
				if err != nil && !errors.Is(err, net.ErrClosed) {
					t.Error(err)
				}
				if err == nil && !live {
					t.Error("live occurrence disappeared")
				}
				pin.Close()
			}()
		}
		wg.Wait()
		if _, err := pin.Peer(); !errors.Is(err, net.ErrClosed) {
			t.Fatalf("closed pin: %v", err)
		}
		if live, err := duplicate.Alive(); !live || err != nil {
			t.Fatalf("independent owner=%v %v", live, err)
		}
	} else {
		if action == "exit" {
			pinFixtureWait(t, phase("client-reaped"))
		} else {
			fields := strings.Fields(string(pinFixtureWait(t, phase("after"))))
			process, _ := captured.Process.Get()
			wantVariant := "one"
			if action == "differentexec" {
				wantVariant = "two"
			}
			if len(fields) != 2 || fields[0] != strconv.Itoa(process.PID) || fields[1] != wantVariant {
				t.Fatalf("exec occurrence marker=%v original=%d want=%s", fields, process.PID, wantVariant)
			}
		}
		until := time.Now().Add(5 * time.Second)
		for {
			live, err := pin.Alive()
			if err != nil {
				t.Fatal(err)
			}
			if !live {
				break
			}
			if time.Now().After(until) {
				t.Fatal("ended occurrence remained alive")
			}
			time.Sleep(10 * time.Millisecond)
		}
		for _, old := range []*Binding{pin, duplicate} {
			if peer, err := old.Peer(); err != nil || peer != captured {
				t.Fatalf("historical occurrence peer=%v err=%v", peer, err)
			}
			if live, err := old.Alive(); live || err != nil {
				t.Fatalf("ended occurrence alive=%v err=%v", live, err)
			}
			if _, err := old.RetainProcess(); !errors.Is(err, ErrPeerGone) {
				t.Fatalf("retained ended occurrence: %v", err)
			}
		}
	}
	pin.Close()
	pin.Close()
	duplicate.Close()
	duplicate.Close()
	pinFixtureWrite(t, phase("finish"), "done")
	pinFixtureWrite(t, phase("result"), "passed")
}

func pinLaunchctl(ctx context.Context, args ...string) ([]byte, error) {
	return exec.CommandContext(ctx, "/bin/launchctl", args...).CombinedOutput()
}

func TestRetainProcessXPCNativeOccurrence(t *testing.T) {
	if os.Getenv("OA_IDENTITY_PIN_NATIVE") != "1" {
		t.Skip("requires isolated task-owned launchd fixture admission")
	}
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	after := os.Getenv("OA_IDENTITY_PIN_AFTER")
	if !filepath.IsAbs(after) || after == exe {
		t.Fatal("separate two-variant fixture binary required")
	}
	evidence := os.Getenv("OA_IDENTITY_PIN_EVIDENCE")
	if !filepath.IsAbs(evidence) || !strings.HasPrefix(evidence, "/private/tmp/macProcessPin978.") {
		t.Fatal("owned isolated fixture evidence directory required")
	}
	if err := os.MkdirAll(evidence, 0700); err != nil {
		t.Fatal(err)
	}
	for _, action := range []string{"alive", "exit", "sameexec", "differentexec"} {
		t.Run(action, func(t *testing.T) {
			dir := filepath.Join(evidence, action)
			if err := os.Mkdir(dir, 0700); err != nil {
				t.Fatal(err)
			}
			label := fmt.Sprintf("com.openabstractions.test.macProcessPin978.%d.%s", os.Getpid(), action)
			domain := "gui/" + strconv.Itoa(os.Getuid())
			target := domain + "/" + label
			command := func(args ...string) ([]byte, error) {
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				return pinLaunchctl(ctx, args...)
			}
			if out, err := command("print", target); err == nil || !strings.Contains(string(out), "Could not find service") {
				t.Fatalf("fixture label already present or unavailable: %v %s", err, out)
			}
			escape := html.EscapeString
			var envXML strings.Builder
			for key, value := range map[string]string{"OA_IDENTITY_PIN_ROLE": "server", "OA_IDENTITY_PIN_DIR": dir, "OA_IDENTITY_PIN_SERVICE": label, "OA_IDENTITY_PIN_CASE": action, "OA_IDENTITY_PIN_AFTER": after, "TMPDIR": os.Getenv("TMPDIR"), "GORACE": "atexit_sleep_ms=0"} {
				fmt.Fprintf(&envXML, "<key>%s</key><string>%s</string>", escape(key), escape(value))
			}
			serverLog := filepath.Join(dir, "server.log")
			plist := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?><plist version="1.0"><dict><key>Label</key><string>%s</string><key>ProgramArguments</key><array><string>%s</string><string>-test.run=^TestXPCProcessPinFixture$</string><string>-test.timeout=25s</string></array><key>EnvironmentVariables</key><dict>%s</dict><key>MachServices</key><dict><key>%s</key><true/></dict><key>StandardOutPath</key><string>%s</string><key>StandardErrorPath</key><string>%s</string></dict></plist>`, escape(label), escape(exe), envXML.String(), escape(label), escape(serverLog), escape(serverLog))
			path := filepath.Join(dir, "server.plist")
			if err := os.WriteFile(path, []byte(plist), 0600); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				command("bootout", target)
				out, err := command("print", target)
				if err == nil || !strings.Contains(string(out), "Could not find service") {
					t.Errorf("owned label cleanup unproven: %v %s", err, out)
				}
			})
			if out, err := command("bootstrap", domain, path); err != nil {
				t.Fatalf("bootstrap: %v %s", err, out)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			client := exec.CommandContext(ctx, exe, "-test.run=^TestXPCProcessPinFixture$", "-test.timeout=25s")
			client.Env = pinFixtureEnv(map[string]string{"OA_IDENTITY_PIN_ROLE": "client", "OA_IDENTITY_PIN_DIR": dir, "OA_IDENTITY_PIN_SERVICE": label, "OA_IDENTITY_PIN_CASE": action, "OA_IDENTITY_PIN_AFTER": after, "GORACE": "atexit_sleep_ms=0"})
			clientLog, err := os.Create(filepath.Join(dir, "client.log"))
			if err != nil {
				t.Fatal(err)
			}
			defer clientLog.Close()
			client.Stdout = clientLog
			client.Stderr = clientLog
			if err = client.Start(); err != nil {
				t.Fatal(err)
			}
			done := make(chan struct{})
			result := make(chan error, 1)
			go func() {
				err := client.Wait()
				os.WriteFile(filepath.Join(dir, "client-reaped"), []byte("reaped"), 0600)
				result <- err
				close(done)
			}()
			t.Cleanup(func() {
				select {
				case <-done:
				default:
					client.Process.Kill()
					<-done
				}
			})
			if got := string(pinFixtureWait(t, filepath.Join(dir, "result"))); got != "passed" {
				t.Fatal(got)
			}
			if err := <-result; err != nil {
				data, _ := os.ReadFile(filepath.Join(dir, "client.log"))
				t.Fatalf("client: %v %s", err, data)
			}
			until := time.Now().Add(5 * time.Second)
			var state []byte
			for time.Now().Before(until) {
				state, err = command("print", target)
				if err == nil && strings.Contains(string(state), "state = not running") {
					break
				}
				time.Sleep(20 * time.Millisecond)
			}
			if err != nil || !strings.Contains(string(state), "last exit code = 0") {
				data, _ := os.ReadFile(serverLog)
				t.Fatalf("server successful exit unproven: %v %s\n%s", err, state, data)
			}
			data, _ := os.ReadFile(serverLog)
			if strings.Contains(string(data), "FAIL") || strings.Contains(string(data), "DATA RACE") {
				t.Fatalf("server failed: %s", data)
			}
			t.Logf("%s: retained occurrence and owned service exit verified", action)
		})
	}
}

func TestXPCProcessPinRejectsInvalidNativeOwner(t *testing.T) {
	pin := &xpcProcessPin{}
	if live, err := pin.alive(); live || err == nil {
		t.Fatalf("invalid owner became live=%v err=%v", live, err)
	}
	if err := pin.recheck(); err == nil {
		t.Fatal("invalid owner became historical authority")
	}
	// OA_XPC_SYSTEM (the local header's value 7) remains an error even with a
	// zero diagnostic payload; only the C named-constant classifier selects
	// the occurrence-ended result.
	if err := xpcProcessError(7, 0); err == nil || errors.Is(err, ErrPeerGone) {
		t.Fatalf("system error collapsed: %v", err)
	}
	if _, err := (&Binding{inner: &bindingState{inner: &darwinBinding{}}}).RetainProcess(); !errors.Is(err, ErrNoBinding) {
		t.Fatalf("Unix ceiling changed: %v", err)
	}
}
