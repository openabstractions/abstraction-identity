package identity

import (
	"errors"
	"fmt"
	"net"
	"os/exec"
	"sync"
	"testing"
	"time"

	"golang.org/x/sys/windows"
)

func TestRetainProcessWindowsRetiredPipeAndExit(t *testing.T) {
	name := pipeName(t)
	server := listen(t, name)
	child := startChildClient(t, name, "retain")
	at := accept(t, server)
	readFrom(t, server)
	b, err := Bind(Handle(server), &Options{ConnectedAt: at})
	if err != nil {
		t.Fatal(err)
	}
	pin, err := b.Shared().RetainProcess()
	if err != nil {
		b.Close()
		t.Fatal(err)
	}
	defer pin.Close()
	second, err := pin.RetainProcess()
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	b.Close()
	if live, err := pin.Alive(); !live || err != nil {
		t.Fatalf("live after owner close=%v %v", live, err)
	}
	if err = child.Wait(); err != nil {
		t.Fatal(err)
	}
	// Disconnect and reuse the very same pipe handle for a different connection.
	// A process-only pin must never consult its now-unrelated client PID.
	if err = windows.DisconnectNamedPipe(server); err != nil {
		t.Fatal(err)
	}
	startChildClient(t, name, "replacement")
	accept(t, server)
	readFrom(t, server)
	if _, err = pin.Peer(); err != nil {
		t.Fatalf("retired/reused pipe changed pin: %v", err)
	}
	if live, err := pin.Alive(); live || err != nil {
		t.Fatalf("exited=%v %v", live, err)
	}
	if _, err = pin.Peer(); err != nil {
		t.Fatalf("historical capture: %v", err)
	}
	if _, err = pin.RetainProcess(); !errors.Is(err, ErrPeerGone) {
		t.Fatalf("retain exited: %v", err)
	}
	pin.Close()
	pin.Close()
	if _, err = pin.Peer(); !errors.Is(err, net.ErrClosed) {
		t.Fatal(err)
	}
	if _, err = second.Peer(); err != nil {
		t.Fatalf("independent duplicate: %v", err)
	}
}

func TestRetainProcessWindowsRejectsContradictoryInstance(t *testing.T) {
	proc, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION|windows.SYNCHRONIZE, false, windows.GetCurrentProcessId())
	if err != nil {
		t.Fatal(err)
	}
	started, err := processStartTime(proc)
	if err != nil {
		windows.CloseHandle(proc)
		t.Fatal(err)
	}
	// Model a mismatched/recycled instance using a real held process primitive
	// and a contradictory creation time. No PID is reopened by retention.
	b := &Binding{inner: &bindingState{inner: &windowsProcessPin{proc: proc, started: started.Add(time.Second)}}}
	defer b.Close()
	if _, err = b.RetainProcess(); !errors.Is(err, ErrPeerMoved) {
		t.Fatalf("contradictory instance: %v", err)
	}
}

func TestRetainProcessWindowsExit259IsNotAlive(t *testing.T) {
	for _, exit := range []int{259, 7} {
		t.Run(fmt.Sprint(exit), func(t *testing.T) {
			name := pipeName(t)
			server := listen(t, name)
			child := startChildClientExit(t, name, "exit", exit)
			at := accept(t, server)
			readFrom(t, server)
			b, err := Bind(Handle(server), &Options{ConnectedAt: at})
			if err != nil {
				t.Fatal(err)
			}
			defer b.Close()
			pin, err := b.RetainProcess()
			if err != nil {
				t.Fatal(err)
			}
			defer pin.Close()
			// Each adapter owns a handle captured with the same shared liveness
			// right. Exercise all four Alive delegates on this real child handle.
			native := b.inner.(*bindingState).inner.(*windowsBinding)
			adapters := map[string]binder{
				"pipe":        native,
				"server":      &windowsServerBinding{windowsBinding: *native},
				"loopback":    &loopbackWindowsBinding{proc: native.proc},
				"unix-server": &unixServerWindowsBinding{proc: native.proc},
			}
			for name, adapter := range adapters {
				if live, err := adapter.alive(); !live || err != nil {
					t.Fatalf("running %s: %v %v", name, live, err)
				}
			}
			if live, err := pin.Alive(); !live || err != nil {
				t.Fatalf("running pin: %v %v", live, err)
			}
			err = child.Wait()
			var status *exec.ExitError
			if !errors.As(err, &status) || status.ExitCode() != exit {
				t.Fatalf("exit=%v want %d", err, exit)
			}
			for name, adapter := range adapters {
				if live, err := adapter.alive(); live || err != nil {
					t.Fatalf("exited %s: %v %v", name, live, err)
				}
			}
			for name, binding := range map[string]*Binding{"owner": b, "pin": pin} {
				if _, err := binding.Peer(); err != nil {
					t.Fatalf("%s historical peer: %v", name, err)
				}
				if live, err := binding.Alive(); live || err != nil {
					t.Fatalf("%s exited: %v %v", name, live, err)
				}
				if _, err := binding.RetainProcess(); !errors.Is(err, ErrPeerGone) {
					t.Fatalf("%s retained exited259: %v", name, err)
				}
			}
		})
	}
}

func TestRetainProcessWindowsBindServerUsesOwnedState(t *testing.T) {
	name := pipeName(t)
	server := listen(t, name)
	client := dial(t, name)
	at := accept(t, server)
	b, err := BindServer(Handle(client), &Options{ConnectedAt: at})
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	state, ok := b.inner.(*bindingState)
	if !ok {
		t.Fatal("BindServer bypassed shared ownership state")
	}
	native := state.inner.(*windowsServerBinding)
	sid := native.sid
	native.sid = "contradictory-primary-token"
	if _, err := b.RetainProcess(); !errors.Is(err, ErrPeerMoved) {
		t.Fatalf("server contradiction: %v", err)
	}
	native.sid = sid
	pin, err := b.Shared().RetainProcess()
	if err != nil {
		t.Fatal(err)
	}
	defer pin.Close()
	var wg sync.WaitGroup
	for range 16 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := b.Shared().Peer()
			if err != nil && !errors.Is(err, net.ErrClosed) {
				t.Error(err)
			}
			b.Close()
		}()
	}
	wg.Wait()
	if _, err := b.RetainProcess(); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("closed server acquisition: %v", err)
	}
	if _, err := b.Shared().Peer(); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("closed server view: %v", err)
	}
	if _, err := pin.Peer(); err != nil {
		t.Fatalf("retained server: %v", err)
	}
	if live, err := pin.Alive(); !live || err != nil {
		t.Fatalf("retained server live: %v %v", live, err)
	}
	pin.Close()
	pin.Close()
}
