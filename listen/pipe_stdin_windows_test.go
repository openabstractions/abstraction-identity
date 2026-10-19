package listen

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/windows"
)

func TestPipeCachedStdinRegression(t *testing.T) {
	for _, mode := range []string{"dial-adoption", "accepted-adoption"} {
		t.Run(mode, func(t *testing.T) {
			exe, err := os.Executable()
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, exe, "-test.run=^TestPipeCachedStdinChild$", "--", mode)
			// Only the owned child changes its cached Go stdin number. It never
			// closes or changes the parent's or the person's standard input.
			if out, err := cmd.CombinedOutput(); err != nil {
				t.Fatalf("owned %s child: %v\n%s", mode, err, out)
			}
		})
	}
}

func TestPipeCachedStdinChild(t *testing.T) {
	if len(os.Args) < 2 {
		return
	}
	mode := os.Args[len(os.Args)-1]
	if mode != "dial-adoption" && mode != "accepted-adoption" {
		return
	}
	name := fmt.Sprintf(`\\.\pipe\openabstractions-test-%d-cached-stdin-%s`, os.Getpid(), mode)
	listener, err := Listen(name)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	oldStdin := syscall.Stdin
	defer func() { syscall.Stdin = oldStdin }()
	if mode == "accepted-adoption" {
		p := listener.(*pipeListener)
		// This deterministic cache alias models a newly allocated overlapped
		// handle reusing the closed stdin number. Native identity stays real.
		syscall.Stdin = p.waiting
	}
	accepted := make(chan Conn, 1)
	failed := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			failed <- err
		} else {
			accepted <- conn
		}
	}()
	n, err := windows.UTF16PtrFromString(name)
	if err != nil {
		t.Fatal(err)
	}
	h, err := windows.CreateFile(n, windows.FILE_GENERIC_READ|(windows.FILE_GENERIC_WRITE&^windows.FILE_APPEND_DATA), windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE, nil, windows.OPEN_EXISTING, identifyOnly|windows.FILE_FLAG_OVERLAPPED, 0)
	if err != nil {
		t.Fatal(err)
	}
	var server Conn
	select {
	case server = <-accepted:
	case err := <-failed:
		windows.CloseHandle(h)
		t.Fatal(err)
	case <-time.After(time.Second):
		windows.CloseHandle(h)
		t.Fatal("native accept deadline")
	}
	defer server.Close()
	if mode == "dial-adoption" {
		syscall.Stdin = syscall.Handle(h)
	}
	client, _, err := adoptPipeFile(syscall.Handle(h), name)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	target := client
	if mode == "accepted-adoption" {
		p := server.(*pipeConn)
		target = p.File
		raw, err := p.File.SyscallConn()
		if err != nil {
			t.Fatal(err)
		}
		var actual syscall.Handle
		if err := raw.Control(func(fd uintptr) { actual = syscall.Handle(fd) }); err != nil {
			t.Fatal(err)
		}
		if p.h != actual {
			t.Fatal("Bind retained a different native handle")
		}
	}
	if err := target.SetDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatalf("owned cached-stdin pipe lost deadline support: %v", err)
	}
	if _, err := client.Write([]byte{1}); err != nil {
		t.Fatal(err)
	}
	var one [1]byte
	if _, err := io.ReadFull(server, one[:]); err != nil {
		t.Fatal(err)
	}
	bound, err := server.Bind()
	if err != nil {
		t.Fatal(err)
	}
	defer bound.Close()
	peer := bound.Captured()
	if err := peer.Check(Program); err != nil {
		t.Fatal(err)
	}
	process, _ := peer.Process.Get()
	if process.PID != os.Getpid() {
		t.Fatal("native peer changed during adoption")
	}
	if err := target.SetReadDeadline(time.Now().Add(20 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { _, err := target.Read(one[:]); done <- err }()
	select {
	case err := <-done:
		if !os.IsTimeout(err) {
			t.Fatalf("native deadline: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("native read ignored deadline")
	}
	if err := target.SetDeadline(time.Time{}); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	stop := context.AfterFunc(ctx, func() { target.Close() })
	defer stop()
	go func() { _, err := target.Read(one[:]); done <- err }()
	cancel()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("cancelled native read succeeded")
		}
	case <-time.After(time.Second):
		t.Fatal("native cancellation did not release read")
	}
}
