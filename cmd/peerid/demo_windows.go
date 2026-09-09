//go:build windows

package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	identity "github.com/openabstractions/abstraction-identity"
	"golang.org/x/sys/windows"
)

const (
	roleEnv = "PEERID_ROLE"
	pipeEnv = "PEERID_PIPE"
)

var victim = filepath.Join(os.Getenv("SystemRoot"), "System32", "cmd.exe")

func runRole(mode string) int {
	h, err := open(os.Getenv(pipeEnv))
	if err != nil {
		fmt.Fprintf(os.Stderr, "peer: %v\n", err)
		return 1
	}
	defer windows.CloseHandle(h)

	var n uint32
	if err := windows.WriteFile(h, []byte("hello"), &n, nil); err != nil {
		return 1
	}
	if mode == "drift" {
		// Hand the connected pipe to a Microsoft-signed program and let it
		// do the writing. This is the move that takes over the answer on
		// macOS.
		c := exec.Command(victim, "/c", "echo i-am-cmd")
		c.Stdout = os.NewFile(uintptr(h), "pipe")
		c.Stderr = os.Stderr
		c.Run()
	}
	time.Sleep(4 * time.Second)
	return 0
}

func open(name string) (windows.Handle, error) {
	n, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return 0, err
	}
	deadline := time.Now().Add(15 * time.Second)
	for {
		h, err := windows.CreateFile(n, windows.GENERIC_READ|windows.GENERIC_WRITE,
			0, nil, windows.OPEN_EXISTING, 0, 0)
		if err == nil {
			return h, nil
		}
		if time.Now().After(deadline) {
			return 0, err
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func listen() (windows.Handle, string, func(), error) {
	name := fmt.Sprintf(`\\.\pipe\peerid-%d`, os.Getpid())
	n, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return 0, "", nil, err
	}
	h, err := windows.CreateNamedPipe(n, windows.PIPE_ACCESS_DUPLEX,
		windows.PIPE_TYPE_BYTE|windows.PIPE_READMODE_BYTE|windows.PIPE_WAIT|windows.PIPE_REJECT_REMOTE_CLIENTS,
		1, 4096, 4096, 0, nil)
	if err != nil {
		return 0, "", nil, err
	}
	return h, name, func() { windows.CloseHandle(h) }, nil
}

func start(role, pipe string) (*exec.Cmd, error) {
	self, err := os.Executable()
	if err != nil {
		return nil, err
	}
	c := exec.Command(self)
	c.Env = append(os.Environ(), roleEnv+"="+role, pipeEnv+"="+pipe)
	c.Stderr = os.Stderr
	if err := c.Start(); err != nil {
		return nil, err
	}
	return c, nil
}

// serve accepts one connection, reads the frame Windows requires before it
// will identify anybody, and binds on the next line.
func serve(h windows.Handle) (time.Time, *identity.Binding, error) {
	type res struct {
		at  time.Time
		err error
	}
	ch := make(chan res, 1)
	go func() {
		err := windows.ConnectNamedPipe(h, nil)
		ch <- res{time.Now(), err}
	}()
	var at time.Time
	select {
	case r := <-ch:
		if r.err != nil && r.err != windows.ERROR_PIPE_CONNECTED {
			return time.Time{}, nil, r.err
		}
		at = r.at
	case <-time.After(20 * time.Second):
		return time.Time{}, nil, fmt.Errorf("no client connected")
	}

	buf := make([]byte, 512)
	var n uint32
	if err := windows.ReadFile(h, buf, &n, nil); err != nil {
		return at, nil, err
	}
	b, err := identity.Bind(identity.Handle(h), &identity.Options{ConnectedAt: at})
	return at, b, err
}

func honestRound() (*round, error) {
	h, name, done, err := listen()
	if err != nil {
		return nil, err
	}
	defer done()

	c, err := start("honest", name)
	if err != nil {
		return nil, err
	}
	defer func() { c.Process.Kill(); c.Wait() }()

	at, b, err := serve(h)
	if err != nil {
		return nil, err
	}
	defer b.Close()

	lookup, lerr := identity.OfHandle(identity.Handle(h), &identity.Options{ConnectedAt: at})
	rb, rerr := b.Peer()
	return &round{
		title: "round 1  an honest caller",
		narration: []string{
			fmt.Sprintf("pid %d opened the pipe and wrote one frame", c.Process.Pid),
		},
		captured: answer{b.Captured(), nil},
		lookup:   answer{lookup, lerr},
		rebound:  answer{rb, rerr},
	}, nil
}

// attackRound runs the macOS socket-owner drift against a named pipe, where it
// must not work. The client hands its pipe handle to cmd.exe and lets cmd.exe
// write; the service must still name the process that opened the pipe.
func attackRound() (*round, error) {
	h, name, done, err := listen()
	if err != nil {
		return nil, err
	}
	defer done()

	c, err := start("drift", name)
	if err != nil {
		return nil, err
	}
	defer func() { c.Process.Kill(); c.Wait() }()

	at, b, err := serve(h)
	if err != nil {
		return nil, err
	}
	defer b.Close()

	wrote := drain(h, 5*time.Second)

	lookup, lerr := identity.OfHandle(identity.Handle(h), &identity.Options{ConnectedAt: at})
	rb, rerr := b.Peer()
	return &round{
		title:   "round 2  the caller hands the connected pipe to " + victim,
		verdict: "the pipe names the process that opened it, and the drift that wins on macOS moves nothing here",
		narration: []string{
			fmt.Sprintf("pid %d opened the pipe, then ran %s with the pipe as its stdout", c.Process.Pid, victim),
			fmt.Sprintf("%s wrote %q through a pipe it never opened", filepath.Base(victim), wrote),
			"on macOS that write takes over the answer, signature included; here it must not",
		},
		captured: answer{b.Captured(), nil},
		lookup:   answer{lookup, lerr},
		rebound:  answer{rb, rerr},
	}, nil
}

func drain(h windows.Handle, d time.Duration) string {
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
		return trimEOL(s)
	case <-time.After(d):
		return ""
	}
}

func trimEOL(s string) string {
	for len(s) > 0 && (s[len(s)-1] == '\n' || s[len(s)-1] == '\r') {
		s = s[:len(s)-1]
	}
	return s
}
