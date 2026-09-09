//go:build linux || darwin

package main

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	identity "github.com/openabstractions/abstraction-identity"
	"golang.org/x/sys/unix"
)

const (
	roleEnv = "PEERID_ROLE"
	pathEnv = "PEERID_SOCKET"

	goFD    = 3
	readyFD = 4
)

const victim = "/bin/cat"

func runRole(mode string) int {
	switch mode {
	case "honest":
		c, err := net.Dial("unix", os.Getenv(pathEnv))
		if err != nil {
			return 1
		}
		defer c.Close()
		signal(readyFD)
		wait(goFD)
		return 0

	case "exec-drift":
		c, err := net.Dial("unix", os.Getenv(pathEnv))
		if err != nil {
			return 1
		}
		f, err := c.(*net.UnixConn).File()
		if err != nil {
			return 1
		}
		// The connection has to outlive the exec or the service just sees a
		// hangup instead of an impersonation.
		unix.FcntlInt(f.Fd(), unix.F_SETFD, 0)
		c.Close()
		signal(readyFD)
		wait(goFD)
		unix.Exec(victim, []string{"cat"}, os.Environ())
		return 1

	case "pre-forked":
		signal(readyFD)
		wait(goFD)
		unix.Exec(victim, []string{"cat"}, os.Environ())
		return 1
	}
	return 2
}

func signal(fd int) { os.NewFile(uintptr(fd), "ready").Write([]byte{1}) }
func wait(fd int) bool {
	_, err := os.NewFile(uintptr(fd), "go").Read(make([]byte, 1))
	return err == nil
}

type peer struct {
	cmd   *exec.Cmd
	go_   *os.File
	stdin *os.File
}

func (p *peer) release()     { p.go_.Write([]byte{1}) }
func (p *peer) say(s string) { p.stdin.Write([]byte(s)) }
func (p *peer) stop() {
	p.cmd.Process.Kill()
	p.cmd.Wait()
}

// start runs this binary again in the named role and blocks until it says it
// is in position. stdout, when non-nil, is what the child inherits as fd 1.
func start(role, sock string, stdout *os.File) (*peer, error) {
	self, err := os.Executable()
	if err != nil {
		return nil, err
	}
	goR, goW, _ := os.Pipe()
	readyR, readyW, _ := os.Pipe()
	inR, inW, _ := os.Pipe()

	cmd := exec.Command(self)
	cmd.Env = append(os.Environ(), roleEnv+"="+role, pathEnv+"="+sock)
	cmd.Stdin = inR
	cmd.Stdout = stdout
	cmd.Stderr = os.Stderr
	cmd.ExtraFiles = []*os.File{goR, readyW}
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	goR.Close()
	readyW.Close()
	inR.Close()

	readyR.SetReadDeadline(time.Now().Add(15 * time.Second))
	if _, err := readyR.Read(make([]byte, 1)); err != nil {
		cmd.Process.Kill()
		return nil, fmt.Errorf("the %s peer never reported in: %w", role, err)
	}
	readyR.Close()
	return &peer{cmd: cmd, go_: goW, stdin: inW}, nil
}

func listen() (*net.UnixListener, string, func(), error) {
	// sun_path is 104 bytes on macOS; a long temp path overruns it.
	dir, err := os.MkdirTemp("", "peerid")
	if err != nil {
		return nil, "", nil, err
	}
	sock := filepath.Join(dir, "s")
	l, err := net.ListenUnix("unix", &net.UnixAddr{Name: sock, Net: "unix"})
	if err != nil {
		os.RemoveAll(dir)
		return nil, "", nil, err
	}
	return l, sock, func() { l.Close(); os.RemoveAll(dir) }, nil
}

// accept takes the connection and binds it on the next line, which is the whole
// discipline this package asks a service for.
//
// A failure to bind is returned alongside the connection rather than instead of
// it. On a kernel with no SO_PEERPIDFD there is no binding to be had, and the
// demo has to show what that machine actually does rather than refusing to run.
func accept(l *net.UnixListener) (*net.UnixConn, *identity.Binding, time.Time, error) {
	l.SetDeadline(time.Now().Add(15 * time.Second))
	c, err := l.AcceptUnix()
	if err != nil {
		return nil, nil, time.Time{}, err
	}
	at := time.Now()
	b, berr := identity.BindConn(c, &identity.Options{ConnectedAt: at})
	return c, b, at, berr
}

func honestRound() (*round, error) {
	l, sock, done, err := listen()
	if err != nil {
		return nil, err
	}
	defer done()

	p, err := start("honest", sock, os.Stderr)
	if err != nil {
		return nil, err
	}
	defer p.stop()

	c, b, at, berr := accept(l)
	if c == nil {
		return nil, berr
	}
	defer c.Close()

	lookup, lerr := identity.OfConn(c, &identity.Options{ConnectedAt: at})
	r := &round{
		title: "round 1  an honest caller",
		narration: []string{
			fmt.Sprintf("pid %d connected and did nothing else", p.cmd.Process.Pid),
		},
		verdict:  "this machine cannot bind a peer, and says so instead of answering anyway",
		captured: answer{nil, berr},
		lookup:   answer{lookup, lerr},
		rebound:  answer{nil, berr},
	}
	if b != nil {
		defer b.Close()
		rb, rerr := b.Peer()
		r.captured = answer{b.Captured(), nil}
		r.rebound = answer{rb, rerr}
		r.verdict = ""
	}
	return r, nil
}
