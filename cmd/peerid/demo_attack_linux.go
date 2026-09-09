//go:build linux

package main

import (
	"fmt"
	"os"
	"time"

	identity "github.com/openabstractions/abstraction-identity"
)

// On Linux the peer that connected is the peer for ever: SO_PEERCRED and
// SO_PEERPIDFD are derived from the connection, so no other process can take
// it over by writing. The one way left to become another program is execve,
// in place, which keeps the pid and the start time and changes only what
// /proc/<pid>/exe points at.
func attackRound() (*round, error) {
	l, sock, done, err := listen()
	if err != nil {
		return nil, err
	}
	defer done()

	p, err := start("exec-drift", sock, os.Stderr)
	if err != nil {
		return nil, err
	}
	defer p.stop()

	c, b, at, berr := accept(l)
	if c == nil {
		return nil, berr
	}
	defer c.Close()

	was, _ := os.Readlink(fmt.Sprintf("/proc/%d/exe", p.cmd.Process.Pid))
	p.release()
	now, err := waitForExec(p.cmd.Process.Pid, was)
	if err != nil {
		return nil, err
	}

	lookup, lerr := identity.OfConn(c, &identity.Options{ConnectedAt: at})
	r := &round{
		title: "round 2  the same caller, replaced by " + victim + " after it connected",
		narration: []string{
			fmt.Sprintf("pid %d connected as %s", p.cmd.Process.Pid, was),
			fmt.Sprintf("then called execve(%q) while holding the connection open", victim),
			fmt.Sprintf("its pid, its start time and SO_PEERCRED are all unchanged; only the image is %s", now),
		},
		verdict:  "there is no binding to be had on this kernel, and the lookup answers /bin/cat: a service here must refuse to start, not grant",
		captured: answer{nil, berr},
		lookup:   answer{lookup, lerr},
		rebound:  answer{nil, berr},
	}
	if b != nil {
		defer b.Close()
		rb, rerr := b.Peer()
		r.captured = answer{b.Captured(), nil}
		r.rebound = answer{rb, rerr}
		r.verdict = "the lookup was fooled and the binding refused it by name; SO_PEERPIDFD is what makes that possible"
	}
	return r, nil
}

func waitForExec(pid int, was string) (string, error) {
	deadline := time.Now().Add(15 * time.Second)
	for {
		got, err := os.Readlink(fmt.Sprintf("/proc/%d/exe", pid))
		if err == nil && got != was {
			return got, nil
		}
		if time.Now().After(deadline) {
			return "", fmt.Errorf("the peer never became %s", victim)
		}
		time.Sleep(2 * time.Millisecond)
	}
}
