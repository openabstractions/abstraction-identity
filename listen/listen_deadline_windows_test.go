package listen

import (
	"errors"
	"fmt"
	"net"
	"os"
	"testing"
	"time"
)

func TestPipeDeadline(t *testing.T) {
	name := fmt.Sprintf(`\\.\pipe\openabstractions-test-%d-%s`, os.Getpid(), t.Name())
	ln, err := Listen(name)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	accepted := make(chan Conn, 1)
	go func() {
		c, err := ln.Accept()
		if err == nil {
			accepted <- c
		}
	}()
	c, err := Dial(name)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	server := <-accepted
	defer server.Close()

	if err = c.SetReadDeadline(time.Now().Add(30 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		var b [1]byte
		_, err := c.Read(b[:])
		done <- err
	}()
	select {
	case err := <-done:
		var n net.Error
		if !errors.As(err, &n) || !n.Timeout() {
			t.Fatalf("expected timeout, got %v", err)
		}
	case <-time.After(200 * time.Millisecond):
		t.Fatal("SetReadDeadline returned nil but blocked Read did not expire")
	}
}

type withDeadline interface{ SetReadDeadline(time.Time) error }

// A deadline is honoured or refused, and the refusal is what a caller must
// never have to guess at. This is the same assertion made of the accepted end,
// which is the one every service in this repository reads from.
func TestAcceptedPipeDeadline(t *testing.T) {
	name := fmt.Sprintf(`\\.\pipe\openabstractions-test-%d-%s`, os.Getpid(), t.Name())
	ln, err := Listen(name)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	accepted := make(chan Conn, 1)
	go func() {
		c, err := ln.Accept()
		if err == nil {
			accepted <- c
		}
	}()
	c, err := Dial(name)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	server := <-accepted
	defer server.Close()

	d, ok := server.(withDeadline)
	if !ok {
		t.Fatal("an accepted connection cannot be given a deadline at all")
	}
	if err := d.SetReadDeadline(time.Now().Add(30 * time.Millisecond)); err != nil {
		t.Logf("deadlines refused explicitly, which is the other acceptable answer: %v", err)
		return
	}
	done := make(chan error, 1)
	go func() {
		var b [1]byte
		_, err := server.Read(b[:])
		done <- err
	}()
	select {
	case err := <-done:
		var n net.Error
		if !errors.As(err, &n) || !n.Timeout() {
			t.Fatalf("expected timeout, got %v", err)
		}
	case <-time.After(200 * time.Millisecond):
		t.Fatal("SetReadDeadline returned nil but blocked Read did not expire")
	}
}
