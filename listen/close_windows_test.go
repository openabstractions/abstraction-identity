package listen

import (
	"errors"
	"fmt"
	"net"
	"os"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/windows"
)

func TestRepeatedCloseDoesNotCloseRecycledHandle(t *testing.T) {
	l, err := Listen(fmt.Sprintf(`\\.\pipe\close-reuse-%d`, os.Getpid()))
	if err != nil {
		t.Fatal(err)
	}
	p := l.(*pipeListener)
	old := p.waiting
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	// Keep new handles live until Windows recycles the listener's numeric slot.
	// This is another owner's event, not a handle the listener may close.
	var events []windows.Handle
	defer func() {
		for _, h := range events {
			windows.CloseHandle(h)
		}
	}()
	var reused windows.Handle
	for i := 0; i < 4096; i++ {
		h, err := windows.CreateEvent(nil, 1, 0, nil)
		if err != nil {
			t.Fatal(err)
		}
		events = append(events, h)
		if syscall.Handle(h) == old {
			reused = h
			break
		}
	}
	if reused == 0 {
		t.Fatal("Windows did not recycle the released handle within the bounded fixture")
	}
	_ = l.Close()
	if err := windows.SetEvent(reused); err != nil {
		t.Fatalf("second close destroyed another owner's recycled event: %v", err)
	}
}

func TestCloseUnblocksPendingAcceptAndRemainsClosed(t *testing.T) {
	for i := 0; i < 20; i++ {
		l, err := Listen(fmt.Sprintf(`\\.\pipe\close-accept-%d-%d`, os.Getpid(), i))
		if err != nil {
			t.Fatal(err)
		}
		done := make(chan error, 1)
		go func() {
			c, err := l.Accept()
			if c != nil {
				c.Close()
			}
			done <- err
		}()
		deadline := time.Now().Add(time.Second)
		for {
			p := l.(*pipeListener)
			p.mu.Lock()
			pending := p.accepting
			p.mu.Unlock()
			if pending {
				break
			}
			if time.Now().After(deadline) {
				t.Fatal("Accept did not enter pending connect")
			}
			time.Sleep(time.Millisecond)
		}
		if err := l.Close(); err != nil {
			t.Fatal(err)
		}
		select {
		case err := <-done:
			if !errors.Is(err, net.ErrClosed) {
				t.Fatalf("Accept after Close: %v", err)
			}
		case <-time.After(2 * time.Second):
			t.Fatal("Close did not release Accept")
		}
		if _, err := l.Accept(); !errors.Is(err, net.ErrClosed) {
			t.Fatalf("closed Accept: %v", err)
		}
		_ = l.Close()
	}
}

func TestNextInstanceFailureRetiresListener(t *testing.T) {
	name := fmt.Sprintf(`\\.\pipe\close-next-%d`, os.Getpid())
	l, err := Listen(name)
	if err != nil {
		t.Fatal(err)
	}
	p := l.(*pipeListener)
	// The first instance exists; force CreateNamedPipe for its successor to fail.
	p.name, err = syscall.UTF16PtrFromString("not-a-pipe-path")
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		c, err := l.Accept()
		if c != nil {
			c.Close()
		}
		done <- err
	}()
	c, err := Dial(name)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("invalid next pipe name succeeded")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Accept did not return creation failure")
	}
	p.mu.Lock()
	closed, waiting := p.closed, p.waiting
	p.mu.Unlock()
	if !closed || waiting != 0 {
		t.Fatalf("failed next instance retained handle ownership: closed=%v waiting=%v", closed, waiting)
	}
	if !errors.Is(l.Close(), net.ErrClosed) {
		t.Fatal("failed listener was not already closed")
	}
	if _, err := l.Accept(); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("failed listener accepted again: %v", err)
	}
}
