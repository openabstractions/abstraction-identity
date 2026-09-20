package listen

import (
	"errors"
	"fmt"
	"net"
	"os"
	"runtime"
	"sync/atomic"
	"testing"
	"time"
)

var acceptThreadSerial atomic.Int64

// Accept initiates ConnectNamedPipe on whichever OS thread runs it. If the
// scheduler moves the goroutine before it waits, that thread can go on to block
// in unrelated synchronous I/O. Close must still release Accept. The seam
// forces that interleaving: the connect is armed on a locked thread which then
// blocks in a pipe read, and the wait runs on another goroutine.
func TestCloseReleasesAcceptWhileArmingThreadBlocks(t *testing.T) {
	defer runtime.GOMAXPROCS(runtime.GOMAXPROCS(1))
	l, err := Listen(fmt.Sprintf(`\\.\pipe\accept-thread-%d-%d`, os.Getpid(), acceptThreadSerial.Add(1)))
	if err != nil {
		t.Fatal(err)
	}
	p := l.(*pipeListener)
	pr, pw, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer pr.Close()
	defer pw.Close()
	armed := make(chan *armedAccept, 1)
	armErr := make(chan error, 1)
	go func() {
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()
		a, err := p.arm()
		if err != nil {
			armErr <- err
			return
		}
		armed <- a
		var b [1]byte
		pr.Read(b[:])
	}()
	var a *armedAccept
	select {
	case a = <-armed:
	case err := <-armErr:
		t.Fatal(err)
	}
	if !a.pending {
		t.Fatalf("connect did not pend: %v", a.cerr)
	}
	done := make(chan error, 1)
	go func() {
		c, err := p.connected(a)
		if c != nil {
			c.Close()
		}
		done <- err
	}()
	time.Sleep(20 * time.Millisecond)
	closed := make(chan error, 1)
	go func() { closed <- l.Close() }()
	hang := time.After(10 * time.Second)
	select {
	case err := <-closed:
		if err != nil {
			t.Fatal(err)
		}
	case <-hang:
		pw.Write([]byte{1})
		t.Fatal("Close did not return within 10s while the arming thread blocked in a pipe read")
	}
	select {
	case err := <-done:
		if !errors.Is(err, net.ErrClosed) {
			t.Fatalf("Accept after Close: %v", err)
		}
	case <-hang:
		pw.Write([]byte{1})
		t.Fatal("Accept did not return within 10s of Close while the arming thread blocked in a pipe read")
	}
	pw.Write([]byte{1})
}
