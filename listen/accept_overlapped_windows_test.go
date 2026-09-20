package listen

import (
	"fmt"
	"os"
	"runtime"
	"testing"
	"time"
)

// ConnectNamedPipe keeps the address of armedAccept.o until the connect
// completes, and the kernel writes the completion status into that memory. The
// collector tracks only Go references. Once connected has passed the port to
// its wait and reads a no further, the accept is unreachable and its memory can
// be reused while the connect is pending. The completion then overwrites the
// object that took the slot. In the facade runtime tests that appeared as nil
// interfaces in net/http, "found bad pointer in Go heap" and "morestack on g0".
// A cleanup on the accept runs after the collector frees it, and it must not
// run before the connect completes.
func TestPendingConnectKeepsItsOverlappedAlive(t *testing.T) {
	name := fmt.Sprintf(`\\.\pipe\accept-overlapped-%d-%d`, os.Getpid(), acceptThreadSerial.Add(1))
	l, err := Listen(name)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	p := l.(*pipeListener)
	a, err := p.arm()
	if err != nil {
		t.Fatal(err)
	}
	if !a.pending {
		t.Fatalf("connect did not pend: %v", a.cerr)
	}
	freed := make(chan struct{})
	runtime.AddCleanup(a, func(freed chan struct{}) { close(freed) }, freed)
	accepted := make(chan error, 1)
	go func(a *armedAccept) {
		c, err := p.connected(a)
		if c != nil {
			c.Close()
		}
		accepted <- err
	}(a)
	a = nil
	for range 20 {
		runtime.GC()
		select {
		case <-freed:
			c, err := Dial(name)
			if err == nil {
				c.Close()
			}
			t.Fatal("the pending connect's OVERLAPPED was freed while the kernel still held its address")
		case <-time.After(5 * time.Millisecond):
		}
	}
	c, err := Dial(name)
	if err != nil {
		t.Fatal(err)
	}
	c.Close()
	select {
	case err := <-accepted:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Accept did not return within 10s of a client connecting")
	}
}
