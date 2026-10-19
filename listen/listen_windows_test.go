package listen

import (
	"errors"
	"fmt"
	"net"
	"os"
	"testing"
	"time"

	"golang.org/x/sys/windows"
)

func TestAPipeNameBelongsToTheFirstListener(t *testing.T) {
	name := fmt.Sprintf(`\\.\pipe\openabstractions-test-%d-%s`, os.Getpid(), t.Name())
	first, err := Listen(name)
	if err != nil {
		t.Fatal(err)
	}
	second, err := Listen(name)
	if err == nil {
		second.Close()
		t.Fatal("a second listener took a name that was already served")
	}
	if !errors.Is(err, ErrTaken) {
		t.Fatalf("the second listener was refused for the wrong reason: %v", err)
	}
	first.Close()
	again, err := Listen(name)
	if err != nil {
		t.Fatalf("the name was still taken after its listener closed: %v", err)
	}
	again.Close()
}

// ConnectNamedPipe reports ERROR_NO_DATA when the previous client closed
// before the server connected. That one aborted connection cannot retire
// the listener: another client must still reach the same endpoint.
func TestAcceptContinuesAfterAClientClosesBeforeConnect(t *testing.T) {
	name := fmt.Sprintf(`\\.\pipe\aborted-connect-%d-%s`, os.Getpid(), t.Name())
	l, err := Listen(name)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	aborted, err := Dial(name)
	if err != nil {
		t.Fatal(err)
	}
	if err := aborted.Close(); err != nil {
		t.Fatal(err)
	}
	type result struct {
		conn Conn
		err  error
	}
	done := make(chan result, 1)
	go func() { c, err := l.Accept(); done <- result{c, err} }()
	valid, err := Dial(name)
	if err != nil {
		t.Fatal(err)
	}
	defer valid.Close()
	select {
	case got := <-done:
		if got.err != nil {
			t.Fatalf("the aborted client retired the listener: %v", got.err)
		}
		got.conn.Close()
	case <-time.After(5 * time.Second):
		t.Fatal("the subsequent valid client was not accepted")
	}
}

// The existing arm/connected seam supplies an unexpected connect completion
// without changing a process-global syscall. Its real OS cause must survive.
func TestConnectFailurePreservesItsOSCause(t *testing.T) {
	name := fmt.Sprintf(`\\.\pipe\connect-cause-%d-%s`, os.Getpid(), t.Name())
	l, err := Listen(name)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	client, err := Dial(name)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	p := l.(*pipeListener)
	a, err := p.arm()
	if err != nil {
		t.Fatal(err)
	}
	if a.pending {
		t.Fatal("the preconnected client's connect unexpectedly pended")
	}
	a.cerr = windows.ERROR_ACCESS_DENIED
	conn, err := p.connected(a)
	if conn != nil {
		conn.Close()
		t.Fatal("an unknown connect failure returned a connection")
	}
	if !errors.Is(err, windows.ERROR_ACCESS_DENIED) {
		t.Fatalf("the connect failure lost its OS cause: %v", err)
	}
}

func TestCloseReleasesAcceptAfterAnAbortedConnection(t *testing.T) {
	name := fmt.Sprintf(`\\.\pipe\close-aborted-%d-%s`, os.Getpid(), t.Name())
	l, err := Listen(name)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	client, err := Dial(name)
	if err != nil {
		t.Fatal(err)
	}
	client.Close()
	done := make(chan error, 1)
	go func() {
		conn, err := l.Accept()
		if conn != nil {
			conn.Close()
		}
		done <- err
	}()
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if !errors.Is(err, net.ErrClosed) {
			t.Fatalf("Accept after Close: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Close left Accept blocked after an aborted connection")
	}
}

func TestPipeNameCanBeReboundWhileOldClientHandleRemainsOpen(t *testing.T) {
	name := fmt.Sprintf(`\\.\pipe\rebind-held-client-%d-%s`, os.Getpid(), t.Name())
	first, err := Listen(name)
	if err != nil {
		t.Fatal(err)
	}
	accepted := make(chan Conn, 1)
	go func() {
		server, err := first.Accept()
		if err != nil {
			accepted <- nil
			return
		}
		accepted <- server
	}()
	client, err := Dial(name)
	if err != nil {
		first.Close()
		t.Fatal(err)
	}
	defer client.Close()
	server := <-accepted
	if server == nil {
		first.Close()
		t.Fatal("the first listener did not accept the client")
	}
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	if err := server.Close(); err != nil {
		t.Fatal(err)
	}
	again, err := Listen(name)
	if err != nil {
		t.Fatalf("the old client's still-open handle holds the name: %v", err)
	}
	again.Close()
}
