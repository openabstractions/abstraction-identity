//go:build windows

package identity

import (
	"errors"
	"net"
	"testing"
	"time"

	"golang.org/x/sys/windows"
)

// ID-T8 on Windows: a server process created after the moment the caller
// says the connection existed is a reused process id, refused at bind.
func TestBindUnixServerRefusesAServerCreatedAfterTheConnection(t *testing.T) {
	before := time.Now()
	path := socketPath(t)
	unixServerChild(t, path)
	conn, err := net.Dial("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if _, err := BindUnixServer(conn, &Options{ConnectedAt: before, SkipCodeSignature: true}); !errors.Is(err, ErrPeerMoved) {
		t.Fatalf("a server created after ConnectedAt: %v, wanted ErrPeerMoved", err)
	}
}

// ID-T8 on Windows: a later answer naming another process than the bind
// captured is refused, at every recheck.
func TestUnixServerRecheckRefusesAnotherProcess(t *testing.T) {
	path := socketPath(t)
	unixServerChild(t, path)
	conn, err := net.Dial("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	binding, err := BindUnixServer(conn, &Options{ConnectedAt: time.Now(), SkipCodeSignature: true})
	if err != nil {
		t.Fatal(err)
	}
	defer binding.Close()
	if _, err := binding.Peer(); err != nil {
		t.Fatal(err)
	}
	inner := binding.inner.(*bindingState).inner.(*unixServerWindowsBinding)
	inner.pid++
	if _, err := binding.Peer(); !errors.Is(err, ErrPeerMoved) {
		t.Fatalf("the kernel naming another process: %v, wanted ErrPeerMoved", err)
	}
}

// ID-T8 on Windows: only a closed or disconnected socket passes a recheck
// unanswered; any other failure to ask refuses.
func TestUnixServerRecheckPassesOnlyADisconnectedSocket(t *testing.T) {
	for _, err := range []error{windows.WSAENOTSOCK, windows.WSAENOTCONN, windows.WSAECONNRESET, windows.WSAECONNABORTED, windows.WSAESHUTDOWN} {
		if !disconnected(err) {
			t.Fatalf("%v reads connected", err)
		}
	}
	for _, err := range []error{windows.WSAEFAULT, windows.WSAEINVAL, windows.WSAEOPNOTSUPP, errors.New("no process")} {
		if disconnected(err) {
			t.Fatalf("%v reads disconnected", err)
		}
	}
	b := &unixServerWindowsBinding{socket: windows.InvalidHandle - 1}
	if err := b.recheck(); err != nil {
		t.Fatalf("a closed socket handle: %v, wanted nil", err)
	}
}
