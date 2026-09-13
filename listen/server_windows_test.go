package listen

import (
	"context"
	"os"
	"testing"

	"golang.org/x/sys/windows"
)

func TestClientHandleNamesServerBeforePayload(t *testing.T) {
	endpoint := framedEndpoint(t)
	listener, err := Listen(endpoint)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	conn, err := dialFramed(context.Background(), endpoint)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	var pid uint32
	if err := windows.GetNamedPipeServerProcessId(windows.Handle(conn.(interface{ Fd() uintptr }).Fd()), &pid); err != nil {
		t.Fatal(err)
	}
	if pid != uint32(os.Getpid()) {
		t.Fatalf("server pid %d want %d", pid, os.Getpid())
	}
}
