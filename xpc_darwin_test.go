//go:build darwin && cgo

package identity

import (
	"context"
	"errors"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"testing"
	"time"
)

func TestOpenXPCListenerRejectsForgedRegistration(t *testing.T) {
	if os.Getenv("OA_XPC_UNREGISTERED_HELPER") == "1" {
		service := "com.openabstractions.test.unregistered." + strconv.Itoa(os.Getpid())
		listener, err := OpenXPCListener(service, 1024)
		if err != nil {
			return // A synchronous platform refusal is also valid.
		}
		defer listener.Close()
		request, err := listener.Accept()
		if request != nil {
			request.Close()
			t.Fatal("unregistered listener accepted a request")
		}
		if !errors.Is(err, net.ErrClosed) {
			t.Fatalf("unregistered listener accept = %v", err)
		}
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestOpenXPCListenerRejectsForgedRegistration$")
	command.Env = append(os.Environ(), "OA_XPC_UNREGISTERED_HELPER=1", "XPC_SERVICE_NAME=forged.nonempty.job")
	output, err := command.CombinedOutput()
	if ctx.Err() != nil {
		t.Fatalf("unregistered listener did not refuse within the bound: %v\n%s", ctx.Err(), output)
	}
	if err != nil {
		t.Fatalf("unregistered listener helper: %v\n%s", err, output)
	}
}

func TestOpenXPCClientRejectsNonCodeProgram(t *testing.T) {
	program := filepath.Join(t.TempDir(), "not-a-program")
	if err := os.WriteFile(program, []byte("ordinary non-code expected program\n"), 0600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	service := "com.openabstractions.test.invalidprogram." + strconv.Itoa(os.Getpid())
	client, err := OpenXPCClient(ctx, service, program, uint32(os.Geteuid()), 1024)
	if client != nil {
		client.Close()
		t.Fatal("non-code expected program returned a client")
	}
	if !errors.Is(err, ErrNoBinding) {
		t.Fatalf("non-code expected program error = %v, want ErrNoBinding", err)
	}
}
