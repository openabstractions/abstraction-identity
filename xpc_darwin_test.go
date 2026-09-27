//go:build darwin && cgo

package identity

import (
	"context"
	"errors"
	"net"
	"os"
	"os/exec"
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
