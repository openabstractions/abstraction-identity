package listen

import (
	"context"
	identity "github.com/openabstractions/abstraction-identity"
	"net"
	"testing"
	"time"
)

func TestFrameClientDefaultsRetainOptions(t *testing.T) {
	expected := &ServerExpectation{Program: "original", Process: &identity.Process{PID: 42}}
	called := false
	c := (FrameClient{Endpoint: "fixed", Timeout: time.Second, MaxFrame: 123, Server: expected, Dialer: func(context.Context, string) (net.Conn, error) { called = true; return nil, nil }}).WithDefaults(2*time.Second, 456)
	expected.Program = "changed"
	expected.Process.PID = 43
	if c.Endpoint != "fixed" || c.Timeout != time.Second || c.MaxFrame != 123 || c.Server.Program != "original" || c.Server.Process.PID != 42 {
		t.Fatalf("options lost: %+v", c)
	}
	c.Dialer(context.Background(), c.Endpoint)
	if !called {
		t.Fatal("dialer lost")
	}
	defaults := (FrameClient{}).WithDefaults(time.Second, 123)
	if defaults.Timeout != time.Second || defaults.MaxFrame != 123 || defaults.Server != nil {
		t.Fatal(defaults)
	}
}
