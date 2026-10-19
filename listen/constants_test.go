package listen

import (
	"testing"
	"time"

	api "github.com/openabstractions/abstraction-identity/go/abstraction/identity/api"
)

// The Go transport reads abstraction-ipc's bounds from identity.thrift's
// generated constants (IPC-F1, IPC-D1), as the Python, C++, Rust and
// JavaScript bindings read them from abstraction.ipc.constants.
func TestTransportBoundsComeFromTheDefinition(t *testing.T) {
	if DefaultMaxFrame != 1048576 {
		t.Fatalf("DefaultMaxFrame = %d, want ipc_default_max_frame %d", DefaultMaxFrame, api.IPCDefaultMaxFrame)
	}
	if DefaultFrameTimeout != 5*time.Second {
		t.Fatalf("DefaultFrameTimeout = %v, want ipc_default_call_budget_ms %d", DefaultFrameTimeout, api.IPCDefaultCallBudgetMs)
	}
	// The header's length bits carry exactly the payload ceiling the definition states.
	if lengthMask != uint32(api.IPCWireMaxFrame) {
		t.Fatalf("lengthMask = %#x, want ipc_wire_max_frame %#x", lengthMask, api.IPCWireMaxFrame)
	}
}
