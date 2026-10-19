package identity

import (
	"errors"
	"os"
	"testing"

	"github.com/openabstractions/abstraction-identity/fileid"
)

// The sandbox reader answers "no sandbox" only for a process whose cgroup it
// read: a pid with no /proc entry, as a process gone or hidden by hidepid
// has, is missing evidence, which SameView refuses with the reader's own
// reason (ID-F2). This process, whose /proc entry is readable, reads as it
// did.
func TestASandboxThatCannotBeReadIsRefused(t *testing.T) {
	// Above PID_MAX_LIMIT (1<<22), so no process has it.
	const gone = 1<<22 + 1
	name, why := sandboxPackage(gone)
	if name != "" || why == whyNoSandbox {
		t.Errorf("pid %d with no /proc entry reads %q, %q", gone, name, why)
	}
	p := sameAccountPeer(t)
	p.Package = unknown[string]("package", why)
	if err := p.SameView(); !errors.Is(err, fileid.ErrOtherView) {
		t.Errorf("SameView for a sandbox not read: %v, want ErrOtherView", err)
	}
	if name, why := sandboxPackage(os.Getpid()); name == "" && why != whyNoSandbox {
		t.Errorf("this process reads no sandbox with %q, want %q", why, whyNoSandbox)
	}
}
