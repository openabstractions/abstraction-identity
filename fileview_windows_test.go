package identity

import (
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/openabstractions/abstraction-identity/fileid"
	"golang.org/x/sys/windows"
)

// The pinned reader behind the loopback and AF_UNIX peers reads this
// process's package identity: an answer of no package is this process's
// view, and a failed GetPackageFullName is missing evidence, which SameView
// refuses with the call's own reason (ID-F2). The failure is injected; the
// rest of the read is this process's own token and image.
func TestAPinnedPeerWhosePackageCannotBeReadIsRefused(t *testing.T) {
	proc := windows.CurrentProcess()
	pid := uint32(os.Getpid())
	read := func(transport string) *Peer {
		t.Helper()
		p, err := pinnedProcessPeer(proc, pid, time.Now(), transport, "test", "test", "test", &Options{SkipCodeSignature: true})
		if err != nil {
			t.Fatal(err)
		}
		return p
	}
	if u, _ := read(TransportLoopback).User.Get(); u.IntegrityRID < mediumIntegrityRID {
		t.Skipf("this process runs at %s integrity, which SameView refuses on its own", u.Integrity)
	}
	if err := read(TransportLoopback).SameView(); err != nil {
		t.Fatalf("this process over loopback, its package read: %v", err)
	}
	real := readPackageFullName
	readPackageFullName = func(windows.Handle) (string, error) { return "", windows.ERROR_ACCESS_DENIED }
	t.Cleanup(func() { readPackageFullName = real })
	for _, transport := range []string{TransportLoopback, string(TransportUnix)} {
		p := read(transport)
		if why := p.Package.Why(); why == whyNotPackaged || !strings.Contains(why, "GetPackageFullName failed") {
			t.Errorf("%s: a failed GetPackageFullName reads %q", transport, why)
		}
		if p.Transport == TransportLoopback {
			if err := p.SameView(); !errors.Is(err, fileid.ErrOtherView) || !strings.Contains(err.Error(), "GetPackageFullName failed") {
				t.Errorf("%s: SameView %v, want ErrOtherView naming the failed call", transport, err)
			}
		}
	}
}
