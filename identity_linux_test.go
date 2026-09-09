//go:build linux

package identity

// The Linux-specific half. The shared scaffolding and the tests that apply to
// both Unix platforms are in unix_test.go.

import (
	"strings"
	"testing"
)

// TestExitedPeerIsNotResolvedFromItsPid: once the peer is gone its pid is a
// number that belongs to nobody, and may already belong to someone else. The
// pid is still reported - the kernel stamped it on the connection - but nothing
// is read out of it.
func TestExitedPeerIsNotResolvedFromItsPid(t *testing.T) {
	l, path := listenUnix(t)
	cmd := startChildClient(t, path, "bye", false)
	c, at, _ := acceptAndRead(t, l)
	if err := cmd.Wait(); err != nil {
		t.Fatalf("child: %v", err)
	}

	p := identify(t, c, at)
	proc, err := p.Process.AtLeast(ProofKernel)
	if err != nil {
		t.Fatalf("process: the pid is a fact about the connection and must survive the peer: %v", err)
	}
	if proc.PID != cmd.Process.Pid {
		t.Errorf("pid = %d, want %d", proc.PID, cmd.Process.Pid)
	}

	if pidfdOK, _ := pidfdSupport(); pidfdOK {
		if p.Path.Known() {
			v, _ := p.Path.Get()
			t.Errorf("path = %q for a peer that has exited; the pid may already name a different process", v)
		}
		if !strings.Contains(p.Path.Why(), "exited") {
			t.Errorf("path why = %q, want it to say the peer exited", p.Path.Why())
		}
	}
}

// TestTheProofSaysWhetherThePidWasPinned is the honesty check on this
// platform's one real fork in the road. With SO_PEERPIDFD everything read from
// /proc is bound to the process that connected; without it the same read is a
// question about a number. The difference must be in the Proof, not buried in a
// comment.
func TestTheProofSaysWhetherThePidWasPinned(t *testing.T) {
	pidfdOK, why := pidfdSupport()
	l, path := listenUnix(t)
	startChildClient(t, path, "x", true)
	c, at, _ := acceptAndRead(t, l)
	p := identify(t, c, at)

	got := p.Path.Proof()
	switch {
	case pidfdOK:
		if got != ProofBound {
			t.Errorf("path proof = %s with SO_PEERPIDFD available; want bound", got)
		}
		if Ceiling().Best.Path != ProofBound {
			t.Error("the ceiling does not admit what the platform can actually do")
		}
	default:
		if got != ProofPID {
			t.Errorf("path proof = %s without SO_PEERPIDFD; want pid, and never better", got)
		}
		if !strings.Contains(p.Path.Why(), "SO_PEERPIDFD") {
			t.Errorf("path why = %q, want it to name the missing kernel feature (%s)", p.Path.Why(), why)
		}
	}
}

// TestWithoutPidfdNothingFromProcIsBound simulates a pre-6.5 kernel by asking
// for a socket option that does not exist, which is what an old kernel does to
// SO_PEERPIDFD. Everything read from /proc must then drop to ProofPID and say
// why - a service that required ProofBound must be refused here rather than
// served an answer that only looks the same.
func TestWithoutPidfdNothingFromProcIsBound(t *testing.T) {
	const notAnOption = 0xfff
	saved := soPeerPIDFD
	soPeerPIDFD = notAnOption
	t.Cleanup(func() { soPeerPIDFD = saved })

	l, path := listenUnix(t)
	startChildClient(t, path, "x", true)
	c, at, _ := acceptAndRead(t, l)
	p := identify(t, c, at)

	if got := p.Path.Proof(); got != ProofPID {
		t.Errorf("path proof = %s without a pidfd; want pid", got)
	}
	if !strings.Contains(p.Path.Why(), "SO_PEERPIDFD") {
		t.Errorf("path why = %q, want it to name the missing kernel feature", p.Path.Why())
	}
	if _, err := p.Path.AtLeast(ProofBound); err == nil {
		t.Error("AtLeast(bound) handed out a path that was read from a bare pid")
	}
	// The pid and the user are unaffected: the kernel stamped those at
	// connect and no lookup was involved.
	if _, err := p.User.AtLeast(ProofKernel); err != nil {
		t.Errorf("user: %v", err)
	}
	if _, err := p.Process.AtLeast(ProofKernel); err != nil {
		t.Errorf("process: %v", err)
	}
}

// TestLSMLabelIsReportedOrAbsent: SO_PEERSEC is the closest Linux comes to
// naming a program rather than a file, and the strings that mean "nothing is
// confining this process" must not be reported as if they were profiles.
func TestLSMLabelIsReportedOrAbsent(t *testing.T) {
	for _, s := range []string{"", "kernel", "unconfined", "unlabeled"} {
		if meaningfulLSMLabel(s) {
			t.Errorf("%q was treated as an LSM profile; it is the absence of one", s)
		}
	}
	if !meaningfulLSMLabel("/usr/bin/evince (enforce)") {
		t.Error("an AppArmor profile was discarded")
	}

	l, path := listenUnix(t)
	startChildClient(t, path, "x", true)
	c, at, _ := acceptAndRead(t, l)
	p := identify(t, c, at)
	u, _ := p.User.Get()
	if u.SecurityContext != "" {
		t.Logf("LSM label of the peer: %q", u.SecurityContext)
		if !meaningfulLSMLabel(u.SecurityContext) {
			t.Errorf("reported a meaningless LSM label %q", u.SecurityContext)
		}
	} else {
		t.Logf("no LSM labels processes on this system; User.SecurityContext is empty, as it should be")
	}
}

// TestLinuxRefusesToPromiseASignature: there is no per-connection code
// signature verification for ELF binaries, so a policy that needs one must fail
// at startup rather than once per connection.
func TestLinuxRefusesToPromiseASignature(t *testing.T) {
	if err := CanEver(Need{Code: ProofSigned}); err == nil {
		t.Error("CanEver accepted a policy requiring a verified signature on Linux")
	}
	if err := CanEver(Need{Code: ProofPID}); err == nil {
		t.Error("CanEver accepted a policy requiring any code identity at all on Linux")
	}
	if err := CanEver(Need{Package: ProofSigned}); err == nil {
		t.Error("CanEver accepted a policy requiring a signed package identity on Linux")
	}
	if err := CanEver(Need{User: ProofKernel, Process: ProofKernel}); err != nil {
		t.Errorf("CanEver refused the policy Linux can actually enforce: %v", err)
	}
}

// TestLinuxPlatformIsNamed guards the log line: an answer that does not say
// which operating system produced it is unreadable a week later.
func TestLinuxPlatformIsNamed(t *testing.T) {
	l, path := listenUnix(t)
	startChildClient(t, path, "x", true)
	c, at, _ := acceptAndRead(t, l)
	p := identify(t, c, at)
	if p.Platform != "linux" {
		t.Errorf("platform = %q", p.Platform)
	}
	if p.Code.Known() {
		t.Error("Linux reported a code identity; it has none to report")
	}
	if !strings.Contains(p.Code.Why(), "signature") {
		t.Errorf("code why = %q, want it to explain the absence", p.Code.Why())
	}
}
