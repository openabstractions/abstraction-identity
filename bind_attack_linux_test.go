//go:build linux

package identity

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func execPathOf(pid int) (string, error) {
	p, _, err := processExe(pid)
	return p, err
}

// TestExecAfterConnectFoolsTheLookupAndTheBindingRefusesIt is the whole point
// of bind.go, in one file, on one connection.
//
// The peer connects honestly as this test binary and then replaces itself with
// /bin/cat. Its pid does not change, its start time does not change, and
// SO_PEERCRED still names it correctly - so every guard the pid-based path has
// is satisfied, and it reports /bin/cat at ProofBound. A service that granted
// on "the caller is /bin/cat" would have granted to a program that was never
// /bin/cat.
//
// The binding captured the image path at accept and refuses. Both halves are
// asserted here so that the difference cannot regress quietly: if a future
// kernel closes the hole, the first half fails and this comment is wrong.
func TestExecAfterConnectFoolsTheLookupAndTheBindingRefusesIt(t *testing.T) {
	if ok, why := pidfdSupport(); !ok {
		t.Skipf("this kernel cannot bind a peer at all: %s", why)
	}
	// /proc/<pid>/exe is the file the kernel mapped, not the name used to
	// reach it: on a uutils-coreutils system /bin/cat is a symlink and the
	// link resolves elsewhere. That is itself the point of the CONTRACT's
	// warning that a path is a name, so the test compares the same thing the
	// kernel reports.
	victim, verr := filepath.EvalSymlinks("/bin/cat")
	if verr != nil {
		t.Skipf("no /bin/cat to impersonate: %v", verr)
	}

	l, path := listenUnix(t)
	a := startAttacker(t, execDriftEnv, path, os.Stderr)
	conn, at := acceptOnly(t, l)

	b := bindOrFail(t, conn, at)

	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	captured, _ := b.Captured().Path.Get()
	if !sameFile(captured, self) {
		t.Fatalf("the binding captured %q; the peer was %q", captured, self)
	}

	a.release(t)
	waitForExe(t, a.pid(), victim)

	t.Run("the lookup is fooled", func(t *testing.T) {
		p, err := OfConn(conn, &Options{ConnectedAt: at})
		if err != nil {
			t.Fatalf("OfConn: %v", err)
		}
		got, proof := p.Path.Get()
		t.Logf("OfHandle says path=%q at %s", got, proof)
		if got != victim {
			t.Fatalf("the attack did not land: the lookup says %q, not %q", got, victim)
		}
		if err := p.Check(Need{Path: ProofBound}); err != nil {
			t.Fatalf("the lookup was expected to report the wrong program at ProofBound; it reported %s: %v", proof, err)
		}
	})

	t.Run("the binding refuses", func(t *testing.T) {
		p, err := b.Peer()
		if err == nil {
			t.Fatalf("the binding answered %v; it should have refused", p)
		}
		if !errors.Is(err, ErrPeerMoved) {
			t.Fatalf("the binding refused with %v; expected ErrPeerMoved", err)
		}
		t.Logf("Bind refuses: %v", err)
		if err := b.Check(Need{Path: ProofBound}); !errors.Is(err, ErrPeerMoved) {
			t.Fatalf("Binding.Check let the policy through: %v", err)
		}
	})
}

// TestBindingSurvivesAnHonestPeer keeps the refusal above from being satisfied
// by a binding that refuses everything.
func TestBindingSurvivesAnHonestPeer(t *testing.T) {
	if ok, why := pidfdSupport(); !ok {
		t.Skipf("this kernel cannot bind a peer at all: %s", why)
	}
	l, path := listenUnix(t)
	startChildClient(t, path, "hello", true)
	conn, at := acceptOnly(t, l)

	b := bindOrFail(t, conn, at)
	for i := 0; i < 3; i++ {
		if _, err := b.Peer(); err != nil {
			t.Fatalf("an honest peer was refused on check %d: %v", i, err)
		}
		time.Sleep(10 * time.Millisecond)
	}
	if err := b.Check(Need{User: ProofKernel, Process: ProofKernel, Path: ProofBound}); err != nil {
		t.Fatalf("an honest peer failed the policy this platform advertises: %v", err)
	}
}

// TestTheBindingOutlivesThePeerItNamed is the reuse half, and the reason the
// pidfd is held rather than fetched again.
//
// A pid lookup after the peer exits reaches nothing, or a successor. The pidfd
// keeps the number reserved, so the captured answer stays available and stays
// true - and liveness is reported as the separate question it is, rather than
// as a reason to refuse an identity that has not been contradicted.
func TestTheBindingOutlivesThePeerItNamed(t *testing.T) {
	if ok, why := pidfdSupport(); !ok {
		t.Skipf("this kernel cannot bind a peer at all: %s", why)
	}
	l, path := listenUnix(t)
	cmd := startChildClient(t, path, "hello", true)
	conn, at := acceptOnly(t, l)
	b := bindOrFail(t, conn, at)

	want, _ := b.Captured().Path.Get()
	cmd.Process.Kill()
	cmd.Wait()

	deadline := time.Now().Add(10 * time.Second)
	for {
		live, err := b.Alive()
		if err != nil {
			t.Fatalf("Alive: %v", err)
		}
		if !live {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the binding never noticed the peer had gone")
		}
		time.Sleep(5 * time.Millisecond)
	}

	p, err := b.Peer()
	if err != nil {
		t.Fatalf("an exited peer invalidated the binding: %v", err)
	}
	got, proof := p.Path.Get()
	if got != want {
		t.Fatalf("the binding now says %q; it captured %q", got, want)
	}
	if proof < ProofBound {
		t.Fatalf("the captured path came back at %s", proof)
	}
	t.Logf("after the peer exited the binding still says path=%q at %s", got, proof)
}

// TestLinuxCeilingNamesItsBinding is the Ceiling half of the contract: a
// machine that cannot bind must say so rather than degrade quietly. On a
// 4.4 kernel this test passes by asserting the refusal.
func TestLinuxCeilingNamesItsBinding(t *testing.T) {
	l := Ceiling()
	if l.Transport != "unix" {
		t.Fatalf("transport is %q", l.Transport)
	}
	if l.Binding == "" {
		t.Fatal("Ceiling did not say what binds a peer here, or what is missing")
	}
	ok, _ := pidfdSupport()
	if l.Bindable != ok {
		t.Fatalf("Ceiling says Bindable=%v; SO_PEERPIDFD probe says %v", l.Bindable, ok)
	}
	t.Logf("%v", l)
	t.Logf("binding: %s", l.Binding)

	if !ok {
		l2, path := listenUnix(t)
		startChildClient(t, path, "hello", true)
		conn, at := acceptOnly(t, l2)
		if _, err := BindConn(conn, &Options{ConnectedAt: at}); !errors.Is(err, ErrNoBinding) {
			t.Fatalf("a kernel with no SO_PEERPIDFD bound a peer anyway: %v", err)
		}
	}
}
