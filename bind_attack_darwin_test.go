//go:build darwin

package identity

import (
	"errors"
	"os"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func execPathOf(pid int) (string, error) { return processExecPath(pid) }

// TestAPreForkedHelperStealsTheSignatureAndTheBindingRefusesIt is experiment 2
// of probe-evidence.txt, turned into a test that
// runs on every build, plus the half that was missing: what a binding taken at
// accept does about it.
//
// A helper is started holding an unconnected socket, so it exists - with its
// start time stamped - before the connection does. The socket is then
// connected, the service accepts and binds, and only then does the helper
// become /bin/cat and write one byte. LOCAL_PEERTOKEN follows that byte, the
// Security framework validates Apple's signature on /bin/cat perfectly
// honestly, and a service that trusted the lookup would have been shown a
// program that never opened the connection.
//
// It replaces TestSocketOwnerDriftToAPreExistingProcessIsRefused, which
// asserted the same attack was refused, failed by design on every run, and left
// the suite permanently red. This one asserts what is true instead - and adds
// the half that was missing, which is what a binding taken at accept does.
//
// The connector here is the test process, which is normally the wrong shape
// for a test in this package. It is safe in this one case because the
// assertion is that the answer moved AWAY from the connector: /bin/cat is not
// this test binary under any circumstances, so an answer that happens to
// describe the caller fails rather than passes.
func TestAPreForkedHelperStealsTheSignatureAndTheBindingRefusesIt(t *testing.T) {
	if _, err := os.Stat("/bin/cat"); err != nil {
		t.Skipf("no /bin/cat to impersonate: %v", err)
	}
	l, path := listenUnix(t)

	fd, err := unix.Socket(unix.AF_UNIX, unix.SOCK_STREAM, 0)
	if err != nil {
		t.Fatal(err)
	}
	sock := os.NewFile(uintptr(fd), "peer")
	defer sock.Close()

	// The helper inherits the socket as its stdout. It is a fork of this
	// process that happened before connect(2), which is exactly the shape
	// Options.ConnectedAt cannot exclude: exec keeps the fork-time start.
	a := startAttacker(t, preForkedEnv, "1", sock)
	time.Sleep(50 * time.Millisecond)

	if err := unix.Connect(fd, &unix.SockaddrUnix{Name: path}); err != nil {
		t.Fatalf("connect: %v", err)
	}
	conn, at := acceptOnly(t, l)
	b := bindOrFail(t, conn, at)

	captured, _ := b.Captured().Process.Get()
	if captured.PID != os.Getpid() {
		t.Fatalf("the binding captured pid %d; this process connected and is pid %d", captured.PID, os.Getpid())
	}

	a.release(t)
	waitForExe(t, a.pid(), "/bin/cat")
	a.speak(t, "i am cat\n")

	buf := make([]byte, 64)
	conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	if _, err := conn.Read(buf); err != nil {
		t.Fatalf("the impersonator never wrote: %v", err)
	}

	t.Run("the lookup hands over Apple's signature", func(t *testing.T) {
		p, err := OfConn(conn, &Options{ConnectedAt: at})
		if err != nil {
			t.Fatalf("OfConn: %v", err)
		}
		got, proof := p.Path.Get()
		t.Logf("OfHandle says path=%q at %s", got, proof)
		if got != "/bin/cat" {
			t.Fatalf("the attack did not land: the lookup says %q", got)
		}
		if code, cp := p.Code.Get(); !code.Trusted {
			t.Logf("code came back untrusted (%s at %s); the cgo half may be absent", code.Status, cp)
		} else {
			t.Logf("and vouches for it: %v", code)
		}
	})

	t.Run("anchor apple passes for a caller that is not Apple's", func(t *testing.T) {
		p, err := OfConn(conn, &Options{ConnectedAt: at, CodeRequirement: "anchor apple"})
		if err != nil {
			t.Fatalf("OfConn: %v", err)
		}
		code, _ := p.Code.Get()
		if !code.Trusted {
			t.Skipf("anchor apple was not satisfied (%s); without cgo there is no signature to steal", code.Status)
		}
		t.Log("Peer.Check against \"anchor apple\" PASSED for a peer that never connected")
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
	})
}

// TestDarwinCeilingRefusesToClaimABinding is the Ceiling half. macOS over
// AF_UNIX has no primitive that names the process which opened the connection,
// and saying so is the whole job: a service reading this must be pushed to XPC
// rather than allowed to believe a socket is enough.
func TestDarwinCeilingRefusesToClaimABinding(t *testing.T) {
	l := Ceiling()
	if l.Transport != "unix" {
		t.Fatalf("transport is %q", l.Transport)
	}
	if l.Bindable {
		t.Fatal("macOS over a unix socket cannot bind a peer; Ceiling claims it can")
	}
	if l.Stronger == "" {
		t.Fatal("Ceiling did not name the transport that would do better")
	}
	for _, a := range []struct {
		name string
		got  Proof
	}{
		{"process", l.Best.Process},
		{"path", l.Best.Path},
		{"package", l.Best.Package},
		{"code", l.Best.Code},
	} {
		if a.got > ProofPID {
			t.Errorf("Ceiling advertises %s at %s over a transport whose answers follow the last writer", a.name, a.got)
		}
	}
	if err := CanEver(Need{Code: ProofBound}); err == nil {
		t.Fatal("CanEver let a service start on a signature policy this transport cannot enforce")
	}
	t.Logf("%v", l)
	t.Logf("stronger: %s", l.Stronger)
}

// TestBindingSurvivesAnHonestDarwinPeer keeps the refusal above from being
// satisfied by a binding that refuses everything.
func TestBindingSurvivesAnHonestDarwinPeer(t *testing.T) {
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
}
