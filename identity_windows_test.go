//go:build windows

package identity

import (
	"errors"
	"os"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/sys/windows"
)

// TestPeerIsTheProcessThatConnected is the test the package exists to pass: a
// real server and a real client, in separate processes, over a real named
// pipe, and the identity the server derives has to be the client's - not the
// server's own, and not anything the client said.
func TestPeerIsTheProcessThatConnected(t *testing.T) {
	name := pipeName(t)
	server := listen(t, name)

	// The payload is a lie. It is here to be ignored.
	child := startChildClient(t, name, `{"owner":"LogViewer","user":"S-1-5-18"}`)

	at := accept(t, server)
	payload := readFrom(t, server)

	peer, err := OfHandle(Handle(server), &Options{ConnectedAt: at})
	if err != nil {
		t.Fatalf("OfHandle: %v", err)
	}
	t.Logf("peer: %v", peer)
	for _, n := range peer.Notes {
		t.Logf("note: %s", n)
	}

	// The process, at kernel strength, and it is the child.
	proc, err := peer.Process.AtLeast(ProofKernel)
	if err != nil {
		t.Fatalf("process not proven at kernel strength: %v", err)
	}
	if proc.PID != child.Process.Pid {
		t.Errorf("peer pid = %d, want the child's %d", proc.PID, child.Process.Pid)
	}
	if proc.PID == os.Getpid() {
		t.Errorf("peer pid is the server's own pid %d; the answer describes the wrong process", proc.PID)
	}
	if proc.Recycled {
		t.Errorf("process reported as recycled, but the child is still running")
	}
	if proc.StartTime.IsZero() {
		t.Errorf("no start time; the pid-reuse check cannot have run")
	}
	if proc.StartTime.After(at) {
		t.Errorf("start time %v is after the connection %v, which should have been refused", proc.StartTime, at)
	}

	// The path, bound to that process, and it is this test binary.
	path, err := peer.Path.AtLeast(ProofBound)
	if err != nil {
		t.Fatalf("path not bound: %v", err)
	}
	exe, _ := os.Executable()
	if !strings.EqualFold(path, exe) {
		t.Errorf("peer path = %q, want %q", path, exe)
	}

	// The user, from the kernel, and it is whoever is running the test.
	user, err := peer.User.AtLeast(ProofKernel)
	if err != nil {
		t.Fatalf("user not proven at kernel strength: %v", err)
	}
	if want := currentUserSID(t); user.SID != want {
		t.Errorf("peer SID = %q, want %q", user.SID, want)
	}
	// The integrity level decides whether this identity is a boundary or
	// only a label; a peer with no level at all would be neither.
	if user.Integrity == "" {
		t.Errorf("no integrity level for the peer; CONTRACT.md's boundary argument rests on it")
	}
	t.Logf("peer user: %v", user)

	// The payload arrived and was not consulted.
	if len(payload) == 0 {
		t.Fatal("no payload; the claimed-identity assertions below would be vacuous")
	}
	assertNothingClaimed(t, peer, "LogViewer", "S-1-5-18")
}

// TestClaimedIdentityIsIgnored connects twice with two different lies and
// requires the derived identity to be the same both times. If any claim in the
// payload could reach the answer, the two would differ.
func TestClaimedIdentityIsIgnored(t *testing.T) {
	resolve := func(payload string) *Peer {
		t.Helper()
		name := pipeName(t) + "-" + strings.NewReplacer(`"`, "", "{", "", "}", "", ":", "", ",", "").Replace(payload)
		server := listen(t, name)
		startChildClient(t, name, payload)
		at := accept(t, server)
		readFrom(t, server)
		peer, err := OfHandle(Handle(server), &Options{ConnectedAt: at})
		if err != nil {
			t.Fatalf("OfHandle: %v", err)
		}
		return peer
	}

	a := resolve(`{"owner":"LogViewer"}`)
	b := resolve(`{"owner":"Malware","user":"S-1-5-18","path":"C:\\Windows\\System32\\lsass.exe"}`)

	assertNothingClaimed(t, a, "LogViewer")
	assertNothingClaimed(t, b, "Malware", "S-1-5-18", "lsass.exe")

	pa, _ := a.Path.Get()
	pb, _ := b.Path.Get()
	if !strings.EqualFold(pa, pb) {
		t.Errorf("two clients from the same program resolved to different paths: %q and %q", pa, pb)
	}
	ua, _ := a.User.Get()
	ub, _ := b.User.Get()
	if ua.SID != ub.SID {
		t.Errorf("two clients from the same user resolved to different SIDs: %q and %q", ua.SID, ub.SID)
	}
}

// assertNothingClaimed checks that no string the peer sent appears anywhere in
// the resolved identity, and that nothing was recorded at ProofClaimed - which
// this package must never produce.
func assertNothingClaimed(t *testing.T, p *Peer, claims ...string) {
	t.Helper()
	rendered := p.String()
	for _, c := range claims {
		if strings.Contains(strings.ToLower(rendered), strings.ToLower(c)) {
			t.Errorf("the peer's claim %q reached the derived identity: %s", c, rendered)
		}
	}
	for name, got := range map[string]Proof{
		"user": p.User.Proof(), "process": p.Process.Proof(), "path": p.Path.Proof(),
		"package": p.Package.Proof(), "code": p.Code.Proof(),
	} {
		if got == ProofClaimed {
			t.Errorf("%s was recorded at ProofClaimed; this package must never produce it", name)
		}
	}
}

// TestClientEndIsRefused: only the server end of a pipe can identify its peer.
// Asked from the other end, the honest answer is a refusal, not the service's
// own identity dressed up as the caller's.
func TestClientEndIsRefused(t *testing.T) {
	name := pipeName(t)
	server := listen(t, name)
	client := dial(t, name)
	accept(t, server)

	if _, err := OfHandle(Handle(client), nil); !errors.Is(err, ErrNotServerEnd) {
		t.Errorf("OfHandle(client end) = %v, want ErrNotServerEnd", err)
	}
	if _, err := OfHandle(Handle(windows.InvalidHandle), nil); !errors.Is(err, ErrUnsupportedConn) {
		t.Errorf("OfHandle(not a pipe) = %v, want ErrUnsupportedConn", err)
	}
}

// TestRecycledPIDIsRefused forces the pid-reuse check to fire by claiming the
// connection is older than the peer process. A real recycled pid is not
// reproducible on demand; this drives the same branch by the same comparison,
// and asserts the consequence that matters - nothing derived from the pid is
// reported, and the reason is on the record.
func TestRecycledPIDIsRefused(t *testing.T) {
	name := pipeName(t)
	server := listen(t, name)
	startChildClient(t, name, "x")
	accept(t, server)
	readFrom(t, server)

	// A connection that supposedly predates the peer's own creation: any
	// process now holding that pid must be a different, later one.
	long_ago := time.Now().Add(-24 * time.Hour)
	peer, err := OfHandle(Handle(server), &Options{ConnectedAt: long_ago})
	if err != nil {
		t.Fatalf("OfHandle: %v", err)
	}
	proc, _ := peer.Process.Get()
	if !proc.Recycled {
		t.Fatalf("pid %d not flagged as recycled; the check did not run", proc.PID)
	}
	for _, a := range []struct {
		name  string
		proof Proof
	}{{"path", peer.Path.Proof()}, {"package", peer.Package.Proof()}, {"code", peer.Code.Proof()}} {
		if a.proof != ProofNone {
			t.Errorf("%s was reported at %s despite a recycled pid; nothing may be read out of a reused pid", a.name, a.proof)
		}
	}
	if _, err := peer.Path.AtLeast(ProofPID); !errors.Is(err, ErrNotProven) {
		t.Errorf("Path.AtLeast(ProofPID) = %v, want ErrNotProven", err)
	}
	if len(peer.Notes) == 0 {
		t.Error("a refused identity left no note explaining why")
	}
}

// TestImpersonationIsAlwaysReverted drives withPeerToken down its success,
// error and panic paths, then goes looking for a thread that was left wearing
// the client's token.
//
// The probe is one-sided: a clean thread always reports no token, so this test
// cannot fail spuriously. It can miss a leak, because it only samples threads
// the runtime happens to hand out. That is the strongest check available from
// inside the process, and it is worth having because the failure it looks for
// is a privilege escalation rather than a wrong answer.
func TestImpersonationIsAlwaysReverted(t *testing.T) {
	name := pipeName(t)
	server := listen(t, name)
	client := dial(t, name)
	accept(t, server)
	// Windows will not impersonate until the server has read; see
	// TestWindowsWillNotIdentifyUntilTheServerHasRead.
	var n uint32
	if err := windows.WriteFile(client, []byte("hello"), &n, nil); err != nil {
		t.Fatal(err)
	}
	readFrom(t, server)
	pipe := windows.Handle(server)

	t.Run("success", func(t *testing.T) {
		var impersonated bool
		err := withPeerToken(pipe, func(tok windows.Token) error {
			impersonated = tok != 0
			return nil
		})
		if err != nil {
			t.Fatalf("withPeerToken: %v", err)
		}
		if !impersonated {
			t.Fatal("no token was opened; the test proves nothing about reverting")
		}
		assertNoThreadIsImpersonating(t)
	})

	t.Run("error", func(t *testing.T) {
		sentinel := errors.New("boom")
		if err := withPeerToken(pipe, func(windows.Token) error { return sentinel }); !errors.Is(err, sentinel) {
			t.Fatalf("withPeerToken = %v, want the callback's error", err)
		}
		assertNoThreadIsImpersonating(t)
	})

	t.Run("panic", func(t *testing.T) {
		err := withPeerToken(pipe, func(windows.Token) error { panic("callback exploded") })
		if err == nil || !strings.Contains(err.Error(), "callback exploded") {
			t.Fatalf("withPeerToken = %v, want the panic reported as an error", err)
		}
		assertNoThreadIsImpersonating(t)
	})
}

func assertNoThreadIsImpersonating(t *testing.T) {
	t.Helper()
	const probes = 64
	var wg sync.WaitGroup
	leaked := make(chan string, probes)
	for i := 0; i < probes; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			runtime.LockOSThread()
			defer runtime.UnlockOSThread()
			th, err := windows.GetCurrentThread()
			if err != nil {
				return
			}
			var tok windows.Token
			if err := windows.OpenThreadToken(th, windows.TOKEN_QUERY, true, &tok); err != nil {
				return // ERROR_NO_TOKEN: this thread is clean, which is the point
			}
			defer tok.Close()
			sid := "unknown"
			if u, err := tok.GetTokenUser(); err == nil {
				sid = u.User.Sid.String()
			}
			leaked <- sid
		}()
	}
	wg.Wait()
	close(leaked)
	for sid := range leaked {
		t.Fatalf("a thread was left impersonating %s after withPeerToken returned", sid)
	}
}

// TestWindowsRefusesToPromiseASignature is the requirement stated as a test: a
// service whose permission model rests on a verified code signature must be
// able to find out, before it starts serving, that Windows will not give it
// one for an ordinary executable.
func TestWindowsRefusesToPromiseASignature(t *testing.T) {
	if err := CanEver(Need{Code: ProofSigned}); err == nil {
		t.Fatal("CanEver said Windows can prove a signed code identity; it cannot for unpackaged programs")
	} else if !errors.Is(err, ErrNotProven) {
		t.Errorf("CanEver returned %v, want an ErrNotProven", err)
	} else {
		t.Logf("as expected: %v", err)
	}

	// The levels Windows genuinely reaches must be promised, or the ceiling
	// is useless in the other direction.
	if err := CanEver(Need{User: ProofKernel, Process: ProofKernel, Path: ProofBound, Code: ProofBound}); err != nil {
		t.Errorf("CanEver refused a policy Windows can meet: %v", err)
	}
	l := Ceiling()
	if l.Platform != "windows" {
		t.Errorf("Ceiling().Platform = %q", l.Platform)
	}
	if l.Why["code"] == "" {
		t.Error("the ceiling on code carries no explanation")
	}
	t.Logf("%v", l)
}

// TestCodeSignatureOfASignedBinary points the verifier at something Microsoft
// signed, to show that the Authenticode path produces a publisher name and not
// only failures - and to record, in the test output, exactly how strong that
// answer is allowed to be.
func TestCodeSignatureOfASignedBinary(t *testing.T) {
	self, err := windows.GetCurrentProcess()
	if err != nil {
		t.Fatal(err)
	}
	// Not the peer's image: verifyImage's identity re-check compares the
	// file against the process it was given, so use a process whose image
	// really is the file. This test therefore uses the test binary, which
	// is unsigned, plus a direct check of a signed system file.
	code, _, err := verifyImage(self, mustExe(t), nil)
	if err != nil {
		t.Fatalf("verifyImage: %v", err)
	}
	t.Logf("test binary: trusted=%v status=%q subject=%q", code.Trusted, code.Status, code.Subject)

	// Something Windows signed itself, to show the verifier reaching a
	// verdict of "valid" and not only failures.
	const signed = `C:\Windows\System32\kernel32.dll`
	p, err := windows.UTF16PtrFromString(signed)
	if err != nil {
		t.Fatal(err)
	}
	f, err := windows.CreateFile(p, windows.GENERIC_READ,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil, windows.OPEN_EXISTING, windows.FILE_ATTRIBUTE_NORMAL, 0)
	if err != nil {
		t.Skipf("cannot open %s: %v", signed, err)
	}
	defer windows.CloseHandle(f)

	c := verifyTrust(f, p, false)
	t.Logf("%s: trusted=%v status=%q", signed, c.Trusted, c.Status)
	if !c.Trusted {
		t.Errorf("Windows does not trust its own %s: %q", signed, c.Status)
	}
	// Its signature lives in a system catalog, not in the file, so the
	// publisher name is not extractable from the file itself. That is worth
	// asserting: "signed and trusted" and "we can name the publisher" are
	// different questions, and a consent prompt needs the second.
	if subject, _, err := signerName(p); err == nil {
		t.Logf("%s carries an embedded signature by %q", signed, subject)
	} else {
		t.Logf("%s is trusted but has no embedded signature to name a publisher from (%v); "+
			"catalog-signed files are trusted without being attributable from the file alone", signed, err)
	}
}

func mustExe(t *testing.T) string {
	t.Helper()
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	return exe
}

func currentUserSID(t *testing.T) string {
	t.Helper()
	tok := windows.GetCurrentProcessToken()
	u, err := tok.GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	return u.User.Sid.String()
}
