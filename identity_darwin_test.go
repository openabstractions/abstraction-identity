//go:build darwin

package identity

// The macOS-specific half. The shared scaffolding and the tests that apply to
// both Unix platforms are in unix_test.go.
//
// These have now been executed on macOS 15.7.4, arm64 (Apple Silicon), against
// a real XNU kernel and a real Security framework. The XNU claim in
// TestSocketOwnerDriftIsRefused was watched, and it is true: LOCAL_PEERPID and
// LOCAL_PEERTOKEN follow the peer socket's last_pid. The mitigation this
// package built on top of it does not hold, which is why nothing here reaches
// ProofBound - see bind_attack_darwin_test.go, which runs the attack that
// breaks it and the binding that catches it.

import (
	"net"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

// TestExitedPeerLeavesOnlyThePrincipal. On Linux the pid survives the peer,
// because the kernel wrote it onto the socket at connect. On macOS it does not:
// the pid is resolved from the peer socket's current owner, and once the peer is
// gone there is nothing to resolve. What survives is LOCAL_PEERCRED, which the
// accepting socket keeps its own copy of.
//
// This is the shape of the platform difference, asserted rather than described.
func TestExitedPeerLeavesOnlyThePrincipal(t *testing.T) {
	l, path := listenUnix(t)
	cmd := startChildClient(t, path, "bye", false)
	c, at, _ := acceptAndRead(t, l)
	if err := cmd.Wait(); err != nil {
		t.Fatalf("child: %v", err)
	}
	// Give the kernel a moment to tear the peer's socket down.
	time.Sleep(50 * time.Millisecond)

	p := identify(t, c, at)
	if _, err := p.User.AtLeast(ProofKernel); err != nil {
		t.Errorf("user: the connect-time credentials must survive the peer: %v", err)
	}
	if p.Process.Known() {
		proc, _ := p.Process.Get()
		t.Logf("process still resolvable after the peer exited: %v", proc)
	}
	if p.Path.Known() {
		v, _ := p.Path.Get()
		t.Errorf("path = %q for a peer that has exited", v)
	}
	if p.Code.Known() {
		t.Error("a code identity was reported for a peer that no longer exists")
	}
}

// TestSocketOwnerDriftIsRefused is the important one on this platform.
//
// LOCAL_PEERPID and LOCAL_PEERTOKEN are not connect-time records: XNU answers
// them from the peer socket's last_pid, which moves to whichever process most
// recently performed a socket operation on that fd. So a caller can connect and
// then hand the connected socket to another program as its stdout; the first
// write from that program moves the identity this package would otherwise
// report.
//
// The defence is Options.ConnectedAt: the impersonating program was spawned
// after the connection existed, so its start time excludes it. This test does
// the attack and requires that the result is a refusal - never the other
// program's identity.
func TestSocketOwnerDriftIsRefused(t *testing.T) {
	l, path := listenUnix(t)

	client, err := net.Dial("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	if _, err := client.Write([]byte("hello")); err != nil {
		t.Fatal(err)
	}
	server, at, _ := acceptAndRead(t, l)

	// Hand the connected socket to a different program as its stdout, and
	// let it write. From here on XNU's last_pid names that program.
	//
	// It must still be RUNNING when the identity is resolved. The original
	// form of this test used /bin/echo and waited for it, which left
	// last_pid naming a dead process: LOCAL_PEERTOKEN then fails with
	// EINVAL and the test passed without ever exercising the mitigation.
	f, err := client.(*net.UnixConn).File()
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	pr, pw, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer pw.Close()
	impostor := exec.Command("/bin/cat")
	impostor.Stdin = pr
	impostor.Stdout = f
	if err := impostor.Start(); err != nil {
		t.Fatalf("/bin/cat: %v", err)
	}
	pr.Close()
	defer func() { impostor.Process.Kill(); impostor.Wait() }()

	// Make it perform a socket write, and prove it did by reading the bytes.
	if _, err := pw.Write([]byte("i am cat\n")); err != nil {
		t.Fatal(err)
	}
	server.SetReadDeadline(time.Now().Add(10 * time.Second))
	if _, err := server.Read(make([]byte, 64)); err != nil {
		t.Fatalf("read from the impostor: %v", err)
	}

	p := identify(t, server, at)

	// Whatever else happens, the answer must not be the spawned program.
	if v, ok := p.Path.Get(); ok > ProofNone && strings.Contains(v, "/cat") {
		t.Fatalf("path = %q: the identity followed the socket to a program the caller spawned", v)
	}
	if p.Code.Known() {
		code, _ := p.Code.Get()
		if code.Trusted && strings.Contains(strings.ToLower(code.Subject), "apple") {
			t.Fatalf("code = %v: a caller borrowed Apple's signature by handing the socket to a platform binary", code)
		}
	}
	// The start-time check does its job here: path, package and code are all
	// withdrawn. What it does NOT do is stop the impostor's pid being
	// reported at ProofPID with Recycled set. That is below any level a
	// policy may act on, so it is allowed - but it means a service that logs
	// p.Process logs the wrong program, and "Recycled" is the wrong word for
	// it: the pid was not reused, the socket changed hands.
	if proc, ok := p.Process.Get(); ok > ProofNone && proc.PID == impostor.Process.Pid {
		if ok >= ProofBound {
			t.Fatalf("process = %v at proof %v: the identity followed the socket", proc, ok)
		}
		t.Logf("the impostor's pid is reported at proof %v (Recycled=%v): a diagnostic, below anything a policy may use", ok, proc.Recycled)
	}
	if _, err := p.Path.AtLeast(ProofBound); err == nil {
		t.Error("a path was reported at ProofBound for a socket handed to another program")
	}
	if p.Code.Known() {
		t.Error("a code identity was reported for a socket handed to another program")
	}
}

// TestAuditTokenMustAgreeWithTheConnectTimeCredentials asserts the cross-check
// that makes the token worth anything on this transport: the process the socket
// currently points at must be running as the user who connected.
func TestAuditTokenMustAgreeWithTheConnectTimeCredentials(t *testing.T) {
	l, path := listenUnix(t)
	startChildClient(t, path, "x", true)
	c, at, _ := acceptAndRead(t, l)

	f, err := c.File()
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	fd := int(f.Fd())

	tok, err := peerAuditToken(fd)
	if err != nil {
		t.Fatalf("LOCAL_PEERTOKEN: %v", err)
	}
	if int(tok.euid()) != os.Getuid() {
		t.Errorf("audit token euid = %d, want %d", tok.euid(), os.Getuid())
	}
	if tok.pidversion() == 0 {
		t.Log("pidversion is 0; the kernel keeps one per process and it is what makes a pid+version pair name an instance")
	}

	p := identify(t, c, at)
	proc, err := p.Process.AtLeast(ProofPID)
	if err != nil {
		t.Fatalf("process: %v", err)
	}
	if proc.Generation != tok.pidversion() {
		t.Errorf("Generation = %d, want the token's pidversion %d", proc.Generation, tok.pidversion())
	}
}

// TestDarwinRefusesToPromiseASignature. macOS can verify the signature of
// running code, which Windows cannot - but over a unix socket the token that
// selects which code gets verified is a lookup, not a stamp. So neither
// ProofSigned nor even ProofBound is achievable on this transport, and a policy
// demanding either must fail at startup with a reason that names XPC.
//
// The ProofBound half was measured before it was believed: a helper forked
// before the connection and exec'ing /bin/cat after it satisfies every
// start-time check this package has, and is handed Apple's signature. See
// bind_attack_darwin_test.go, which runs that attack, and probe-evidence.txt
// experiments 2 and 7.
func TestDarwinRefusesToPromiseASignature(t *testing.T) {
	err := CanEver(Need{Code: ProofSigned})
	if err == nil {
		t.Fatal("CanEver accepted a policy requiring ProofSigned over a unix socket")
	}
	if !strings.Contains(err.Error(), "XPC") {
		t.Errorf("CanEver said %q; it must name the transport that would deliver it", err)
	}
	if err := CanEver(Need{Process: ProofBound}); err == nil {
		t.Error("CanEver accepted a policy requiring ProofBound over a transport whose answers follow the last writer")
	}
	if err := CanEver(Need{User: ProofKernel, Process: ProofPID, Path: ProofPID}); err != nil {
		t.Errorf("CanEver refused the policy macOS can actually enforce over a socket: %v", err)
	}
}

// TestSigningInformationIsNeverReadWithoutValidating guards the trap named in
// CONTRACT.md: SecCodeCopySigningInformation reports what the code claims. A
// build that read a team identifier out of a failed verification would hand a
// service an attacker's chosen string.
func TestSigningInformationIsNeverReadWithoutValidating(t *testing.T) {
	l, path := listenUnix(t)
	startChildClient(t, path, "x", true)
	c, at, _ := acceptAndRead(t, l)
	p := identify(t, c, at)

	code, proof := p.Code.Get()
	if proof == ProofNone {
		t.Skipf("no code identity available in this build: %s", p.Code.Why())
	}
	if !code.Trusted && (code.Subject != "" || code.TeamID != "") {
		t.Errorf("a failed verification carried an identity out with it: %v", code)
	}
	if code.Trusted && code.Status != "valid" {
		t.Errorf("a trusted verdict with status %q", code.Status)
	}
	t.Logf("code: %v", code)
}
