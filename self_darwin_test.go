//go:build darwin && cgo

package identity

import (
	"os"
	"os/exec"
	"testing"
)

func TestSelfAuditSessionMatchesStartedChild(t *testing.T) {
	u, err := Self()
	if err != nil {
		t.Fatal(err)
	}
	if u.UID != os.Geteuid() || u.GID != os.Getegid() || u.AuditSessionID == 0 {
		t.Fatalf("incomplete effective principal: %+v", u)
	}
	cmd := exec.Command("/bin/sleep", "10")
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = cmd.Process.Kill(); _ = cmd.Wait() }()
	b, err := BindStartedProcess(cmd.Process)
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	p, err := b.Peer()
	if err != nil {
		t.Fatal(err)
	}
	child, err := p.User.AtLeast(ProofKernel)
	if err != nil {
		t.Fatal(err)
	}
	if child.UID != u.UID || child.GID != u.GID || child.AuditSessionID != u.AuditSessionID {
		t.Fatalf("child principal %+v differs from self %+v", child, u)
	}
}

func TestSelfAuditSessionDoesNotChangeSameAccountView(t *testing.T) {
	me, err := Self()
	if err != nil {
		t.Fatal(err)
	}
	// Ordinary socket/XPC User evidence does not acquire the runtime ASID.
	ordinary := me
	ordinary.AuditSessionID = 0
	mine, err := me.Account()
	if err != nil {
		t.Fatal(err)
	}
	theirs, err := ordinary.Account()
	if err != nil || mine != theirs {
		t.Fatalf("audit session changed account: %q %q %v", mine, theirs, err)
	}
	p := &Peer{Platform: "darwin", Transport: string(TransportUnix), User: attr("user", ordinary, ProofKernel, "ordinary peer account")}
	if err := p.SameView(); err != nil {
		t.Fatalf("same-account ordinary peer lost namespace view: %v", err)
	}
}
