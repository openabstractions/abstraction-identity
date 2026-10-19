//go:build windows

package identity

import (
	"testing"

	"golang.org/x/sys/windows"
)

// TestPipePeerElevationMatchesItsProcessToken is ID-H3 at bind: a real child
// process connected over a real pipe reads elevated exactly when its own
// token classifies as elevated. The child inherits this test's token, so an
// ordinary run reads not elevated and an elevated run reads elevated.
func TestPipePeerElevationMatchesItsProcessToken(t *testing.T) {
	self, err := windows.OpenCurrentProcessToken()
	if err != nil {
		t.Fatal(err)
	}
	u, err := self.GetTokenUser()
	if err != nil {
		self.Close()
		t.Fatal(err)
	}
	want := readTokenElevated(self, readTokenLabel(self))
	sid := u.User.Sid.String()
	self.Close()

	peer := childPipePeer(t)
	user, err := peer.User.AtLeast(ProofKernel)
	if err != nil || user.SID != sid {
		t.Fatalf("peer user %v %v, want %s", user, err, sid)
	}
	if peer.Elevated() != want || user.Elevated != want {
		t.Fatalf("peer elevated %v (user %v), this account's token classifies %v; notes %v", peer.Elevated(), user.Elevated, want, peer.Notes)
	}
}

// TestPipeTokenElevationNeedsTheProcessToken is ID-H3's cross-check at the
// bind seam: the pipe token's classifier is forced to elevated, and the peer
// reads elevated only when the pinned process's primary token also does. A
// limited process presenting an elevated linked token is the case it refuses.
func TestPipeTokenElevationNeedsTheProcessToken(t *testing.T) {
	priorType, priorFlag, priorLabel, priorProcess := tokenElevationType, tokenIsElevated, labelRID, processElevated
	t.Cleanup(func() {
		tokenElevationType, tokenIsElevated, labelRID, processElevated = priorType, priorFlag, priorLabel, priorProcess
	})
	tokenElevationType = func(windows.Token) (uint32, bool) { return tokenElevationTypeFull, true }
	tokenIsElevated = func(windows.Token) bool { return true }
	labelRID = func(windows.Token) (uint32, bool) { return 0x3000, true }

	for _, processSays := range []bool{false, true} {
		t.Run(map[bool]string{false: "process-limited", true: "process-elevated"}[processSays], func(t *testing.T) {
			var asked string
			processElevated = func(_ windows.Handle, sid string) bool { asked = sid; return processSays }
			peer := childPipePeer(t)
			user, err := peer.User.AtLeast(ProofKernel)
			if err != nil || asked != user.SID {
				t.Fatalf("process check asked about %q, peer user %v %v", asked, user, err)
			}
			if peer.Elevated() != processSays || user.Elevated != processSays {
				t.Fatalf("process token elevated %v: peer elevated %v; notes %v", processSays, peer.Elevated(), peer.Notes)
			}
		})
	}
}

// childPipePeer connects a child process to a fresh pipe and resolves it.
func childPipePeer(t *testing.T) *Peer {
	t.Helper()
	name := pipeName(t)
	server := listen(t, name)
	startChildClient(t, name, "{}")
	at := accept(t, server)
	readFrom(t, server)
	peer, err := OfHandle(Handle(server), &Options{ConnectedAt: at, SkipCodeSignature: true})
	if err != nil {
		t.Fatalf("OfHandle: %v", err)
	}
	return peer
}
