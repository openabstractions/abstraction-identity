package identity

import (
	"testing"
	"time"
)

// TestElevatedTokenFromFields is ID-H3's classification, from the three token
// fields alone: an admin's ordinary medium-integrity process (the limited
// half, whose Administrators SID is deny-only) is never elevated, and neither
// is a token whose label could not be read.
func TestElevatedTokenFromFields(t *testing.T) {
	for _, c := range []struct {
		name     string
		kind     uint32
		elevated bool
		rid      uint32
		want     bool
	}{
		{"UAC-elevated full token at high", tokenElevationTypeFull, true, 0x3000, true},
		{"non-split admin token at high", tokenElevationTypeDefault, true, 0x3000, true},
		{"SYSTEM, non-split at system", tokenElevationTypeDefault, true, 0x4000, true},
		{"admin's ordinary process, limited at medium", tokenElevationTypeLimited, false, 0x2000, false},
		{"limited half that claims elevation", tokenElevationTypeLimited, true, 0x3000, false},
		{"standard user, non-split at medium", tokenElevationTypeDefault, false, 0x2000, false},
		{"elevated flag at medium", tokenElevationTypeDefault, true, 0x2000, false},
		{"full token at medium", tokenElevationTypeFull, true, 0x2000, false},
		{"full token not reported elevated", tokenElevationTypeFull, false, 0x3000, false},
		{"unreadable label", tokenElevationTypeFull, true, 0, false},
		{"unknown elevation type", 0, true, 0x3000, false},
		{"low integrity AppContainer", tokenElevationTypeDefault, false, 0x1000, false},
	} {
		if got := elevatedToken(c.kind, c.elevated, c.rid); got != c.want {
			t.Errorf("%s: elevatedToken(%d, %v, %#x) = %v, want %v", c.name, c.kind, c.elevated, c.rid, got, c.want)
		}
	}
}

// TestPeerElevatedNeedsBoundPipeEvidence is ID-H3's bound attribute: only a
// Windows named-pipe peer whose user reads elevated at kernel, at high
// integrity, unrestricted, with a pinned unrecycled process reads elevated.
func TestPeerElevatedNeedsBoundPipeEvidence(t *testing.T) {
	sid := "S-1-5-21-1-2-3-1001"
	elevated := func() *Peer {
		return &Peer{
			Platform:  "windows",
			Transport: "npipe",
			User:      attr("user", User{Kind: "windows", SID: sid, Elevated: true, Integrity: "high", IntegrityRID: 0x3000}, ProofKernel, ""),
			Process:   attr("process", Process{PID: 4242, StartTime: time.Now()}, ProofKernel, ""),
		}
	}
	if !elevated().Elevated() {
		t.Fatal("an elevated pipe peer read not elevated")
	}
	var none *Peer
	if none.Elevated() {
		t.Fatal("a nil peer read elevated")
	}
	for name, change := range map[string]func(*Peer){
		"loopback":  func(p *Peer) { p.Transport = TransportLoopback },
		"remote":    func(p *Peer) { p.Transport = "oa-framed-mtls@1" },
		"synthetic": func(p *Peer) { p.Platform, p.Transport = "identitytest", "fixture" },
		"linux":     func(p *Peer) { p.Platform, p.Transport = "linux", "unix" },
		"not elevated": func(p *Peer) {
			p.User = attr("user", User{Kind: "windows", SID: sid, IntegrityRID: 0x3000}, ProofKernel, "")
		},
		"medium integrity": func(p *Peer) {
			p.User = attr("user", User{Kind: "windows", SID: sid, Elevated: true, IntegrityRID: 0x2000}, ProofKernel, "")
		},
		"restricted": func(p *Peer) {
			p.User = attr("user", User{Kind: "windows", SID: sid, Elevated: true, IntegrityRID: 0x3000, Restricted: true}, ProofKernel, "")
		},
		"user below kernel": func(p *Peer) {
			p.User = attr("user", User{Kind: "windows", SID: sid, Elevated: true, IntegrityRID: 0x3000}, ProofPID, "")
		},
		"no SID": func(p *Peer) {
			p.User = attr("user", User{Kind: "windows", Elevated: true, IntegrityRID: 0x3000}, ProofKernel, "")
		},
		"process unknown": func(p *Peer) { p.Process = unknown[Process]("process", "gone") },
		"recycled": func(p *Peer) {
			p.Process = attr("process", Process{PID: 4242, StartTime: time.Now(), Recycled: true}, ProofKernel, "")
		},
		"unpinned": func(p *Peer) { p.Process = attr("process", Process{PID: 4242}, ProofKernel, "") },
	} {
		p := elevated()
		change(p)
		if p.Elevated() {
			t.Errorf("%s: read elevated", name)
		}
	}
}
