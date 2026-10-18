package identity

import (
	"errors"
	"path/filepath"
	"testing"
	"time"
)

// TestCheckElevatedHelper is ID-H1: only this account's elevated,
// high-integrity process running the named image is the helper.
func TestCheckElevatedHelper(t *testing.T) {
	dir := t.TempDir()
	program := filepath.Join(dir, "openabstractions-system.exe")
	self := User{Kind: "windows", SID: "S-1-5-21-1-2-3-1001", Integrity: "medium", IntegrityRID: 0x2000}
	helper := func() *Peer {
		return &Peer{
			User:    attr("user", User{Kind: "windows", SID: self.SID, Elevated: true, Integrity: "high", IntegrityRID: 0x3000}, ProofKernel, ""),
			Process: attr("process", Process{PID: 4242, StartTime: time.Now()}, ProofKernel, ""),
			Path:    attr("path", program, ProofBound, ""),
		}
	}
	if err := CheckElevatedHelper(helper(), self, program); err != nil {
		t.Fatalf("the elevated helper of this account was refused: %v", err)
	}
	system := helper()
	system.User = attr("user", User{Kind: "windows", SID: self.SID, Elevated: true, Integrity: "system", IntegrityRID: 0x4000}, ProofKernel, "")
	if err := CheckElevatedHelper(system, self, program); err != nil {
		t.Fatalf("a level above high was refused: %v", err)
	}
	cases := map[string]func(*Peer){
		"another account": func(p *Peer) {
			p.User = attr("user", User{Kind: "windows", SID: "S-1-5-21-1-2-3-500", Elevated: true, IntegrityRID: 0x3000}, ProofKernel, "")
		},
		"unelevated": func(p *Peer) {
			p.User = attr("user", User{Kind: "windows", SID: self.SID, IntegrityRID: 0x3000}, ProofKernel, "")
		},
		"medium integrity": func(p *Peer) {
			p.User = attr("user", User{Kind: "windows", SID: self.SID, Elevated: true, IntegrityRID: 0x2000}, ProofKernel, "")
		},
		"unknown integrity": func(p *Peer) {
			p.User = attr("user", User{Kind: "windows", SID: self.SID, Elevated: true, Integrity: "unknown"}, ProofKernel, "")
		},
		"user below kernel": func(p *Peer) {
			p.User = attr("user", User{Kind: "windows", SID: self.SID, Elevated: true, IntegrityRID: 0x3000}, ProofPID, "")
		},
		"posix user": func(p *Peer) {
			p.User = attr("user", User{Kind: "posix", UID: 0, GID: 0}, ProofKernel, "")
		},
		"process unknown": func(p *Peer) { p.Process = unknown[Process]("process", "gone") },
		"path below bound": func(p *Peer) { p.Path = attr("path", program, ProofPID, "") },
		"another image": func(p *Peer) {
			p.Path = attr("path", filepath.Join(dir, "openabstractions.exe"), ProofBound, "")
		},
	}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			p := helper()
			change(p)
			if err := CheckElevatedHelper(p, self, program); !errors.Is(err, ErrNotHelper) {
				t.Fatalf("accepted: %v", err)
			}
		})
	}
	if err := CheckElevatedHelper(nil, self, program); !errors.Is(err, ErrNotHelper) {
		t.Fatalf("a missing peer was accepted: %v", err)
	}
	if err := CheckElevatedHelper(helper(), User{Kind: "posix"}, program); !errors.Is(err, ErrNotHelper) {
		t.Fatalf("a non-Windows self was accepted: %v", err)
	}
	if err := CheckElevatedHelper(helper(), self, "openabstractions-system.exe"); !errors.Is(err, ErrNotHelper) {
		t.Fatalf("a relative program matched: %v", err)
	}
}
