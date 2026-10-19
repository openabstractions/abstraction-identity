package identity

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/openabstractions/abstraction-identity/fileid"
	"github.com/openabstractions/abstraction-identity/placetest"
)

// localTransport is the stream transport a same-account peer arrives over
// on this platform.
func localTransport() string {
	if runtime.GOOS == "windows" {
		return string(TransportNamedPipe)
	}
	return string(TransportUnix)
}

// sameAccountPeer is a peer running as this process's account over this
// platform's local transport: the case the resolver reads in its own view.
func sameAccountPeer(t *testing.T) *Peer {
	t.Helper()
	me, err := Self()
	if err != nil {
		t.Skip("this process's account:", err)
	}
	if me.Integrity == "" {
		me.Integrity = "medium"
	}
	p := &Peer{Platform: runtime.GOOS, Transport: localTransport(), User: attr("user", me, ProofKernel, "")}
	switch runtime.GOOS {
	case "windows":
		p.Package = unknown[string]("package", whyNotPackaged)
	case "linux":
		p.Package = unknown[string]("package", whyNoSandbox)
	}
	return p
}

// peerFor builds the peer a cases.json caller_namespace names.
func peerFor(t *testing.T, ns string) *Peer {
	p := sameAccountPeer(t)
	switch ns {
	case "same-account peer":
	case "MSIX caller":
		p.Package = attr("package", "Contoso.Notes_1.0.0.0_x64__8wekyb3d8bbwe", ProofSigned, "")
	case "AppContainer caller":
		u, _ := p.User.Get()
		u.Integrity = "low"
		p.User = attr("user", u, ProofKernel, "")
	case "WSL client":
		p.Transport = string(TransportUnix)
	case "remote peer":
		p.Transport = "tls"
	default:
		t.Fatalf("no peer for caller namespace %q", ns)
	}
	return p
}

// TestCallerRowsOfCasesJSON runs the cases.json rows whose fixture is a
// caller (setup caller): fileid.Resolve with that caller's peer, against a
// file that exists, answers the row's want before anything is opened. A
// caller-relative row gives the peer the file's relative name, which is
// refused with ErrUnsafeName; a caller row's refusal is ErrOtherView.
func TestCallerRowsOfCasesJSON(t *testing.T) {
	table, _, err := placetest.Load()
	if errors.Is(err, placetest.ErrNoTable) {
		t.Skip(err)
	}
	if err != nil {
		t.Fatal(err)
	}
	f := filepath.Join(t.TempDir(), "file.txt")
	if err := os.WriteFile(f, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	ran := 0
	for _, c := range table.Rows {
		if c.Setup != "caller" && c.Setup != "caller-relative" {
			continue
		}
		c := c
		t.Run(c.ID, func(t *testing.T) {
			if !c.ForThisPlatform() {
				t.Skipf("platform %s, running on %s", c.Platform, runtime.GOOS)
			}
			ran++
			opened := 0
			stop, ok := ObserveOpens(func(string) { opened++ })
			if !ok {
				t.Fatal("another open observer is set")
			}
			defer stop()
			path, refusal := f, fileid.ErrOtherView
			if c.Setup == "caller-relative" {
				path, refusal = filepath.Base(f), fileid.ErrUnsafeName
			}
			_, err := fileid.Resolve(context.Background(), peerFor(t, c.CallerNamespace), path, fileid.Options{})
			got := "resolves"
			if errors.Is(err, refusal) {
				got = "refused"
			} else if err != nil {
				got = "error: " + err.Error()
			}
			if got != c.Want || got != c.Current {
				t.Errorf("%s: %s (%v), want %s", c.CallerNamespace, got, err, c.Want)
			}
			if opened != 0 {
				t.Errorf("%s: %d opens before the refusal", c.CallerNamespace, opened)
			}
		})
	}
	if ran == 0 && runtime.GOOS != "darwin" {
		t.Error("cases.json has no caller row for this platform")
	}
}

// A peer of this account over the local transport reads paths in this
// process's view; each other kind of peer is refused.
func TestSameViewTellsTheCallersNamespace(t *testing.T) {
	f := filepath.Join(t.TempDir(), "file.txt")
	if err := os.WriteFile(f, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	p := sameAccountPeer(t)
	if err := p.SameView(); err != nil {
		t.Fatalf("a same-account peer: %v", err)
	}
	if _, err := fileid.Resolve(context.Background(), p, f, fileid.Options{}); err != nil {
		t.Fatalf("Resolve for a same-account peer: %v", err)
	}
	other := func(change func(p *Peer)) *Peer {
		q := sameAccountPeer(t)
		change(q)
		return q
	}
	refused := map[string]*Peer{
		"nil":            nil,
		"other platform": other(func(q *Peer) { q.Platform = "plan9" }),
		"remote":         other(func(q *Peer) { q.Transport = "tls" }),
		"user unknown":   other(func(q *Peer) { q.User = unknown[User]("user", "not read") }),
		"other account": other(func(q *Peer) {
			u, _ := q.User.Get()
			u.SID, u.UID = "S-1-5-21-1-2-3-1001", u.UID+1
			q.User = attr("user", u, ProofKernel, "")
		}),
	}
	if runtime.GOOS == "windows" {
		refused["packaged"] = peerFor(t, "MSIX caller")
		refused["appcontainer"] = peerFor(t, "AppContainer caller")
		refused["wsl"] = peerFor(t, "WSL client")
		// Missing evidence is refused with the cases it would have shown.
		refused["package unknown: call failed"] = other(func(q *Peer) {
			q.Package = unknown[string]("package", "GetPackageFullName failed: Access is denied.")
		})
		refused["package unknown: process gone"] = other(func(q *Peer) {
			q.Package = unknown[string]("package", "the peer process was gone before it could be pinned")
		})
		refused["package unknown: never read"] = other(func(q *Peer) { q.Package = Attr[string]{} })
		refused["integrity unknown"] = other(func(q *Peer) {
			u, _ := q.User.Get()
			u.Integrity, u.IntegrityRID = "unknown", 0
			q.User = attr("user", u, ProofKernel, "")
		})
	}
	if runtime.GOOS == "linux" {
		refused["flatpak"] = other(func(q *Peer) { q.Package = attr("package", "flatpak:org.example.App", ProofPID, "") })
		refused["sandbox unknown: pid reused"] = other(func(q *Peer) {
			q.Package = unknown[string]("package", "pid 4242 now belongs to a process that started later; it is not the peer")
		})
	}
	for name, q := range refused {
		if err := q.SameView(); !errors.Is(err, fileid.ErrOtherView) {
			t.Errorf("%s: SameView %v, want ErrOtherView", name, err)
		}
	}
}
