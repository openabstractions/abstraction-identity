package identity

import (
	"fmt"
	"runtime"

	"github.com/openabstractions/abstraction-identity/fileid"
)

// SameView makes *Peer the peer argument of fileid's resolver, the argument
// SubjectOf takes (TD72): fileid.Resolve(ctx, peer, path, opt). It reports
// whether a path this peer sends names, in this process, the file it names
// for the peer. The runtime never resolves a caller's path with its own view
// of a namespace the caller does not share (VISION.md:750-751). It refuses,
// with an error matching fileid.ErrOtherView:
//   - a nil peer, and one whose platform is not this process's;
//   - a transport other than a named pipe, a Unix domain socket, XPC and
//     loopback TCP, which is how a remote peer would arrive;
//   - an AF_UNIX peer on Windows, which may be a WSL program reading its own
//     Linux file system;
//   - a user this process is not, or one not known at ProofPID: another
//     account sees other drive letters and other per-user folders;
//   - on Windows, a peer with a package identity (MSIX), whose AppData is
//     virtualized, and one at low or untrusted integrity (an AppContainer);
//   - on Linux, a Flatpak or Snap peer, which has its own mount namespace;
//   - a peer whose package, sandbox or integrity could not be read: only the
//     reader's own "not packaged" or "no sandbox" answer and, on Windows, a
//     known integrity at medium or above are read as this process's view.
//
// A macOS sandboxed app is not told apart yet: its container is read as this
// process reads it (Not built).
func (p *Peer) SameView() error {
	refuse := func(format string, args ...any) error {
		return fmt.Errorf("%w: %s", fileid.ErrOtherView, fmt.Sprintf(format, args...))
	}
	if p == nil {
		return refuse("no peer")
	}
	if p.Platform != runtime.GOOS {
		return refuse("the peer's answer came from %s", p.Platform)
	}
	switch p.Transport {
	case string(TransportNamedPipe), string(TransportUnix), string(TransportXPC), TransportLoopback:
	default:
		return refuse("the peer arrived over %q, which is not a local transport", p.Transport)
	}
	if runtime.GOOS == "windows" && p.Transport == string(TransportUnix) {
		return refuse("an AF_UNIX peer on Windows may be a WSL program, whose paths name its own file system")
	}
	u, err := p.User.AtLeast(ProofPID)
	if err != nil {
		return refuse("the peer's account is not known: %v", err)
	}
	me, err := Self()
	if err != nil {
		return refuse("this process's account is not known: %v", err)
	}
	theirs, err := u.Account()
	if err != nil {
		return refuse("the peer's account cannot be named")
	}
	mine, err := me.Account()
	if err != nil || theirs != mine {
		return refuse("the peer runs as another account")
	}
	pkg, _ := p.Package.Get()
	switch runtime.GOOS {
	case "windows":
		if pkg != "" {
			return refuse("a packaged app (%s) reads AppData through its own virtualized folders", pkg)
		}
		if p.Package.Why() != whyNotPackaged {
			return refuse("whether the peer is a packaged app is not known: %s", p.Package.Why())
		}
		switch u.Integrity {
		case "unknown", "untrusted", "low", "":
			return refuse("the peer runs at %q integrity, as an AppContainer or low-integrity process does, and reads files through its own namespace", u.Integrity)
		}
		if u.IntegrityRID < mediumIntegrityRID {
			return refuse("the peer runs at %s integrity, as an AppContainer or low-integrity process does, and reads files through its own namespace", u.Integrity)
		}
	case "linux":
		if pkg != "" {
			return refuse("a sandboxed app (%s) has its own mount namespace", pkg)
		}
		if p.Package.Why() != whyNoSandbox {
			return refuse("whether the peer is in a sandbox is not known: %s", p.Package.Why())
		}
	}
	return nil
}

// The reasons the readers give for a peer with no package identity: SameView
// reads the peer's view as this process's only on them, so a package that
// could not be read (the process gone, a recycled pid, a failed call) is
// refused with the packages.
const (
	whyNotPackaged = "the peer is an ordinary executable, not an MSIX package; Windows has no package identity to give"
	whyNoSandbox   = "the peer is not in a sandbox this package can recognise (Flatpak, Snap or Firejail); Linux has no general answer to what a process is - see CONTRACT.md"
	// mediumIntegrityRID is SECURITY_MANDATORY_MEDIUM_RID: an ordinary
	// process of the signed-in account runs at it or above.
	mediumIntegrityRID = 0x2000
)

var _ fileid.Peer = (*Peer)(nil)
