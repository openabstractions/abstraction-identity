package identity

import (
	"errors"
	"fmt"
	"strings"
	"time"
)

// Peer is what a service was able to learn about the program on the other end
// of an accepted local connection, with the strength of the evidence attached
// to every part of it separately.
//
// Nothing in a Peer was ever spoken by the peer. There is no field a caller can
// fill in from a request payload, and no constructor that takes one.
type Peer struct {
	// Platform is the GOOS the answer came from. The answer differs per
	// platform and a log line that omits which one is unreadable later.
	Platform string
	// Transport names the channel the identity was taken from: "npipe" on
	// Windows, "unix" on Linux and macOS. The same platform gives different
	// answers on different transports - on macOS, dramatically so, since an
	// XPC peer can be identified to a standard a socket peer cannot - so the
	// transport belongs next to the answer.
	Transport string
	// ObservedAt is when the identity was resolved, which is not when the
	// connection was accepted. See Options.ConnectedAt.
	ObservedAt time.Time

	// User is the security principal the peer runs as.
	User Attr[User]
	// Process is which process it is.
	Process Attr[Process]
	// Path is the filesystem path of the running image.
	Path Attr[string]
	// Package is a package identity where the platform has one: an MSIX
	// package full name on Windows, the signing identifier out of a
	// validated signature on macOS, a sandbox application id on Linux
	// ("flatpak:org.gnome.Calculator", "snap:chromium.chromium"). Unset for
	// ordinary executables.
	//
	// The three are not comparable. The Windows one comes out of a
	// certificate the OS validated; the macOS one out of a signature it
	// validated; the Linux one out of a file in the peer's own mount
	// namespace or a cgroup name, neither of which resists a hostile
	// process running as the same user. See CONTRACT.md before writing a
	// rule against this field.
	Package Attr[string]
	// Code is a code signing identity for the image, and never exceeds
	// ProofBound on any platform this package supports.
	//
	// On Windows it is an Authenticode verification of the file the process
	// was launched from, which is a weaker statement than it looks. On macOS
	// it is a Security framework verification of the running code, which is
	// a stronger statement - attached to a weaker binding, because a unix
	// socket cannot prove which process it belongs to. On Linux it is always
	// unset: the platform has nothing to verify. See CONTRACT.md.
	Code Attr[Code]

	// Notes records everything a reader would otherwise get wrong about this
	// particular answer: every place it came out weaker than this platform's
	// best, and why. It is for humans, for logs and for tests.
	Notes []string
}

// User is a security principal. Which fields are populated depends on the
// platform; Kind says which.
type User struct {
	Kind string // "windows" or "posix"

	// Windows.
	SID      string // e.g. "S-1-5-21-...-1001"
	Name     string // account name, best effort, may be empty
	Domain   string // account domain, best effort, may be empty
	Elevated bool   // the peer's token is elevated

	// Integrity is the peer's mandatory integrity level: "untrusted",
	// "low", "medium", "high", "system", or "unknown".
	//
	// It matters more than it looks. Two processes at the same integrity
	// level running as the same user are not isolated from each other on
	// Windows: either can open the other for full access and write into
	// it. So the answer this package gives about a same-user, same-level
	// peer identifies a program but does not defend against one. The
	// boundary that does hold is a lower level talking to a higher one - a
	// medium-integrity process cannot touch a high-integrity one, and an
	// AppContainer (low or untrusted) cannot touch either. See CONTRACT.md.
	Integrity string
	// IntegrityRID is the raw mandatory label RID behind Integrity, for
	// comparisons the named levels are too coarse for. Zero when unknown.
	IntegrityRID uint32

	// POSIX.
	UID int // -1 when unknown
	GID int // -1 when unknown

	// SecurityContext is the peer's LSM label on Linux: an SELinux context
	// ("unconfined_u:unconfined_r:unconfined_t:s0") or an AppArmor profile
	// ("/usr/bin/evince (enforce)"), read from SO_PEERSEC.
	//
	// It belongs to the principal rather than to the process because that
	// is what it is - a label the kernel attaches to a subject at exec, by
	// local policy - and it is stamped onto the socket at connect, so it
	// carries the same ProofKernel strength as the uid beside it. On an
	// AppArmor system it is worth more than the image path: the path names
	// a file, the profile names the policy the kernel is actually enforcing
	// against the peer. It is not a signature and never becomes one.
	//
	// Empty when no LSM labels processes on this system, and on every
	// platform other than Linux.
	SecurityContext string

	// AuditSessionID is the macOS audit session the peer belongs to, from
	// its audit token. Zero elsewhere. Two processes in the same audit
	// session are, roughly, the same login session.
	AuditSessionID uint32
}

func (u User) String() string {
	switch u.Kind {
	case "windows":
		s := u.SID
		if u.Name != "" {
			n := u.Name
			if u.Domain != "" {
				n = u.Domain + `\` + u.Name
			}
			s = n + " (" + u.SID + ")"
		}
		if u.Integrity != "" {
			s += " " + u.Integrity + "-integrity"
		}
		if u.Elevated {
			s += " elevated"
		}
		return s
	case "posix":
		s := fmt.Sprintf("uid=%d gid=%d", u.UID, u.GID)
		if u.SecurityContext != "" {
			s += " lsm=" + u.SecurityContext
		}
		if u.AuditSessionID != 0 {
			s += fmt.Sprintf(" asid=%d", u.AuditSessionID)
		}
		return s
	}
	return "unknown user"
}

// Process identifies the process on the other end.
type Process struct {
	// PID is the process id the kernel recorded for the peer when it
	// connected. It names the process that opened the connection, which is
	// not necessarily the process writing to it now: handles can be
	// inherited and duplicated. See CONTRACT.md.
	PID int
	// StartTime is when that process was created. It is the thing that
	// distinguishes a process from a later one that inherited its number,
	// so it belongs in a log next to the pid. Zero when the process could
	// not be opened.
	StartTime time.Time
	// Recycled is true when the pid was proven to belong to a different,
	// later process than the one that connected. Nothing resolved from the
	// pid is reported when it is set.
	Recycled bool

	// Generation distinguishes this process from a later one that inherits
	// its pid, where the platform keeps a counter for exactly that: the
	// pidversion inside a macOS audit token. Zero where the platform has
	// none, which is everywhere else - Windows uses StartTime for the same
	// job and Linux has neither.
	//
	// It is not a bound on its own. A pid and a pidversion read together
	// describe one process instance consistently; whether that instance is
	// the peer is a separate question, and on macOS sockets it is the
	// unanswered one. See CONTRACT.md.
	Generation uint32
}

func (p Process) String() string {
	s := fmt.Sprintf("pid %d", p.PID)
	if p.Generation != 0 {
		s += fmt.Sprintf(".%d", p.Generation)
	}
	if !p.StartTime.IsZero() {
		s += " started " + p.StartTime.Format(time.RFC3339Nano)
	}
	if p.Recycled {
		s += " RECYCLED"
	}
	return s
}

// Code is a code signing identity as some part of the operating system
// verified it - not as a file on disk claims it.
type Code struct {
	// Subject is the name the signing certificate was issued to: the
	// publisher, as a person reading a consent prompt would understand it.
	Subject string
	// Issuer is the certificate authority that vouched for the subject.
	// Subject alone is not an identity; anyone can obtain a certificate
	// naming themselves anything a CA will accept.
	Issuer string
	// Trusted is true when the platform's own trust policy accepted the
	// signature and the chain, with revocation checking as configured in
	// Options. A Code with Trusted false is a signature that exists and
	// failed, and Status says how.
	Trusted bool
	// Status is the platform's verdict in its own words, always populated:
	// "valid", "no signature", or the failing condition.
	Status string
	// Catalog is true on Windows when the signature came from a system
	// catalog rather than from an embedded signature in the file itself.
	Catalog bool

	// TeamID is the Apple Developer team identifier out of the validated
	// signature on macOS, and empty elsewhere.
	//
	// It is the field to write a rule against on that platform. Subject is a
	// display name a certificate authority was willing to issue and two
	// publishers can share one; a team id is assigned by Apple and is the
	// stable half of the answer. Platform binaries have none: they validate
	// against the system's own anchor instead, which is a different claim
	// and should be checked with a requirement rather than a string compare.
	TeamID string
}

func (c Code) String() string {
	if c.Subject == "" {
		return c.Status
	}
	s := c.Subject
	if c.TeamID != "" {
		s += " [team " + c.TeamID + "]"
	}
	if c.Issuer != "" {
		s += " (issued by " + c.Issuer + ")"
	}
	if !c.Trusted {
		s += " UNTRUSTED: " + c.Status
	}
	if c.Catalog {
		s += " via-catalog"
	}
	return s
}

func (p *Peer) String() string {
	return fmt.Sprintf("%s/%s %v %v %v %v %v", p.Platform, p.Transport,
		p.User, p.Process, p.Path, p.Package, p.Code)
}

func (p *Peer) note(format string, a ...any) {
	p.Notes = append(p.Notes, fmt.Sprintf(format, a...))
}

// Need is a policy: the minimum proof a service requires for each attribute
// before it will act. The zero Need requires nothing.
type Need struct {
	User    Proof
	Process Proof
	Path    Proof
	Package Proof
	Code    Proof
}

// Check reports whether this Peer meets the policy. The error names every
// attribute that fell short, so a service does not learn about its second
// impossible requirement only after fixing the first.
func (p *Peer) Check(n Need) error {
	var errs []error
	if n.User > ProofNone {
		if _, err := p.User.AtLeast(n.User); err != nil {
			errs = append(errs, err)
		}
	}
	if n.Process > ProofNone {
		if _, err := p.Process.AtLeast(n.Process); err != nil {
			errs = append(errs, err)
		}
	}
	if n.Path > ProofNone {
		if _, err := p.Path.AtLeast(n.Path); err != nil {
			errs = append(errs, err)
		}
	}
	if n.Package > ProofNone {
		if _, err := p.Package.AtLeast(n.Package); err != nil {
			errs = append(errs, err)
		}
	}
	if n.Code > ProofNone {
		if _, err := p.Code.AtLeast(n.Code); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// Limits is what a platform can prove at best, with the reason for each
// ceiling. Obtained from Ceiling.
type Limits struct {
	Platform string
	Best     Need
	Why      map[string]string // "user", "process", "path", "package", "code"

	// Transport names the channel these limits are about. The same platform
	// answers differently on different channels and a ceiling that omits
	// which one is unreadable.
	Transport string

	// Bindable reports whether [Bind] can tie an identity to the process
	// that opened the connection on this machine, as opposed to looking a
	// program up from a number afterwards. It is a property of the running
	// kernel, not of the GOOS: the same Linux binary answers true on 6.5 and
	// false on 4.4.
	Bindable bool

	// Binding names the primitive behind Bindable, or states what is missing
	// when it is false. Always populated.
	Binding string

	// Stronger names the transport that would prove more than this one, and
	// what it would add. Empty when this transport is already the platform's
	// best.
	Stronger string
}

func (l Limits) String() string {
	bind := "binding=" + l.Binding
	if l.Bindable {
		bind = "bound-by=" + l.Binding
	}
	return fmt.Sprintf("%s/%s: user=%s process=%s path=%s package=%s code=%s %s",
		l.Platform, l.Transport, l.Best.User, l.Best.Process, l.Best.Path,
		l.Best.Package, l.Best.Code, bind)
}

// CanEver reports whether a policy is satisfiable on this platform at all,
// under the best case for every attribute.
//
// Call it at startup, not per connection. The answer does not depend on who is
// calling, and a service whose permission model rests on a proof this platform
// cannot produce should refuse to start rather than fail open once per
// connection - or, worse, decide it can relax the requirement.
func CanEver(n Need) error {
	l := Ceiling()
	var errs []error
	cmp := func(name string, want, have Proof) {
		if want > have {
			errs = append(errs, &ProofError{Attribute: name, Want: want, Got: have, Why: l.Why[name]})
		}
	}
	cmp("user", n.User, l.Best.User)
	cmp("process", n.Process, l.Best.Process)
	cmp("path", n.Path, l.Best.Path)
	cmp("package", n.Package, l.Best.Package)
	cmp("code", n.Code, l.Best.Code)
	return errors.Join(errs...)
}

// Errors that say the channel itself cannot answer the question, as distinct
// from answering it weakly.
var (
	// ErrRemotePeer means the peer is not on this machine. A Windows named
	// pipe is reachable over SMB unless the server passes
	// PIPE_REJECT_REMOTE_CLIENTS, and a remote peer has no local pid at all.
	ErrRemotePeer = errors.New("identity: peer is not on this machine")

	// ErrNotServerEnd means the handle is not the end a service accepted:
	// the client end of a Windows named pipe, or a listening Unix socket.
	//
	// Both mistakes answer, rather than fail, if they are not caught. On the
	// client end of a pipe every question below has an answer and every
	// answer is about the service itself. SO_PEERCRED on a listening socket
	// returns the credentials captured at listen(2) - also the service's
	// own. A service that identified itself and believed it had identified a
	// caller would authorise everything.
	ErrNotServerEnd = errors.New("identity: handle is not the end of the connection the service accepted")

	// ErrUnsupportedConn means the connection is of a kind that carries no
	// peer credentials, or one whose handle this package cannot reach.
	ErrUnsupportedConn = errors.New("identity: connection carries no peer credentials")

	// ErrMustReadFirst means Windows will not identify a named pipe's client
	// until the server has completed a read on that pipe. It is not enough
	// for the client to have written; the server must have read.
	//
	// The consequence is unpleasant and unavoidable: a service has to accept
	// and read bytes from a caller it cannot yet name. Read one bounded
	// frame, identify the peer, and only then decide what the bytes were
	// allowed to ask for. Do not parse the frame first, do not size a buffer
	// from it, and above all do not read a name out of it - see
	// CONTRACT.md, "You must listen before you can ask who is speaking".
	ErrMustReadFirst = errors.New("identity: windows will not identify a pipe client until the server has read from the pipe")

	// ErrImpersonationStuck means the operating system refused to undo an
	// impersonation. It is returned instead of an identity, because a
	// process that cannot drop a client's token has a privilege escalation,
	// not a naming problem. The thread that held the token is destroyed
	// rather than returned to the scheduler; see impersonate_windows.go.
	ErrImpersonationStuck = errors.New("identity: could not revert impersonation; thread abandoned")

	// ErrUnimplemented means this platform's answer has not been built yet.
	// It is returned instead of a weaker answer from a portable fallback,
	// deliberately: a permission system that silently degrades to "some
	// process on this machine" is worse than one that will not start.
	ErrUnimplemented = errors.New("identity: not implemented on this platform")
)

// Options tunes resolution. The zero value is safe. ConnectedAt is worth
// setting, and is the only field most callers need.
type Options struct {
	// ConnectedAt is when the connection was accepted.
	//
	// Resolution refuses to report anything read out of the peer's pid
	// unless it can first open the process and see that it was created
	// before this instant. A process that inherited a recycled pid must have
	// been created after the connection already existed, so the check
	// excludes every one of them.
	//
	// Leave it zero and the check uses the moment of resolution instead,
	// which still excludes any reuse after that moment but not reuse between
	// accept and resolution. Set it in the accept loop, on the line after
	// accept returns, and the window closes to the width of one accept.
	ConnectedAt time.Time

	// CheckRevocation asks the platform to contact revocation infrastructure
	// while verifying a signature. It is off by default because it makes
	// identification depend on the network, and a permission prompt that
	// hangs is a permission prompt that gets clicked through.
	CheckRevocation bool

	// SkipCodeSignature skips signature verification entirely. It costs tens
	// of milliseconds on a cold cache and a service that never asks about
	// Code should not pay it.
	SkipCodeSignature bool

	// CodeRequirement is a macOS code signing requirement, such as
	//
	//	anchor apple generic and certificate leaf[subject.OU] = "TEAMID"
	//
	// It is handed to SecCodeCheckValidity, so the operating system decides
	// whether the peer satisfies it. That is worth more than reading
	// Code.TeamID and comparing it here: the requirement language covers the
	// anchor, the chain and the leaf together, and a comparison written in
	// Go can only see what this package chose to extract.
	//
	// Empty means "verify the signature, tell me what it says, and let me
	// decide". Ignored on Windows and Linux, neither of which has anything
	// to give it to.
	CodeRequirement string
}

func (o *Options) connectedAt() time.Time {
	if o != nil && !o.ConnectedAt.IsZero() {
		return o.ConnectedAt
	}
	return time.Now()
}

func (o *Options) checkRevocation() bool   { return o != nil && o.CheckRevocation }
func (o *Options) skipCodeSignature() bool { return o != nil && o.SkipCodeSignature }

func (o *Options) codeRequirement() string {
	if o == nil {
		return ""
	}
	return o.CodeRequirement
}

// samePath compares two filesystem paths for the platforms this package
// supports. Windows paths are case-insensitive; the comparison is only ever
// used between two paths the kernel produced for the same handle, never
// against anything a peer supplied.
func samePath(a, b string) bool { return strings.EqualFold(a, b) }
