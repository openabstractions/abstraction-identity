package identity

import (
	"errors"
	"fmt"
)

// Proof says how hard it would be for a hostile caller to make one attribute of
// a Peer lie. It is a total order because a policy has to compare against a
// minimum, but the steps are qualitatively different, and the documentation of
// each one says what it actually rests on. Read those before writing a policy;
// the number alone is not the argument.
//
// From ProofPID upwards a rung says how the value was bound to the peer. The
// three rungs below it are verdicts, produced only for Code: the platform
// examined the peer's signature and did not accept it, and the rung says how
// far it got. They sit below every rung that implies verification, so a policy
// that requires a verified signature refuses them by comparison alone, and a
// policy that knowingly admits an unverified caller names the lower rung.
type Proof uint8

const (
	// ProofNone means the attribute was not determined: either the platform
	// cannot supply it at all, or this particular connection did not carry
	// it. The value is meaningless and must not be used. Attr refuses to
	// hand it out.
	ProofNone Proof = iota

	// ProofClaimed means the peer said so. This package never produces it
	// and has no API that accepts it. The level exists to name the thing
	// being refused, so a service tempted to read an "owner" field out of
	// the request payload has somewhere to look and be told no.
	ProofClaimed

	// ProofInvalid means the platform found a signature and refused it: the
	// code was modified after signing, the certificate is expired or revoked,
	// or the chain reaches a root this machine does not trust. It is the
	// lowest verdict, below ProofUnsigned, because no signature is no claim
	// and a refused signature is a claim the operating system rejected. The
	// value carries the platform's wording in Code.Status and no identity.
	ProofInvalid

	// ProofUnsigned means the platform looked and found no signature at all.
	// A policy that admits unsigned callers asks for this rung by name.
	ProofUnsigned

	// ProofUnmet means the signature is intact and the platform accepted it,
	// but the code does not satisfy the requirement the service asked for in
	// Options.CodeRequirement. It is the strongest verdict short of
	// verification: intact code, signed by somebody other than who was
	// required. Nothing is read out of a signature that failed the check it
	// was given, so the value still carries no identity. Only macOS produces
	// it; Windows has no requirement language.
	ProofUnmet

	// ProofPID means the attribute was read out of the operating system by
	// process id, after the connection was already up, without checking that
	// the process behind that id is still the one that connected. It is racy
	// by construction: pids are reused. Good enough for a log line, never
	// good enough for a permission decision.
	ProofPID

	// ProofBound means the attribute was read through something that ties
	// it to the process that connected, rather than to a number that
	// process once had. What that something is differs per platform, and so
	// does exactly what it excludes:
	//
	//   - Windows: a process handle whose creation time predates the
	//     connection, which excludes every process that could have
	//     inherited the pid. The reuse race is closed.
	//   - Linux: a pidfd the kernel derived from the connection itself
	//     (SO_PEERPIDFD). While it is open the pid cannot be reassigned, so
	//     /proc read behind it answers about the peer or about nothing.
	//   - macOS: a pid and pidversion from the peer socket, cross-checked
	//     against the connect-time credentials and refused if the process
	//     started after the connection. That excludes pid reuse and any
	//     program spawned to impersonate; it does not exclude a process
	//     that already existed and was handed the socket. See CONTRACT.md.
	//
	// The attribute is still only the operating system's record about a
	// running process (an image path, say), not a statement about code -
	// except on macOS, where a verified code signature also lands here,
	// because over a socket the signature is only worth what the binding
	// above is worth.
	ProofBound

	// ProofKernel means the kernel stamped the attribute onto the connection
	// itself, out of its own records, at the moment the peer connected. The
	// peer never spoke it and cannot influence it. The access token behind
	// ImpersonateNamedPipeClient is of this kind, and so is the client
	// process id the kernel recorded on the pipe; on Linux, so are the uid,
	// gid and pid in SO_PEERCRED and the LSM label in SO_PEERSEC.
	//
	// "At the moment the peer connected" is the load-bearing half. A value
	// the kernel produces honestly but resolves when asked - LOCAL_PEERPID
	// and LOCAL_PEERTOKEN on macOS, which follow the peer socket's current
	// owner - is not of this kind, however official its source.
	ProofKernel

	// ProofSigned means the operating system itself validated a code
	// signature and the identity reported here came out of that validation -
	// not out of a filename. On Windows only MSIX package identity reaches
	// this level: the package full name contains a hash of the publisher
	// identity from the certificate the OS checked when it installed and
	// launched the package, and no unpackaged process can be given one.
	//
	// Authenticode on a plain executable does NOT reach this level, however
	// good the signature is. See Peer.Code and CONTRACT.md.
	//
	// Neither does macOS over a unix socket, which is the surprise in this
	// package: the Security framework really does verify running code, but
	// the audit token that selects which code is resolved from the peer
	// socket's current owner rather than stamped at connect. The transport
	// that reaches this level on macOS is XPC, whose messages carry a token
	// the kernel stamped on the sender. This package speaks sockets, so no
	// platform it supports reports ProofSigned for an ordinary program.
	ProofSigned
)

var proofNames = [...]string{"none", "claimed", "invalid", "unsigned", "unmet", "pid", "bound", "kernel", "signed"}

func (p Proof) String() string {
	if int(p) < len(proofNames) {
		return proofNames[p]
	}
	return fmt.Sprintf("Proof(%d)", uint8(p))
}

// ErrNotProven is the root of every failure to meet a required proof level.
// Test for it with errors.Is.
var ErrNotProven = errors.New("identity: not proven to the required level")

// ProofError reports an attribute that is either unknown or known less firmly
// than the caller demanded. Why carries the reason the platform gave, which is
// usually the only actionable part of the message.
type ProofError struct {
	Attribute string
	Want, Got Proof
	Why       string
}

func (e *ProofError) Error() string {
	s := fmt.Sprintf("identity: %s is proven only at %q, %q required", e.Attribute, e.Got, e.Want)
	if e.Why != "" {
		s += " (" + e.Why + ")"
	}
	return s
}

func (e *ProofError) Is(target error) bool { return target == ErrNotProven }

// Attr is one attribute of a peer together with the strength of the evidence
// for it. There is deliberately no way to read the value without being handed
// the proof at the same time: a service that needs a verified signature has to
// see that it got something weaker instead of silently accepting it.
type Attr[T any] struct {
	name  string
	value T
	proof Proof
	why   string
}

func attr[T any](name string, value T, proof Proof, why string) Attr[T] {
	return Attr[T]{name: name, value: value, proof: proof, why: why}
}

func unknown[T any](name, why string) Attr[T] {
	return Attr[T]{name: name, proof: ProofNone, why: why}
}

// Name is the attribute's name, as it appears in messages.
func (a Attr[T]) Name() string { return a.name }

// Proof is the strength of the evidence. ProofNone means there is no value.
func (a Attr[T]) Proof() Proof { return a.proof }

// Why explains how the attribute came to be as strong as it is, and no
// stronger. It is populated whenever there is something a reader would
// otherwise get wrong - including for values that were resolved successfully.
func (a Attr[T]) Why() string { return a.why }

// Known reports whether any value at all was determined.
func (a Attr[T]) Known() bool { return a.proof > ProofNone }

// Get returns the value and its proof together. Use it when the decision
// depends on the proof; use AtLeast when a fixed minimum is required.
func (a Attr[T]) Get() (T, Proof) { return a.value, a.proof }

// AtLeast returns the value only if it is proven at least as strongly as min,
// and otherwise a *ProofError explaining what was available instead.
func (a Attr[T]) AtLeast(min Proof) (T, error) {
	if a.proof >= min && a.proof > ProofNone {
		return a.value, nil
	}
	var zero T
	return zero, &ProofError{Attribute: a.name, Want: min, Got: a.proof, Why: a.why}
}

// String renders the attribute for logs, always including the proof, so that a
// log line cannot look stronger than it is.
func (a Attr[T]) String() string {
	if !a.Known() {
		if a.why != "" {
			return fmt.Sprintf("%s=unknown(%s)", a.name, a.why)
		}
		return a.name + "=unknown"
	}
	return fmt.Sprintf("%s=%v[%s]", a.name, a.value, a.proof)
}
