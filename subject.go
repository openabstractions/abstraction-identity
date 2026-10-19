package identity

import (
	"errors"
	"fmt"
	"strconv"
)

// Subject is the account and program a receiving service acts for [ID-C7].
// Every service names its caller with SubjectOf, so a permission granted to
// or refused for an application means the same thing in every service.
type Subject struct {
	// AccountKind is the User.Kind the account was read from: "windows" or
	// "posix".
	AccountKind string
	// Account is the Windows SID, or the POSIX uid in decimal.
	Account string
	// Program is SubjectProgram's answer at the need's path proof, and empty
	// when the need names no path proof.
	Program string
}

var (
	// ErrNoAccount refuses a user with no account to name: a Windows user
	// with no SID, a negative POSIX uid, or a user of no known kind.
	ErrNoAccount = errors.New("identity: the caller's account cannot be named")
	// ErrNoProgram refuses a peer whose program SubjectProgram cannot name
	// at the need's path proof.
	ErrNoProgram = errors.New("identity: the caller's program cannot be named")
	// ErrNoPeer refuses a nil peer: the receiving site held no peer to name,
	// a programming error at that site.
	ErrNoPeer = errors.New("identity: no peer to name")
)

// SubjectOf names the account and program behind a peer, at the proof need
// asks of each attribute [ID-C7]. need is the receiving site's own policy:
// listen.Program for a service acting for its caller, a need naming the user
// alone for a site that only compares accounts. In order, it refuses:
//   - a nil peer, with ErrNoPeer;
//   - a peer that fails Check(need), with Check's error (errors.Is
//     ErrNotProven);
//   - a user that is not known at need.User;
//   - when need names a path proof, a program SubjectProgram cannot name at
//     that proof, with ErrNoProgram;
//   - a user whose account cannot be named, with ErrNoAccount.
//
// The account is the Windows SID, or the POSIX uid in decimal when it is not
// negative (User.Account).
func SubjectOf(p *Peer, need Need) (Subject, error) {
	if p == nil {
		return Subject{}, ErrNoPeer
	}
	if err := p.Check(need); err != nil {
		return Subject{}, err
	}
	u, err := p.User.AtLeast(need.User)
	if err != nil {
		return Subject{}, err
	}
	var s Subject
	if need.Path > ProofNone {
		program, err := SubjectProgram(p, need.Path)
		if err != nil {
			return Subject{}, fmt.Errorf("%w (%v)", ErrNoProgram, err)
		}
		s.Program = program
	}
	account, err := u.Account()
	if err != nil {
		return Subject{}, err
	}
	s.AccountKind, s.Account = u.Kind, account
	return s, nil
}

// OwnerAdmission is same-account admission at a receiving service. A refusal
// carries no Subject. Services retain their version's generated refusal words.
type OwnerAdmission string

const (
	OwnerAdmitted         OwnerAdmission = ""
	OwnerUnavailable      OwnerAdmission = "unavailable"
	OwnerIdentityRequired OwnerAdmission = "identity_required"
	OwnerOtherAccount     OwnerAdmission = "wrong_user"
)

// AdmitOwner derives SubjectOf at need and compares the receiving account.
// It grants no operation or resource permission and never changes need. An
// absent peer is unavailable; an unnameable account retains the wrong-user
// refusal used by the existing same-account adapters. An empty owner cannot
// match a named account. Identity-only derivations continue to use SubjectOf.
func AdmitOwner(peer *Peer, need Need, owner string) (Subject, OwnerAdmission) {
	if peer == nil {
		return Subject{}, OwnerUnavailable
	}
	subject, err := SubjectOf(peer, need)
	if errors.Is(err, ErrNoAccount) {
		return Subject{}, OwnerOtherAccount
	}
	if err != nil {
		return Subject{}, OwnerIdentityRequired
	}
	if subject.Account != owner {
		return Subject{}, OwnerOtherAccount
	}
	return subject, OwnerAdmitted
}

// Account names the user as every service names an account [ID-C7]: a
// Windows user by its SID, a POSIX user by its uid in decimal. A Windows user
// with no SID, a negative uid and a user of no known kind refuse with
// ErrNoAccount. SubjectOf is the entry point for a peer; Account serves a
// User obtained without one, such as Self's.
func (u User) Account() (string, error) {
	switch {
	case u.Kind == "windows" && u.SID != "":
		return u.SID, nil
	case u.Kind == "posix" && u.UID >= 0:
		return strconv.Itoa(u.UID), nil
	}
	return "", ErrNoAccount
}
