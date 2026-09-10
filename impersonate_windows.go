//go:build windows

package identity

import (
	"errors"
	"fmt"
	"runtime"
	"unsafe"

	"github.com/openabstractions/abstraction-identity/internal/integrity"
	"golang.org/x/sys/windows"
)

// errAnonymousClient is internal: the caller sees it as an unknown user with a
// why, not as a failure of the whole resolution, because the connection is
// still perfectly real and the service may still want to refuse it politely.
var errAnonymousClient = errors.New("the client opened the pipe with SECURITY_ANONYMOUS, so the kernel gave the server a token that identifies nobody")

// withPeerToken opens the pipe client's access token and hands it to fn.
//
// This is the only place in the package that impersonates, and the rules it
// obeys are worth stating, because getting any of them wrong is a privilege
// escalation rather than a wrong answer:
//
//  1. Impersonation is a property of an OS thread, not of a goroutine. The Go
//     scheduler is free to move a goroutine to another thread at almost any
//     point, and would then leave a thread behind still wearing the client's
//     token, ready to run unrelated code. So the impersonation runs on its own
//     goroutine, locked to its thread for the whole of it.
//
//  2. RevertToSelf runs on every path out - success, syscall failure, and
//     panic - because "we returned an error" is exactly the path where a
//     leaked token is least likely to be noticed.
//
//  3. If RevertToSelf itself fails there is no way to make that thread safe
//     again. The goroutine exits without unlocking, which makes the Go runtime
//     destroy the thread instead of returning it to the pool, and the caller
//     gets ErrImpersonationStuck instead of an identity. Losing a thread is
//     cheap; handing a client's token to the next piece of work that lands on
//     it is not.
//
// The token handed to fn is only borrowed: it is closed as soon as fn returns,
// so fn must copy anything it wants to keep. It is an impersonation token
// opened for TOKEN_QUERY only - this package reads identity, it never acts as
// the client.
func withPeerToken(pipe windows.Handle, fn func(windows.Token) error) error {
	done := make(chan error, 1)
	go func() {
		runtime.LockOSThread()
		// Set false only if the thread can no longer be trusted, in which
		// case it is deliberately never unlocked.
		safe := true
		defer func() {
			if safe {
				runtime.UnlockOSThread()
			}
		}()

		if err := impersonateNamedPipeClient(pipe); err != nil {
			if err == windows.ERROR_CANNOT_IMPERSONATE {
				done <- ErrMustReadFirst
				return
			}
			done <- fmt.Errorf("identity: ImpersonateNamedPipeClient: %w", err)
			return
		}

		// From here to RevertToSelf this thread is the client. Do as
		// little as possible, and nothing that can block.
		err := func() (err error) {
			defer func() {
				if r := recover(); r != nil {
					err = fmt.Errorf("identity: panic while impersonating: %v", r)
				}
			}()
			// openAsSelf: check access to the thread token against the
			// service's own token, not the client's. Without it a
			// low-privilege client's token cannot be opened at all.
			var tok windows.Token
			th, err := windows.GetCurrentThread()
			if err != nil {
				return fmt.Errorf("identity: GetCurrentThread: %w", err)
			}
			if err := windows.OpenThreadToken(th, windows.TOKEN_QUERY, true, &tok); err != nil {
				return fmt.Errorf("identity: OpenThreadToken: %w", err)
			}
			defer tok.Close()
			return fn(tok)
		}()

		if rerr := windows.RevertToSelf(); rerr != nil {
			safe = false
			done <- fmt.Errorf("%w: %v", ErrImpersonationStuck, rerr)
			return
		}
		done <- err
	}()
	return <-done
}

// peerUser reads the client's security principal off the impersonation token.
//
// It deliberately does everything that needs the token inside withPeerToken and
// nothing else: the SID is copied out, and the account-name lookup - which
// talks to the LSA and can be slow or fail on a machine that has lost its
// domain - happens afterwards, unimpersonated, where a failure costs a display
// name and not the identity.
func peerUser(pipe windows.Handle) (User, string, error) {
	var (
		sid          *windows.SID
		elevated     bool
		level        uint32
		integrityRID uint32
	)
	err := withPeerToken(pipe, func(tok windows.Token) error {
		var n uint32
		if err := windows.GetTokenInformation(tok, windows.TokenImpersonationLevel,
			(*byte)(unsafe.Pointer(&level)), uint32(unsafe.Sizeof(level)), &n); err != nil {
			return fmt.Errorf("identity: TokenImpersonationLevel: %w", err)
		}
		if level == windows.SecurityAnonymous {
			// The client opened the pipe with SECURITY_ANONYMOUS, which
			// tells the kernel to give the server a token it can learn
			// nothing from. This is the client's choice and there is no
			// override; refusing is the only honest response.
			return errAnonymousClient
		}
		u, err := tok.GetTokenUser()
		if err != nil {
			return fmt.Errorf("identity: GetTokenUser: %w", err)
		}
		// The SID lives in the token information buffer, which is freed
		// when this returns. Copy it.
		sid, err = u.User.Sid.Copy()
		if err != nil {
			return fmt.Errorf("identity: copy SID: %w", err)
		}
		elevated = tok.IsElevated()
		integrityRID = tokenIntegrityRID(tok)
		return nil
	})
	if err != nil {
		return User{}, "", err
	}

	user := User{
		Kind: "windows", SID: sid.String(), Elevated: elevated,
		Integrity: integrityName(integrityRID), IntegrityRID: integrityRID,
		UID: -1, GID: -1,
	}
	why := ""
	if name, domain, _, err := sid.LookupAccount(""); err == nil {
		user.Name, user.Domain = name, domain
	} else {
		why = "the SID has no resolvable account name (" + err.Error() + "); the SID itself is unaffected"
	}
	if level == windows.SecurityIdentification {
		why = joinWhy(why, "the client granted SECURITY_IDENTIFICATION, which is the level this identity is read at")
	}
	return user, why, nil
}

// tokenIntegrityRID reads the mandatory label off the peer's token. A failure
// costs a display detail, not the identity, so it returns 0 rather than an
// error.
func tokenIntegrityRID(tok windows.Token) uint32 {
	rid, _ := integrity.RID(tok)
	return rid
}

// Mandatory integrity levels, as RIDs of the label SID.
const (
	integrityUntrusted = 0x0000
	integrityLow       = 0x1000
	integrityMedium    = 0x2000
	integrityHigh      = 0x3000
	integritySystem    = 0x4000
)

func integrityName(rid uint32) string {
	switch {
	case rid == 0:
		return ""
	case rid >= integritySystem:
		return "system"
	case rid >= integrityHigh:
		return "high"
	case rid >= integrityMedium:
		return "medium"
	case rid >= integrityLow:
		return "low"
	default:
		return "untrusted"
	}
}

func joinWhy(a, b string) string {
	if a == "" {
		return b
	}
	if b == "" {
		return a
	}
	return a + "; " + b
}
