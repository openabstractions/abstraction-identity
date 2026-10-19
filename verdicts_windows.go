//go:build windows

package identity

import (
	"errors"
	"sync"
	"time"

	"golang.org/x/sys/windows"
)

// An Authenticode verdict is reused for later connections from the same live
// process instance.
//
// verifyImage hashes the whole image file and walks its certificate chain on
// every call: about 2 ms for a small unsigned program, 30 to 40 ms for the
// signed python.exe and 150 ms or more for the 90 MB signed node.exe, measured
// 2026-09-17 (research/inference/MEASURED.txt). A service binds every framed
// connection, so each call from a signed interpreter paid that price again for
// a file that could not have changed.
//
// The reuse rests on three facts, and its key is exactly what they need:
//
//   - the entry holds its own handle to the process, so while it exists the pid
//     names that process object and no other (the fact Bind already rests on),
//     and pid plus creation time identify the instance;
//   - a Windows process cannot replace its own image, and while the image
//     section is mapped the file cannot be opened for writing, so the file the
//     first verification read is the file the process still runs;
//   - the image path is part of the key, read afresh through the pinned handle
//     for every connection, so a different path verifies again.
//
// What a reused verdict does not see: a change in this machine's trust (a root
// or catalog added or removed, a certificate expiring) until the entry's
// lifetime ends. Revocation is checked from the local cache only by default,
// and CheckRevocation is part of the key. Failed verifications are not kept.
const (
	codeVerdictLifetime = 5 * time.Minute
	// New captures refresh with enough overlap for a 30-second presence lease
	// and its 10-second renewal cadence. Existing captures keep their deadline.
	codeVerdictRefreshAhead = 30 * time.Second
	codeVerdictLimit        = 256
)

type codeVerdictKey struct {
	pid        uint32
	started    int64
	image      string
	revocation bool
}

type codeVerdict struct {
	proc    windows.Handle
	code    Code
	verdict Proof
	at      time.Time
}

type codeVerification struct {
	done    chan struct{}
	code    Code
	verdict Proof
	at      time.Time
	err     error
}

// verifyFile is verifyImage; tests count verifications through it.
var verifyFile = verifyImage

var codeVerdictNow = time.Now

var codeVerdicts = struct {
	sync.Mutex
	entries map[codeVerdictKey]*codeVerdict
	working map[codeVerdictKey]*codeVerification
}{entries: map[codeVerdictKey]*codeVerdict{}, working: map[codeVerdictKey]*codeVerification{}}

// maxVerificationsPerAccount bounds the first-time code verifications one
// account has running at once [ID-V1]. A verification hashes the whole image,
// 150 ms or more for node.exe (ID-W2), so a burst of new processes from one
// account would otherwise hold a verification thread each. A peer over the
// bound is told no code answer with the reason, and a later connection of it
// verifies once a slot is free; a reused or shared verdict takes no slot.
const maxVerificationsPerAccount = 4

var verificationSlots = struct {
	sync.Mutex
	running map[string]int
}{running: map[string]int{}}

// errVerificationBudget refuses a verification over its account's bound.
var errVerificationBudget = errors.New("identity: this account already has the most code verifications running at once (ID-V1)")

// takeVerificationSlot reserves one of account's verification slots, or
// refuses with errVerificationBudget when all are taken.
func takeVerificationSlot(account string) (release func(), err error) {
	verificationSlots.Lock()
	defer verificationSlots.Unlock()
	if verificationSlots.running[account] >= maxVerificationsPerAccount {
		return nil, errVerificationBudget
	}
	verificationSlots.running[account]++
	return func() {
		verificationSlots.Lock()
		defer verificationSlots.Unlock()
		if verificationSlots.running[account]--; verificationSlots.running[account] <= 0 {
			delete(verificationSlots.running, account)
		}
	}, nil
}

// verifyProcessImage is verifyImage for a pinned peer process, reusing a verdict
// already reached for this process instance at this image path. It counts
// against the slots of the empty account, which tests use.
func verifyProcessImage(proc windows.Handle, pid uint32, started time.Time, imagePath string, opts *Options) (code Code, verdict Proof, err error) {
	code, verdict, _, err = verifyProcessImageAt(proc, pid, started, imagePath, "", opts)
	return code, verdict, err
}

// verifyProcessImageAt also returns when the verdict was verified. A binding
// reusing this evidence must preserve that original time, not restart its age.
// A verification it starts takes one of account's slots (ID-V1).
func verifyProcessImageAt(proc windows.Handle, pid uint32, started time.Time, imagePath, account string, opts *Options) (code Code, verdict Proof, at time.Time, err error) {
	key := codeVerdictKey{pid: pid, started: started.UnixNano(), image: imagePath, revocation: opts.checkRevocation()}
	codeVerdicts.Lock()
	if entry, ok := codeVerdicts.entries[key]; ok {
		now := codeVerdictNow()
		if now.Sub(entry.at) < codeVerdictLifetime-codeVerdictRefreshAhead && !now.Before(entry.at) {
			codeVerdicts.Unlock()
			return entry.code, entry.verdict, entry.at, nil
		}
		dropVerdict(key, entry)
	}
	if working := codeVerdicts.working[key]; working != nil {
		codeVerdicts.Unlock()
		<-working.done
		return working.code, working.verdict, working.at, working.err
	}
	working := &codeVerification{done: make(chan struct{})}
	codeVerdicts.working[key] = working
	codeVerdicts.Unlock()

	completed := false
	defer func() {
		if !completed {
			err = errors.New("identity: code verification interrupted")
		}
		codeVerdicts.Lock()
		working.code, working.verdict, working.at, working.err = code, verdict, at, err
		delete(codeVerdicts.working, key)
		close(working.done)
		codeVerdicts.Unlock()
	}()
	release, err := takeVerificationSlot(account)
	if err != nil {
		completed = true
		return Code{}, ProofNone, time.Time{}, err
	}
	defer release()
	code, verdict, err = verifyFile(proc, imagePath, opts)
	if err == nil {
		at = codeVerdictNow()
		keepVerdict(key, proc, code, verdict, at)
	}
	completed = true
	return code, verdict, at, err
}

func keepVerdict(key codeVerdictKey, proc windows.Handle, code Code, verdict Proof, now time.Time) {
	self := windows.CurrentProcess()
	var held windows.Handle
	if err := windows.DuplicateHandle(self, proc, self, &held, 0, false, windows.DUPLICATE_SAME_ACCESS); err != nil {
		return
	}
	// The duplicate must name the process the verification pinned.
	if started, err := processStartTime(held); err != nil || started.UnixNano() != key.started {
		//unchecked: best-effort release of a duplicated handle being discarded on this verification-failure path
		windows.CloseHandle(held)
		return
	}
	codeVerdicts.Lock()
	defer codeVerdicts.Unlock()
	if old, ok := codeVerdicts.entries[key]; ok {
		dropVerdict(key, old)
	}
	var oldest codeVerdictKey
	var oldestAt time.Time
	for k, e := range codeVerdicts.entries {
		var exit uint32
		gone := windows.GetExitCodeProcess(e.proc, &exit) != nil || exit != stillActive
		if gone || now.Sub(e.at) >= codeVerdictLifetime || now.Before(e.at) {
			dropVerdict(k, e)
			continue
		}
		if oldestAt.IsZero() || e.at.Before(oldestAt) {
			oldest, oldestAt = k, e.at
		}
	}
	if len(codeVerdicts.entries) >= codeVerdictLimit {
		dropVerdict(oldest, codeVerdicts.entries[oldest])
	}
	codeVerdicts.entries[key] = &codeVerdict{proc: held, code: code, verdict: verdict, at: now}
}

// dropVerdict requires the codeVerdicts lock.
func dropVerdict(key codeVerdictKey, entry *codeVerdict) {
	delete(codeVerdicts.entries, key)
	//unchecked: best-effort release of an evicted verdict entry's process handle, no caller left to report a close failure to
	windows.CloseHandle(entry.proc)
}
