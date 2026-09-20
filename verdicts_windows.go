//go:build windows

package identity

import (
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
	codeVerdictLimit    = 256
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

// verifyFile is verifyImage; tests count verifications through it.
var verifyFile = verifyImage

var codeVerdicts = struct {
	sync.Mutex
	entries map[codeVerdictKey]*codeVerdict
}{entries: map[codeVerdictKey]*codeVerdict{}}

// verifyProcessImage is verifyImage for a pinned peer process, reusing a verdict
// already reached for this process instance at this image path.
func verifyProcessImage(proc windows.Handle, pid uint32, started time.Time, imagePath string, opts *Options) (Code, Proof, error) {
	key := codeVerdictKey{pid: pid, started: started.UnixNano(), image: imagePath, revocation: opts.checkRevocation()}
	if code, verdict, ok := reusedVerdict(key, time.Now()); ok {
		return code, verdict, nil
	}
	code, verdict, err := verifyFile(proc, imagePath, opts)
	if err == nil {
		keepVerdict(key, proc, code, verdict, time.Now())
	}
	return code, verdict, err
}

func reusedVerdict(key codeVerdictKey, now time.Time) (Code, Proof, bool) {
	codeVerdicts.Lock()
	defer codeVerdicts.Unlock()
	entry, ok := codeVerdicts.entries[key]
	if !ok {
		return Code{}, ProofNone, false
	}
	if now.Sub(entry.at) >= codeVerdictLifetime || now.Before(entry.at) {
		dropVerdict(key, entry)
		return Code{}, ProofNone, false
	}
	return entry.code, entry.verdict, true
}

func keepVerdict(key codeVerdictKey, proc windows.Handle, code Code, verdict Proof, now time.Time) {
	self := windows.CurrentProcess()
	var held windows.Handle
	if err := windows.DuplicateHandle(self, proc, self, &held, 0, false, windows.DUPLICATE_SAME_ACCESS); err != nil {
		return
	}
	// The duplicate must name the process the verification pinned.
	if started, err := processStartTime(held); err != nil || started.UnixNano() != key.started {
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
	windows.CloseHandle(entry.proc)
}
