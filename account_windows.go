//go:build windows

package identity

import (
	"sync"
	"time"

	"golang.org/x/sys/windows"
)

// accountName is sid.LookupAccount with a short memory.
//
// The lookup is an LSA call of about 250 us, more than half of binding a pipe
// connection (measured 2026-09-17). Its answer is display text: the identity
// is the SID, which is read from the peer's token for every connection and
// never comes from here. A remembered name is at most accountNameLifetime old,
// so a renamed account shows its old name for that long. Failed lookups are
// not remembered.
const (
	accountNameLifetime = time.Minute
	accountNameLimit    = 64
)

type accountNameEntry struct {
	name, domain string
	at           time.Time
}

var accountNames = struct {
	sync.Mutex
	entries map[string]accountNameEntry
}{entries: map[string]accountNameEntry{}}

func accountName(sid *windows.SID) (name, domain string, err error) {
	key := sid.String()
	now := time.Now()
	accountNames.Lock()
	entry, ok := accountNames.entries[key]
	accountNames.Unlock()
	if ok && now.Sub(entry.at) < accountNameLifetime && !now.Before(entry.at) {
		return entry.name, entry.domain, nil
	}
	name, domain, _, err = sid.LookupAccount("")
	if err != nil {
		return "", "", err
	}
	accountNames.Lock()
	defer accountNames.Unlock()
	if len(accountNames.entries) >= accountNameLimit {
		clear(accountNames.entries)
	}
	accountNames.entries[key] = accountNameEntry{name: name, domain: domain, at: now}
	return name, domain, nil
}
