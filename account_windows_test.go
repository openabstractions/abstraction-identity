//go:build windows

package identity

import (
	"testing"
	"time"

	"golang.org/x/sys/windows"
)

// TestAccountNameIsRememberedBriefly requires a remembered display name to match
// a fresh LSA lookup, and an expired one to be looked up again.
func TestAccountNameIsRememberedBriefly(t *testing.T) {
	u, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	sid := u.User.Sid
	want, wantDomain, _, err := sid.LookupAccount("")
	if err != nil {
		t.Skipf("this account has no resolvable name: %v", err)
	}
	accountNames.Lock()
	clear(accountNames.entries)
	accountNames.Unlock()
	for i := 0; i < 2; i++ {
		name, domain, err := accountName(sid)
		if err != nil || name != want || domain != wantDomain {
			t.Fatalf("lookup %d: %q %q %v, want %q %q", i, name, domain, err, want, wantDomain)
		}
	}
	accountNames.Lock()
	entry, ok := accountNames.entries[sid.String()]
	if !ok {
		accountNames.Unlock()
		t.Fatal("the name was not remembered")
	}
	entry.name, entry.at = "stale", entry.at.Add(-accountNameLifetime-time.Second)
	accountNames.entries[sid.String()] = entry
	accountNames.Unlock()
	if name, _, err := accountName(sid); err != nil || name != want {
		t.Fatalf("an expired name was reused: %q %v", name, err)
	}
}
