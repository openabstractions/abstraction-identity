//go:build windows

package identity

import (
	"errors"
	"testing"

	"golang.org/x/sys/windows"
)

// [ID-S1] An unreadable integrity label is never a level: a peer reads
// Integrity "unknown" with RID 0, and Self refuses to answer, since callers
// compare authority with it. An unreadable restricted flag reads restricted.
func TestAnUnreadableTokenLabelIsNeverALevel(t *testing.T) {
	savedRID, savedRestricted := labelRID, tokenRestricted
	t.Cleanup(func() { labelRID, tokenRestricted = savedRID, savedRestricted })
	labelRID = func(windows.Token) (uint32, bool) { return 0, false }
	user, _, err := processUser(windows.CurrentProcess())
	if err != nil || user.Integrity != "unknown" || user.IntegrityRID != 0 {
		t.Fatalf("unreadable label read as %q %#x %v", user.Integrity, user.IntegrityRID, err)
	}
	if _, err := Self(); err == nil {
		t.Fatal("Self answered with an unreadable integrity level")
	}
	labelRID = savedRID
	tokenRestricted = func(windows.Token) (bool, error) { return false, errors.New("unreadable") }
	user, _, err = processUser(windows.CurrentProcess())
	if err != nil || !user.Restricted {
		t.Fatalf("unreadable restricted flag read as %v %v", user.Restricted, err)
	}
	tokenRestricted = savedRestricted
	if user, err := Self(); err != nil || user.Restricted || user.Integrity == "unknown" {
		t.Fatalf("this process: %+v %v", user, err)
	}
	// RID 0 that was read is the untrusted level.
	if integrityName(0) != "untrusted" {
		t.Fatalf("RID 0 named %q", integrityName(0))
	}
}
