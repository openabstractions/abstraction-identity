//go:build windows

package identity

import (
	"golang.org/x/sys/windows"
	"testing"
)

func TestServerQueryEntriesHaveOnlyExplicitQueryMasks(t *testing.T) {
	sid, err := windows.StringToSid("S-1-15-2-1-2-3-4-5-6-7")
	if err != nil {
		t.Fatal(err)
	}
	for _, mask := range []windows.ACCESS_MASK{windows.PROCESS_QUERY_LIMITED_INFORMATION, windows.TOKEN_QUERY} {
		entries := serverQueryEntries([]*windows.SID{sid}, mask)
		if len(entries) != 1 || entries[0].AccessPermissions != mask || entries[0].Inheritance != 0 || entries[0].AccessMode != windows.GRANT_ACCESS {
			t.Fatalf("query ACE = %+v", entries)
		}
	}
}
