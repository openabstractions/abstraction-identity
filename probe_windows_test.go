//go:build windows

package identity

import (
	"errors"
	"testing"
	"time"

	"golang.org/x/sys/windows"
)

// TestWindowsWillNotIdentifyUntilTheServerHasRead records the precondition
// that shapes every service built on this package, because it is not obvious
// and it cannot be worked around: Windows refuses to impersonate the client of
// a named pipe until the server has completed a read on that pipe. The
// client's write is not enough - the server has to have read.
//
// A service therefore has to accept bytes from a caller it cannot yet name.
// That is the reason the rest of this package is so insistent that the bytes
// are a request and never a claim about who is making it.
func TestWindowsWillNotIdentifyUntilTheServerHasRead(t *testing.T) {
	setup := func(label string, write, read bool) error {
		name := pipeName(t) + "-" + label
		server := listen(t, name)
		client := dial(t, name)
		accept(t, server)
		if write {
			var n uint32
			if err := windows.WriteFile(client, []byte("hello"), &n, nil); err != nil {
				t.Fatalf("%s: write: %v", label, err)
			}
			// Give the write time to land, so that a pass in the
			// "written but not read" case cannot be explained by the
			// bytes simply not having arrived.
			time.Sleep(50 * time.Millisecond)
		}
		if read {
			buf := make([]byte, 16)
			var n uint32
			if err := windows.ReadFile(server, buf, &n, nil); err != nil {
				t.Fatalf("%s: read: %v", label, err)
			}
		}
		_, err := OfHandle(Handle(server), &Options{ConnectedAt: time.Now()})
		return err
	}

	if err := setup("silent", false, false); !errors.Is(err, ErrMustReadFirst) {
		t.Errorf("a connected but silent peer: got %v, want ErrMustReadFirst", err)
	}
	if err := setup("written-not-read", true, false); !errors.Is(err, ErrMustReadFirst) {
		t.Errorf("peer wrote but server has not read: got %v, want ErrMustReadFirst "+
			"(if this now succeeds, Windows changed and CONTRACT.md is out of date)", err)
	}
	if err := setup("written-and-read", true, true); err != nil {
		t.Errorf("after the server read, identification should work: %v", err)
	}
}
