package integrity

import (
	"strconv"
	"strings"
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Run under -race, or -gcflags=all=-d=checkptr=1 where there is no C compiler:
// the reader this test exercises is the one that killed the process outright
// while the arithmetic was done by advapi32 behind a bare uintptr.
func TestTheIntegrityRIDIsTheLastComponentOfTheLabelSID(t *testing.T) {
	tok := windows.Token(windows.GetCurrentProcessToken())
	rid, ok := RID(tok)
	if !ok {
		t.Fatal("the current process token reported no readable mandatory label")
	}
	sid := labelSID(t, tok)
	last := sid[strings.LastIndex(sid, "-")+1:]
	want, err := strconv.ParseUint(last, 10, 32)
	if err != nil {
		t.Fatalf("label SID %q does not end in a number: %v", sid, err)
	}
	if uint32(want) != rid {
		t.Fatalf("RID read %#x, and the label SID %s says %#x", rid, sid, want)
	}
}

func TestASIDIsReadNoFurtherThanItsOwnBytes(t *testing.T) {
	medium := []byte{1, 1, 0, 0, 0, 0, 0, 16, 0x00, 0x20, 0x00, 0x00}
	for _, c := range []struct {
		name string
		sid  []byte
		want uint32
		ok   bool
	}{
		{"the medium mandatory level", medium, 0x2000, true},
		{"two sub-authorities, and the last one is the answer", []byte{1, 2, 0, 0, 0, 0, 0, 5, 0x20, 0, 0, 0, 0x21, 0x02, 0, 0}, 0x221, true},
		{"a header with no sub-authority after it", medium[:8], 0, false},
		{"a header cut short", medium[:7], 0, false},
		{"a count of four with one sub-authority present", []byte{1, 4, 0, 0, 0, 0, 0, 16, 0x00, 0x20, 0x00, 0x00}, 0, false},
		{"a revision this reader does not know", []byte{2, 1, 0, 0, 0, 0, 0, 16, 0x00, 0x20, 0x00, 0x00}, 0, false},
		{"nothing at all", nil, 0, false},
	} {
		t.Run(c.name, func(t *testing.T) {
			got, ok := lastSubAuthorityOf(c.sid)
			if ok != c.ok || got != c.want {
				t.Fatalf("read %#x, %v; wanted %#x, %v", got, ok, c.want, c.ok)
			}
		})
	}
}

func TestASIDPointingPastTheBufferIsRefused(t *testing.T) {
	whole := make([]byte, 64)
	copy(whole[32:], []byte{1, 1, 0, 0, 0, 0, 0, 16, 0x00, 0x20, 0x00, 0x00})
	if _, ok := lastSubAuthority(whole[:16], (*windows.SID)(unsafe.Pointer(&whole[32]))); ok {
		t.Fatal("a SID 32 bytes past a 16 byte buffer was read as if it were inside it")
	}
	if _, ok := lastSubAuthority(whole, nil); ok {
		t.Fatal("a label with no SID was read as if it had one")
	}
}

// ConvertSidToStringSid writes through an out parameter, so this second reading
// of the same label owes nothing to the one under test.
func labelSID(t *testing.T, tok windows.Token) string {
	t.Helper()
	var n uint32
	windows.GetTokenInformation(tok, windows.TokenIntegrityLevel, nil, 0, &n)
	if n == 0 {
		t.Fatal("TokenIntegrityLevel reported a zero length buffer")
	}
	buf := make([]byte, n)
	if err := windows.GetTokenInformation(tok, windows.TokenIntegrityLevel, &buf[0], n, &n); err != nil {
		t.Fatalf("GetTokenInformation(TokenIntegrityLevel): %v", err)
	}
	return (*windows.Tokenmandatorylabel)(unsafe.Pointer(&buf[0])).Label.Sid.String()
}
