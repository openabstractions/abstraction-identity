package integrity

import (
	"encoding/binary"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	sidRevision            = 1
	sidRevisionAt          = 0
	sidSubAuthorityCountAt = 1
	sidSubAuthorityAt      = 8
	sidSubAuthoritySize    = 4
)

// RID returns the token's integrity level, which is the last sub-authority of
// its mandatory label SID. It reports false when the token carries no readable
// label; every caller treats that as a display detail lost, never as an
// identity in doubt.
func RID(tok windows.Token) (uint32, bool) {
	var n uint32
	windows.GetTokenInformation(tok, windows.TokenIntegrityLevel, nil, 0, &n)
	if n == 0 {
		return 0, false
	}
	buf := make([]byte, n)
	if err := windows.GetTokenInformation(tok, windows.TokenIntegrityLevel, &buf[0], n, &n); err != nil {
		return 0, false
	}
	label := (*windows.Tokenmandatorylabel)(unsafe.Pointer(&buf[0]))
	return lastSubAuthority(buf, label.Label.Sid)
}

// A TOKEN_MANDATORY_LABEL names a SID that lies inside the same buffer
// GetTokenInformation just filled, so the SID is read as bytes of that slice.
// x/sys/windows.(*SID).SubAuthorityCount cannot be used instead: it turns
// advapi32's return address - a bare uintptr with no Go allocation behind it -
// back into a pointer, and under -race the runtime kills the process for it.
func lastSubAuthority(buf []byte, sid *windows.SID) (uint32, bool) {
	if sid == nil {
		return 0, false
	}
	at := uintptr(unsafe.Pointer(sid)) - uintptr(unsafe.Pointer(&buf[0]))
	if at >= uintptr(len(buf)) {
		return 0, false
	}
	return lastSubAuthorityOf(buf[at:])
}

func lastSubAuthorityOf(sid []byte) (uint32, bool) {
	if len(sid) < sidSubAuthorityAt || sid[sidRevisionAt] != sidRevision {
		return 0, false
	}
	n := int(sid[sidSubAuthorityCountAt])
	if n == 0 || len(sid) < sidSubAuthorityAt+n*sidSubAuthoritySize {
		return 0, false
	}
	return binary.LittleEndian.Uint32(sid[sidSubAuthorityAt+(n-1)*sidSubAuthoritySize:]), true
}
