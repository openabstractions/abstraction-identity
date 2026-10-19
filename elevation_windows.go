//go:build windows

package identity

import (
	"unsafe"

	"golang.org/x/sys/windows"
)

// The token reads behind elevatedToken; tests replace them.
var (
	tokenElevationType = func(tok windows.Token) (uint32, bool) {
		var kind, n uint32
		if err := windows.GetTokenInformation(tok, windows.TokenElevationType, (*byte)(unsafe.Pointer(&kind)), uint32(unsafe.Sizeof(kind)), &n); err != nil {
			return 0, false
		}
		return kind, true
	}
	tokenIsElevated = func(tok windows.Token) bool { return tok.IsElevated() }
)

// readTokenElevated classifies tok by elevatedToken from its elevation type,
// TokenIsElevated and the label already read. An unreadable field reads not
// elevated.
func readTokenElevated(tok windows.Token, label tokenLabel) bool {
	kind, ok := tokenElevationType(tok)
	return ok && label.known && elevatedToken(kind, tokenIsElevated(tok), label.rid)
}

// processElevated reports whether the pinned process's primary token belongs
// to sid and classifies as elevated, unrestricted. A pipe client can present
// an impersonation token other than its own primary token, such as the
// identification-level linked token an admin's limited process can read, so
// the bound attribute requires both tokens. Any failure reads not elevated.
// Tests replace it.
var processElevated = func(proc windows.Handle, sid string) bool {
	var tok windows.Token
	if err := windows.OpenProcessToken(proc, windows.TOKEN_QUERY, &tok); err != nil {
		return false
	}
	defer tok.Close()
	u, err := tok.GetTokenUser()
	if err != nil || u.User.Sid == nil || u.User.Sid.String() != sid {
		return false
	}
	label := readTokenLabel(tok)
	return !label.restricted && readTokenElevated(tok, label)
}
