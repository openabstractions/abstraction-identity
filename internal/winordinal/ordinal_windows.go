// Package winordinal owns the raw Windows ordinal name comparison primitive.
package winordinal

import (
	"errors"
	"fmt"
	"unicode/utf16"
	"unicode/utf8"
	"unsafe"

	"golang.org/x/sys/windows"
)

var ordinal = windows.NewLazySystemDLL("kernel32.dll").NewProc("CompareStringOrdinal")
var compareOrdinal = systemOrdinal

func systemOrdinal(a, b []uint16) (uintptr, error) {
	if err := ordinal.Find(); err != nil {
		return 0, err
	}
	r, _, err := ordinal.Call(uintptr(unsafe.Pointer(&a[0])), uintptr(len(a)),
		uintptr(unsafe.Pointer(&b[0])), uintptr(len(b)), 1)
	return r, err
}

// EqualIgnoringCase compares UTF-16 code units through the system uppercase
// table. It normalizes nothing and reports unavailable native evidence.
func EqualIgnoringCase(a, b string) (bool, error) {
	if !utf8.ValidString(a) || !utf8.ValidString(b) {
		return false, errors.New("ordinal name comparison requires valid UTF-8")
	}
	a16, b16 := utf16.Encode([]rune(a)), utf16.Encode([]rune(b))
	if len(a16) != len(b16) {
		return false, nil
	}
	if len(a16) == 0 {
		return true, nil
	}
	r, err := compareOrdinal(a16, b16)
	switch r {
	case 1, 3:
		return false, nil
	case 2:
		return true, nil
	}
	if err != nil && err != windows.ERROR_SUCCESS {
		return false, fmt.Errorf("native ordinal name comparison: %w", err)
	}
	return false, errors.New("native ordinal name comparison is unavailable")
}
