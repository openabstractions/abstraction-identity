package identity

import (
	"unicode/utf16"
	"unicode/utf8"
	"unsafe"

	"golang.org/x/sys/windows"
)

// CompareStringOrdinal with bIgnoreCase compares UTF-16 code units after
// mapping each through the system uppercase table, the table NTFS compares
// file names with. It returns CSTR_EQUAL (2) for equal strings.
var procCompareStringOrdinal = modkernel32.NewProc("CompareStringOrdinal")

const cstrEqual = 2

// ordinalEqualIgnoringCase compares a and b as the file system compares
// names. The system table maps code unit to code unit, so names of different
// UTF-16 length are never equal. Text that is not valid UTF-8 compares byte
// for byte: two different invalid sequences must not meet as U+FFFD.
func ordinalEqualIgnoringCase(a, b string) bool {
	if !utf8.ValidString(a) || !utf8.ValidString(b) {
		return a == b
	}
	a16, b16 := utf16.Encode([]rune(a)), utf16.Encode([]rune(b))
	if len(a16) != len(b16) {
		return false
	}
	if len(a16) == 0 {
		return true
	}
	r, _, _ := procCompareStringOrdinal.Call(uintptr(unsafe.Pointer(&a16[0])), uintptr(len(a16)),
		uintptr(unsafe.Pointer(&b16[0])), uintptr(len(b16)), 1)
	return r == cstrEqual
}

// RtlUpcaseUnicodeChar maps one UTF-16 code unit through the system
// uppercase table, the table CompareStringOrdinal ignores case with.
var procRtlUpcaseUnicodeChar = windows.NewLazySystemDLL("ntdll.dll").NewProc("RtlUpcaseUnicodeChar")

// upcaseKey is PathNameKey on Windows. Text that is not valid UTF-8 keys as
// itself, as ordinalEqualIgnoringCase compares it byte for byte.
func upcaseKey(p string) string {
	if !utf8.ValidString(p) {
		return p
	}
	units := utf16.Encode([]rune(p))
	for i, u := range units {
		r, _, _ := procRtlUpcaseUnicodeChar.Call(uintptr(u))
		units[i] = uint16(r)
	}
	return string(utf16.Decode(units))
}

func init() {
	samePathName = ordinalEqualIgnoringCase
	pathNameKey = upcaseKey
}
