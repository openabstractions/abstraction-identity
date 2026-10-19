package listen

import (
	"errors"
	"strings"
)

// SameEndpointName compares names, not connections, server identities or
// filesystem aliases. Windows uses native ordinal name comparison; Unix uses
// exact bytes. It performs no normalization, connection or I/O. Invalid names
// or unavailable native comparison evidence return an error.
func SameEndpointName(a, b string) (bool, error) {
	if a == "" || b == "" || strings.IndexByte(a, 0) >= 0 || strings.IndexByte(b, 0) >= 0 {
		return false, errors.New("endpoint names must be nonempty and contain no NUL")
	}
	return sameEndpointName(a, b)
}
