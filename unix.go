//go:build linux || darwin

package identity

import "strconv"

// Small shared helpers for the two Unix implementations. Kept here so that the
// platform files read as the argument they are making rather than as string
// formatting.

func itoa(i int) string { return strconv.Itoa(i) }

func strconvQuote(s string) string { return strconv.Quote(s) }
