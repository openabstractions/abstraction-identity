//go:build !windows

package listen

func sameEndpointName(a, b string) (bool, error) { return a == b, nil }
