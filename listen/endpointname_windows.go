package listen

import "github.com/openabstractions/abstraction-identity/internal/winordinal"

func sameEndpointName(a, b string) (bool, error) { return winordinal.EqualIgnoringCase(a, b) }
