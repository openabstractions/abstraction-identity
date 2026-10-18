package identity

// Self returns the principal the operating system attributes to the calling
// process [ID-S1]: on Windows the primary token's user SID, elevation and
// mandatory integrity level, on Linux and macOS the effective uid and gid.
// It reads this process's own token or credentials and never a peer. A
// service compares a peer's kernel-proven User with it to decide whether the
// peer holds at least the service's own authority.
func Self() (User, error) { return self() }
