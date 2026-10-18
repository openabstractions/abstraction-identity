//go:build !windows

package identity

import "os"

// self is the effective uid and gid, the credentials a socket peer's
// SO_PEERCRED or getpeereid reports.
func self() (User, error) {
	return User{Kind: "posix", UID: os.Geteuid(), GID: os.Getegid()}, nil
}
