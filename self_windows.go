//go:build windows

package identity

import (
	"errors"

	"golang.org/x/sys/windows"
)

// self reads the current process's primary token the way a peer's process
// token is read (processUser). An unreadable integrity label is an error:
// a caller compares authority with this answer (ID-S1).
func self() (User, error) {
	user, _, err := processUser(windows.CurrentProcess())
	if err != nil {
		return User{}, err
	}
	if user.Integrity == "unknown" {
		return User{}, errors.New("identity: this process's integrity level could not be read")
	}
	return user, nil
}
