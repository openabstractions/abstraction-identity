//go:build !windows

package identity

import "errors"

func AdmitServerQueries(...string) (func() error, error) {
	return nil, errors.New("identity: AppContainer server query admission requires Windows")
}
