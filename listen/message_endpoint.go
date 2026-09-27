package listen

import (
	"errors"
	"strings"

	identity "github.com/openabstractions/abstraction-identity"
)

// Ceiling reports identity capabilities for this endpoint's transport.
// It does not open an endpoint or establish installation trust.
func Ceiling(endpoint string) (identity.Limits, error) {
	service, err := xpcService(endpoint)
	if err != nil {
		return identity.Limits{}, err
	}
	transport := identity.TransportNative
	if service != "" {
		transport = identity.TransportXPC
	}
	return identity.CeilingFor(transport)
}

// CanEver refuses an unsatisfiable endpoint policy before service startup.
func CanEver(endpoint string, need identity.Need) error {
	limits, err := Ceiling(endpoint)
	if err != nil {
		return err
	}
	return limits.CanEver(need)
}

// ListenFramed checks the requested policy before creating its endpoint.
// Receivers must still enforce that policy against each actual request.
func ListenFramed(endpoint string, need identity.Need) (Listener, error) {
	if err := CanEver(endpoint, need); err != nil {
		return nil, err
	}
	return Listen(endpoint)
}

func xpcService(endpoint string) (string, error) {
	service, ok := strings.CutPrefix(endpoint, "xpc:")
	if !ok {
		return "", nil
	}
	if service == "" || len(service) > 255 || strings.ContainsAny(service, "/\\\x00\r\n") {
		return "", errors.New("listen: invalid XPC service name")
	}
	return service, nil
}
