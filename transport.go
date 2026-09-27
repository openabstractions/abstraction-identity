package identity

import "fmt"

// Transport selects the channel whose identity limits are being queried.
type Transport string

const (
	TransportNative    Transport = ""
	TransportUnix      Transport = "unix"
	TransportNamedPipe Transport = "npipe"
	TransportXPC       Transport = "xpc"
)

// CeilingFor reports the selected transport's capabilities without opening a
// connection. Unsupported transports return an error, including for empty policy.
// Ceiling retains its existing meaning: the default native stream transport.
func CeilingFor(transport Transport) (Limits, error) {
	if transport == TransportXPC {
		return xpcCeiling()
	}
	limits := Ceiling()
	if transport == TransportNative || string(transport) == limits.Transport {
		return limits, nil
	}
	return Limits{}, fmt.Errorf("%w: identity transport %q is unavailable on %s", ErrUnsupportedConn, transport, limits.Platform)
}

func xpcLimits() Limits {
	return Limits{
		Platform: "darwin", Transport: string(TransportXPC), Bindable: true,
		Binding: "validated XPC message and its remote connection",
		Best:    Need{User: ProofKernel, Process: ProofKernel, Path: ProofBound},
		Why: map[string]string{
			"user":    "credentials of the exact message's remote connection",
			"process": "process of the exact message's remote connection, checked against message-bound code",
			"path":    "validated message code's main executable agrees with the sender process path",
			"package": "no trusted publisher policy is configured",
			"code":    "code validity alone does not establish trusted publisher identity",
		},
	}
}
