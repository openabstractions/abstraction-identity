//go:build darwin

package identity

import (
	"fmt"
	"net/netip"
)

// macOS keeps the recorded identity refusal for loopback TCP. The per-socket
// process record, so_last_pid, follows the most recent writer, the defeat
// measured for AF_UNIX in probe-evidence.txt, and a descriptor-table read per
// pid answers about a number after the fact. No primitive pins the process that
// opened a loopback connection, so the binding refuses rather than answering
// from a number.
const loopbackDarwinWhy = "macOS has no socket-owner record that pins the process behind a loopback TCP connection: per-socket process ids follow the most recent writer, and protected calls keep the recorded identity refusal"

func loopbackCeiling() Limits {
	return Limits{
		Platform:  "darwin",
		Transport: TransportLoopback,
		Bindable:  false,
		Binding:   loopbackDarwinWhy,
		Stronger:  "xpc: messages carry an audit token the kernel stamped on the sending task",
		Best:      Need{},
		Why: map[string]string{
			"user":    loopbackDarwinWhy,
			"process": loopbackDarwinWhy,
			"path":    loopbackDarwinWhy,
			"package": loopbackDarwinWhy,
			"code":    loopbackDarwinWhy,
		},
	}
}

func bindLoopback(client, server netip.AddrPort, opts *Options) (binder, *Peer, error) {
	return nil, nil, fmt.Errorf("%w: %s", ErrNoBinding, loopbackDarwinWhy)
}
