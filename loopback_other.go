//go:build !windows && !darwin && !linux

package identity

import "net/netip"

func loopbackCeiling() Limits {
	l := ceiling()
	l.Transport = TransportLoopback
	return l
}

func bindLoopback(client, server netip.AddrPort, opts *Options) (binder, *Peer, error) {
	return nil, nil, ErrUnimplemented
}
