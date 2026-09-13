//go:build !windows && !linux

package identity

// Requested server program proof remains unavailable on this transport.
// In particular, macOS socket identity retains its documented proof ceiling.
func bindServerHandle(h Handle, opts *Options) (binder, *Peer, error) {
	return nil, nil, ErrNoBinding
}
