//go:build linux

package identity

// On Linux the peer credentials of a connected client socket name the
// process that listens at the far end, so the accepted-socket bind is the
// server bind: requireAcceptedUnixSocket refuses only a listening socket.
func bindUnixServer(h Handle, opts *Options) (binder, *Peer, error) {
	return bindHandle(h, opts)
}
