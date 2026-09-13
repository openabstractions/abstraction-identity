package identity

// SO_PEERCRED and SO_PEERPIDFD also identify the peer of a connected client
// socket. Reuse the retained pidfd and exec recheck of the receiving boundary.
func bindServerHandle(h Handle, opts *Options) (binder, *Peer, error) {
	return bindHandle(h, opts)
}
