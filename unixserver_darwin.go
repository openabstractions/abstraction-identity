//go:build darwin

package identity

import "fmt"

// macOS has no server binding for a dialed AF_UNIX socket. LOCAL_PEERCRED on
// the client end carries the listener's credentials from listen(2), but
// LOCAL_PEERPID and LOCAL_PEERTOKEN follow whichever process last wrote to the
// server's accepted socket, the defeat ID-M1 records for accepted sockets. The
// process behind the far end is therefore known only at ProofPID, below the
// bound process a provider checks against the engine it started (inference
// CONTRACT.md INF-EL2), so the binding refuses rather than answering from a
// number, as BindLoopback does on this platform.
const unixServerDarwinWhy = "macOS has no record that pins the process listening behind a dialed AF_UNIX socket: LOCAL_PEERPID and LOCAL_PEERTOKEN follow the server socket's most recent writer (ID-M1)"

func bindUnixServer(Handle, *Options) (binder, *Peer, error) {
	return nil, nil, fmt.Errorf("%w: %s", ErrNoBinding, unixServerDarwinWhy)
}
