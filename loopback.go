package identity

import (
	"fmt"
	"net"
	"net/netip"
	"time"
)

// TransportLoopback names a loopback TCP connection in Peer.Transport and
// Limits.Transport.
const TransportLoopback = "tcp-loopback"

// BindLoopback binds the process on the other end of an accepted IPv4 loopback
// TCP connection, through the operating system's socket-owner table.
//
// A loopback socket carries no peer credentials: the kernel stamps nothing onto
// the connection that names the process at the other end. What it does keep is
// a table of the sockets each process owns. The binding looks the client's end
// of this connection up in that table, pins the process it names, and refuses
// afterwards when the table stops agreeing:
//
//   - Windows: GetExtendedTcpTable with TCP_TABLE_OWNER_PID_CONNECTIONS names
//     the process that created the client socket. The binding opens that
//     process, requires its creation time to predate the connection, and
//     refuses with [ErrPeerMoved] once the process has exited while the
//     connection is still established, because another process then holds
//     the socket.
//   - Linux: /proc/net/tcp names the socket inode and its owning uid, and the
//     binding finds the one same-uid process whose descriptor table holds that
//     inode, pins it with pidfd_open and captures its image path. A socket held
//     by two processes, or later held by a different one, is [ErrPeerMoved].
//   - macOS: [ErrNoBinding]. The recorded identity refusal stands; see
//     [LoopbackCeiling].
//
// Call it on the line after accept, before the service reads a byte, and
// re-check with [Binding.Peer] before acting. c must be the accepted end: this
// function cannot tell a connection the service dialed from one it accepted,
// and a dialed connection would name the listening service. The returned
// Binding must be closed before c.
func BindLoopback(c net.Conn, opts *Options) (*Binding, error) {
	tcp, ok := c.(*net.TCPConn)
	if !ok {
		return nil, fmt.Errorf("%w: not a TCP connection", ErrUnsupportedConn)
	}
	server, err := loopbackAddr(tcp.LocalAddr())
	if err != nil {
		return nil, err
	}
	client, err := loopbackAddr(tcp.RemoteAddr())
	if err != nil {
		return nil, err
	}
	inner, peer, err := bindLoopback(client, server, opts)
	if err != nil {
		return nil, err
	}
	return &Binding{peer: peer, boundAt: time.Now(), inner: inner}, nil
}

// LoopbackCeiling reports what this platform can prove at best about the
// process behind a loopback TCP connection. It does not depend on any
// connection.
func LoopbackCeiling() Limits { return loopbackCeiling() }

// Rung is the compact proof summary a decision records: the transport, the
// platform, and the proof of the user, process and path attributes.
func (p *Peer) Rung() string {
	return fmt.Sprintf("%s/%s user=%s process=%s path=%s", p.Transport, p.Platform, p.User.Proof(), p.Process.Proof(), p.Path.Proof())
}

func loopbackAddr(a net.Addr) (netip.AddrPort, error) {
	tcp, ok := a.(*net.TCPAddr)
	if !ok {
		return netip.AddrPort{}, fmt.Errorf("%w: not a TCP address", ErrUnsupportedConn)
	}
	addr, ok := netip.AddrFromSlice(tcp.IP)
	if !ok {
		return netip.AddrPort{}, fmt.Errorf("%w: unreadable address %s", ErrUnsupportedConn, tcp.IP)
	}
	addr = addr.Unmap()
	if !addr.Is4() || !addr.IsLoopback() {
		return netip.AddrPort{}, fmt.Errorf("%w: %s is not an IPv4 loopback address", ErrRemotePeer, addr)
	}
	return netip.AddrPortFrom(addr, uint16(tcp.Port)), nil
}
