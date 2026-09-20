//go:build windows

package identity

import (
	"errors"
	"fmt"
	"net/netip"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// The Windows loopback binding reads the TCP owner table.
//
// Windows records, for each TCP connection, the process id that created the
// socket, and GetExtendedTcpTable returns it beside the four-tuple. The number
// is not stamped onto the connection the way a pipe's client process id is; it
// is the table's record of the creator, and a handle to the socket can be
// duplicated into another process that then does the talking while the table
// still names the creator. So the binding pins the creator with a process
// handle, as bind_windows.go does for pipes, and treats one observation as a
// contradiction: the creator has exited while the client end is still
// established. A socket outlives the process that created it only when another
// process holds it, and that process is not the one the table names.
//
// A creator that is alive and has handed a duplicate to a second process is not
// visible here, the same limit the pipe binding documents: the answer is the
// process that opened the connection.

var (
	modiphlpapi             = windows.NewLazySystemDLL("iphlpapi.dll")
	procGetExtendedTcpTable = modiphlpapi.NewProc("GetExtendedTcpTable")
)

const (
	tcpTableOwnerPIDConnections = 4 // TCP_TABLE_OWNER_PID_CONNECTIONS
	mibTCPStateEstablished      = 5 // MIB_TCP_STATE_ESTAB
	errorInsufficientBuffer     = 122
)

type mibTCPRowOwnerPID struct {
	State      uint32
	LocalAddr  uint32
	LocalPort  uint32
	RemoteAddr uint32
	RemotePort uint32
	OwningPID  uint32
}

type tcpOwner struct {
	pid         uint32
	established bool
}

func (r *mibTCPRowOwnerPID) local() netip.AddrPort {
	return netip.AddrPortFrom(netip.AddrFrom4(*(*[4]byte)(unsafe.Pointer(&r.LocalAddr))), tablePort(r.LocalPort))
}

func (r *mibTCPRowOwnerPID) remote() netip.AddrPort {
	return netip.AddrPortFrom(netip.AddrFrom4(*(*[4]byte)(unsafe.Pointer(&r.RemoteAddr))), tablePort(r.RemotePort))
}

// tablePort converts a port the table stores in network byte order in the low
// 16 bits of a DWORD.
func tablePort(p uint32) uint16 { return uint16(p&0xff)<<8 | uint16(p>>8&0xff) }

// ownerOf finds the row whose local end is client and remote end is server. A
// missing row returns ok false.
func ownerOf(client, server netip.AddrPort) (tcpOwner, bool, error) {
	size := uint32(64 * 1024)
	for attempt := 0; attempt < 8; attempt++ {
		buf := make([]byte, size)
		r, _, _ := procGetExtendedTcpTable.Call(uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&size)), 0, windows.AF_INET, tcpTableOwnerPIDConnections, 0)
		if r == errorInsufficientBuffer {
			size += 16 * 1024
			continue
		}
		if r != 0 {
			return tcpOwner{}, false, fmt.Errorf("GetExtendedTcpTable: %w", windows.Errno(r))
		}
		n := *(*uint32)(unsafe.Pointer(&buf[0]))
		rowSize := unsafe.Sizeof(mibTCPRowOwnerPID{})
		if uintptr(n)*rowSize+4 > uintptr(len(buf)) {
			return tcpOwner{}, false, errors.New("GetExtendedTcpTable: table larger than its buffer")
		}
		for i := uintptr(0); i < uintptr(n); i++ {
			row := (*mibTCPRowOwnerPID)(unsafe.Pointer(&buf[4+i*rowSize]))
			if row.local() == client && row.remote() == server {
				return tcpOwner{pid: row.OwningPID, established: row.State == mibTCPStateEstablished}, true, nil
			}
		}
		return tcpOwner{}, false, nil
	}
	return tcpOwner{}, false, errors.New("GetExtendedTcpTable: the table kept growing")
}

func loopbackCeiling() Limits {
	return Limits{
		Platform:  "windows",
		Transport: TransportLoopback,
		Bindable:  true,
		Binding:   "the TCP owner table: GetExtendedTcpTable names the process that created the client socket, an open process handle whose creation time predates the connection pins it, and a creator that has exited while the connection is still established is refused as moved",
		Stronger:  "npipe: the kernel names the pipe's client process on the pipe instance itself, and the user comes from the client's own impersonation token at kernel",
		Best: Need{
			User:    ProofBound,
			Process: ProofBound,
			Path:    ProofBound,
			Package: ProofSigned,
			Code:    ProofBound,
		},
		Why: map[string]string{
			"user":    "read from the access token of the pinned creator process; the connection carries no token of its own",
			"process": "the TCP owner table's record of the process that created the client socket, pinned by a process handle whose creation time predates the connection",
			"path":    "the image path is read through the pinned process handle; a path is a name, not an identity",
			"package": "an MSIX package full name read through the pinned process handle",
			"code":    "Authenticode verifies a file, and Windows exposes no way to verify the image a running process executes",
		},
	}
}

type loopbackWindowsBinding struct {
	client, server netip.AddrPort
	proc           windows.Handle
	pid            uint32
	started        time.Time
}

func bindLoopback(client, server netip.AddrPort, opts *Options) (binder, *Peer, error) {
	owner, found, err := ownerOf(client, server)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: %v", ErrNoBinding, err)
	}
	if !found {
		return nil, nil, fmt.Errorf("%w: the TCP owner table has no row for %s -> %s", ErrPeerGone, client, server)
	}
	if owner.pid == 0 {
		return nil, nil, fmt.Errorf("%w: the TCP owner table names no process for %s", ErrNoBinding, client)
	}
	proc, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, owner.pid)
	if err != nil {
		if owner.established {
			return nil, nil, fmt.Errorf("%w: pid %d created the client socket and can no longer be opened (%v), while the connection is still established; another process holds it", ErrPeerMoved, owner.pid, err)
		}
		return nil, nil, fmt.Errorf("%w: pid %d could not be opened (%v)", ErrPeerGone, owner.pid, err)
	}
	b := &loopbackWindowsBinding{client: client, server: server, proc: proc, pid: owner.pid}
	if b.started, err = processStartTime(proc); err != nil {
		b.release()
		return nil, nil, fmt.Errorf("%w: the creator's start time could not be read: %v", ErrNoBinding, err)
	}
	if connectedAt := opts.connectedAt(); b.started.After(connectedAt) {
		b.release()
		return nil, nil, fmt.Errorf("%w: pid %d belongs to a process created at %s, after this connection existed at %s",
			ErrPeerMoved, owner.pid, b.started.Format(time.RFC3339Nano), connectedAt.Format(time.RFC3339Nano))
	}
	// The table is read again with the process pinned, so the pid the row names
	// cannot have been reassigned between the two reads.
	if err := b.recheck(); err != nil {
		b.release()
		return nil, nil, err
	}
	peer, err := b.peer(opts)
	if err != nil {
		b.release()
		return nil, nil, err
	}
	return b, peer, nil
}

func (b *loopbackWindowsBinding) peer(opts *Options) (*Peer, error) {
	p := &Peer{
		Platform:   "windows",
		Transport:  TransportLoopback,
		ObservedAt: time.Now(),
		Package:    unknown[string]("package", "not resolved"),
		Code:       unknown[Code]("code", "not resolved"),
	}
	user, why, err := processUser(b.proc)
	if err != nil {
		return nil, fmt.Errorf("%w: the creator's token could not be read: %v", ErrNoBinding, err)
	}
	p.User = attr("user", user, ProofBound, joinWhy("read from the access token of the process that created the client socket, through a handle that cannot be a recycled pid", why))
	p.Process = attr("process", Process{PID: int(b.pid), StartTime: b.started}, ProofBound,
		"the TCP owner table names the process that created the client socket; its handle is pinned and its creation time predates the connection")
	imagePath, err := processImagePath(b.proc)
	if err != nil {
		return nil, fmt.Errorf("%w: QueryFullProcessImageName: %v", ErrNoBinding, err)
	}
	p.Path = attr("path", imagePath, ProofBound, "read through the pinned process handle; a path is not an identity - see CONTRACT.md")
	if name, err := packageFullName(b.proc); err == nil && name != "" {
		p.Package = attr("package", name, ProofSigned, "an MSIX package full name read through the pinned process handle")
	} else {
		p.Package = unknown[string]("package", "the peer is an ordinary executable, not an MSIX package")
	}
	if opts.skipCodeSignature() {
		p.Code = unknown[Code]("code", "signature verification was skipped by the caller")
	} else if code, verdict, err := verifyProcessImage(b.proc, b.pid, b.started, imagePath, opts); err != nil {
		p.Code = unknown[Code]("code", "verification could not be performed: "+err.Error())
	} else {
		p.recordCode(code, verdict, "Authenticode verified the file at the peer's image path, not the image the peer is executing")
	}
	p.note("transport: a loopback TCP connection carries no credentials; the process came from the TCP owner table")
	return p, nil
}

// processUser reads the principal off a pinned process's primary token.
func processUser(proc windows.Handle) (User, string, error) {
	var tok windows.Token
	if err := windows.OpenProcessToken(proc, windows.TOKEN_QUERY, &tok); err != nil {
		return User{}, "", err
	}
	defer tok.Close()
	u, err := tok.GetTokenUser()
	if err != nil {
		return User{}, "", err
	}
	sid, err := u.User.Sid.Copy()
	if err != nil {
		return User{}, "", err
	}
	rid := tokenIntegrityRID(tok)
	user := User{Kind: "windows", SID: sid.String(), Elevated: tok.IsElevated(), Integrity: integrityName(rid), IntegrityRID: rid, UID: -1, GID: -1}
	why := ""
	if name, domain, err := accountName(sid); err == nil {
		user.Name, user.Domain = name, domain
	} else {
		why = "the SID has no resolvable account name (" + err.Error() + ")"
	}
	return user, why, nil
}

func (b *loopbackWindowsBinding) recheck() error {
	// A missing row is the connection having closed, which contradicts
	// nothing about who opened it.
	owner, found, err := ownerOf(b.client, b.server)
	if err != nil || !found {
		return nil
	}
	if owner.pid != b.pid {
		return fmt.Errorf("%w: the TCP owner table now names pid %d for %s; it named pid %d when the connection was accepted", ErrPeerMoved, owner.pid, b.client, b.pid)
	}
	if started, err := processStartTime(b.proc); err == nil && !started.Equal(b.started) {
		return fmt.Errorf("%w: pid %d was created at %s and is now reported as created at %s", ErrPeerMoved, b.pid, b.started.Format(time.RFC3339Nano), started.Format(time.RFC3339Nano))
	}
	if alive, err := b.alive(); err == nil && !alive && owner.established {
		return fmt.Errorf("%w: pid %d created the client socket and has exited, and the connection is still established; another process holds the socket", ErrPeerMoved, b.pid)
	}
	return nil
}

func (b *loopbackWindowsBinding) alive() (bool, error) {
	var code uint32
	if err := windows.GetExitCodeProcess(b.proc, &code); err != nil {
		return false, err
	}
	return code == stillActive, nil
}

func (b *loopbackWindowsBinding) release() error {
	if b.proc == 0 {
		return nil
	}
	err := windows.CloseHandle(b.proc)
	b.proc = 0
	return err
}
