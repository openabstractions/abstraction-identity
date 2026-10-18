package identity

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"time"
)

// ErrBeyondLoopback reports a socket of a contained process tree bound to an
// address other than loopback, or a tree whose own listener could not be
// observed in the owner tables.
var ErrBeyondLoopback = errors.New("identity: process tree listens beyond loopback")

// Socket is one listening TCP socket or bound UDP socket and the process id
// the operating system's owner table names for it.
type Socket struct {
	Proto string // "tcp" or "udp"
	Addr  netip.Addr
	Port  int
	PID   int
}

// TreeContains answers whether the process with this id and creation time is
// a member of a contained process tree, for example a supervised job's
// Contains method. The creation time distinguishes a reused process id.
type TreeContains func(pid int, started time.Time) (bool, error)

// CheckTreeLoopback reads the socket owner tables and applies
// [CheckLoopbackOnly] to the tree contains describes, whose own listener is
// listener. It is the Get-NetTCPConnection and Get-NetUDPEndpoint view of one
// process tree, with membership proved by process id and creation time.
func CheckTreeLoopback(listener netip.AddrPort, contains TreeContains) error {
	sockets, err := Sockets()
	if err != nil {
		return fmt.Errorf("%w: owner tables: %v", ErrBeyondLoopback, err)
	}
	return CheckLoopbackOnly(sockets, OwnedByTree(contains), listener)
}

// OwnedByTree turns a tree's membership answer into a per-process-id test. It
// reads the process's creation time and asks contains about that exact
// process; a process that cannot be opened, has exited or answers an error is
// not a member.
func OwnedByTree(contains TreeContains) func(pid int) bool {
	return func(pid int) bool {
		if pid <= 0 || contains == nil {
			return false
		}
		started, err := processCreation(pid)
		if err != nil {
			return false
		}
		in, err := contains(pid, started)
		return err == nil && in
	}
}

// CheckLoopbackOnly accepts sockets only when every socket owned by the tree
// is bound to a loopback address (127.0.0.0/8 or ::1, IPv4-mapped forms
// unmapped first) and the tree holds the TCP listener at listener. Requiring
// that listener proves the table was read: an empty table never passes.
// Membership is asked only where it decides the answer, for sockets beyond
// loopback and for the expected listener.
func CheckLoopbackOnly(sockets []Socket, owned func(pid int) bool, listener netip.AddrPort) error {
	membership := map[int]bool{}
	member := func(pid int) bool {
		in, seen := membership[pid]
		if !seen {
			in = pid > 0 && owned(pid)
			membership[pid] = in
		}
		return in
	}
	want := netip.AddrPortFrom(listener.Addr().Unmap(), listener.Port())
	expected := false
	for _, s := range sockets {
		addr := s.Addr.Unmap()
		if !addr.IsLoopback() {
			if member(s.PID) {
				return fmt.Errorf("%w: %s %s owned by process %d", ErrBeyondLoopback, s.Proto, netip.AddrPortFrom(addr, uint16(s.Port)), s.PID)
			}
			continue
		}
		if !expected && s.Proto == "tcp" && netip.AddrPortFrom(addr, uint16(s.Port)) == want && member(s.PID) {
			expected = true
		}
	}
	if !expected {
		return fmt.Errorf("%w: the tree's listener on %s was not observed", ErrBeyondLoopback, want)
	}
	return nil
}

// The Windows owner tables are MIB_TCPTABLE_OWNER_PID, MIB_TCP6TABLE_OWNER_PID,
// MIB_UDPTABLE_OWNER_PID and MIB_UDP6TABLE_OWNER_PID: a DWORD row count, then
// rows of DWORDs and byte arrays with no padding. Addresses are in network
// order; each port is the first two bytes of its DWORD, in network order. The
// parser is portable so its tests run everywhere.

type ownerTableLayout struct {
	proto     string
	rowSize   int
	addrAt    int
	addrBytes int
	portAt    int
	pidAt     int
}

var (
	tcp4OwnerLayout = ownerTableLayout{proto: "tcp", rowSize: 24, addrAt: 4, addrBytes: 4, portAt: 8, pidAt: 20}
	tcp6OwnerLayout = ownerTableLayout{proto: "tcp", rowSize: 56, addrAt: 0, addrBytes: 16, portAt: 20, pidAt: 52}
	udp4OwnerLayout = ownerTableLayout{proto: "udp", rowSize: 12, addrAt: 0, addrBytes: 4, portAt: 4, pidAt: 8}
	udp6OwnerLayout = ownerTableLayout{proto: "udp", rowSize: 28, addrAt: 0, addrBytes: 16, portAt: 20, pidAt: 24}
)

func parseOwnerTable(buf []byte, layout ownerTableLayout) ([]Socket, error) {
	if len(buf) < 4 {
		return nil, errors.New("owner table shorter than its count")
	}
	count := int(binary.LittleEndian.Uint32(buf))
	rows := buf[4:]
	if count < 0 || count > len(rows)/layout.rowSize {
		return nil, errors.New("owner table count exceeds its buffer")
	}
	sockets := make([]Socket, 0, count)
	for i := 0; i < count; i++ {
		row := rows[i*layout.rowSize : (i+1)*layout.rowSize]
		addr, ok := netip.AddrFromSlice(row[layout.addrAt : layout.addrAt+layout.addrBytes])
		if !ok {
			return nil, errors.New("owner table address")
		}
		port := int(row[layout.portAt])<<8 | int(row[layout.portAt+1])
		pid := int(binary.LittleEndian.Uint32(row[layout.pidAt:]))
		sockets = append(sockets, Socket{Proto: layout.proto, Addr: addr, Port: port, PID: pid})
	}
	return sockets, nil
}
