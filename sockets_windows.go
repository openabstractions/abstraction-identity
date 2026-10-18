//go:build windows

package identity

import (
	"errors"
	"fmt"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

var procGetExtendedUdpTable = modiphlpapi.NewProc("GetExtendedUdpTable")

const (
	tcpTableOwnerPIDListener = 3 // TCP_TABLE_OWNER_PID_LISTENER
	tcpTableOwnerPIDAll      = 5 // TCP_TABLE_OWNER_PID_ALL
	udpTableOwnerPID         = 1 // UDP_TABLE_OWNER_PID
)

// Sockets reads every listening TCP socket and bound UDP socket, IPv4 and
// IPv6, with its owning process id, from iphlpapi's owner tables.
func Sockets() ([]Socket, error) { return ownedSockets(tcpTableOwnerPIDListener) }

// AllSockets reads every TCP socket in any state, listening, connecting,
// established and closing alike, and every bound UDP socket, IPv4 and IPv6,
// with its owning process id (ID-T7). An outbound connection is in it with
// its local address.
func AllSockets() ([]Socket, error) { return ownedSockets(tcpTableOwnerPIDAll) }

func ownedSockets(tcpClass uint32) ([]Socket, error) {
	var all []Socket
	for _, table := range []struct {
		proc   *windows.LazyProc
		family uint32
		class  uint32
		layout ownerTableLayout
	}{
		{procGetExtendedTcpTable, windows.AF_INET, tcpClass, tcp4OwnerLayout},
		{procGetExtendedTcpTable, windows.AF_INET6, tcpClass, tcp6OwnerLayout},
		{procGetExtendedUdpTable, windows.AF_INET, udpTableOwnerPID, udp4OwnerLayout},
		{procGetExtendedUdpTable, windows.AF_INET6, udpTableOwnerPID, udp6OwnerLayout},
	} {
		buf, err := readOwnerTable(table.proc, table.family, table.class)
		if err != nil {
			return nil, err
		}
		sockets, err := parseOwnerTable(buf, table.layout)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", table.proc.Name, err)
		}
		all = append(all, sockets...)
	}
	return all, nil
}

func readOwnerTable(proc *windows.LazyProc, family, class uint32) ([]byte, error) {
	size := uint32(16 << 10)
	for attempt := 0; attempt < 8; attempt++ {
		buf := make([]byte, size)
		//unchecked: Call's error is the raw GetLastError, not meaningful without a failed primary return, which is checked below
		r, _, _ := proc.Call(uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&size)), 0, uintptr(family), uintptr(class), 0)
		switch r {
		case 0:
			if int(size) > len(buf) {
				return nil, fmt.Errorf("%s: table larger than its buffer", proc.Name)
			}
			return buf[:size], nil
		case errorInsufficientBuffer:
			size += 4 << 10
		default:
			return nil, fmt.Errorf("%s: %w", proc.Name, windows.Errno(r))
		}
	}
	return nil, fmt.Errorf("%s: the table kept growing", proc.Name)
}

// processCreation reads a process's creation time in the form a supervised
// job records it, time.Unix(0, FILETIME nanoseconds).
func processCreation(pid int) (time.Time, error) {
	if pid <= 0 || pid > int(^uint32(0)) {
		return time.Time{}, errors.New("process id out of range")
	}
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, uint32(pid))
	if err != nil {
		return time.Time{}, err
	}
	defer windows.CloseHandle(h)
	var creation, exited, kernel, user windows.Filetime
	if err := windows.GetProcessTimes(h, &creation, &exited, &kernel, &user); err != nil {
		return time.Time{}, err
	}
	return time.Unix(0, creation.Nanoseconds()), nil
}
