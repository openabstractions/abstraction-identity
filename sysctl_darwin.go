//go:build darwin

package identity

// The macOS reads that do not need the Security framework: the peer's audit
// token off the socket, and the two questions answered by sysctl.

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

// xucredVersion is XUCRED_VERSION from sys/ucred.h. A struct that arrives with
// a different version is a struct with a different layout, and this package
// refuses it rather than reading fields out of the wrong offsets.
const xucredVersion = 0

// auditToken is audit_token_t: eight 32-bit words whose meaning is fixed by
// libbsm's audit_token_to_au32. The accessors exist so that no offset is ever
// written twice.
type auditToken [8]uint32

func (t auditToken) auid() uint32       { return t[0] }
func (t auditToken) euid() uint32       { return t[1] }
func (t auditToken) egid() uint32       { return t[2] }
func (t auditToken) ruid() uint32       { return t[3] }
func (t auditToken) rgid() uint32       { return t[4] }
func (t auditToken) pid() uint32        { return t[5] }
func (t auditToken) asid() uint32       { return t[6] }
func (t auditToken) pidversion() uint32 { return t[7] }

// peerAuditToken reads LOCAL_PEERTOKEN off a connected unix socket.
//
// Read the file comment in identity_darwin.go before trusting the result. XNU
// answers this option by resolving the peer socket's current owner and asking
// that task for its token; it is not the connect-time record LOCAL_PEERCRED is,
// and it is not the message-stamped token an XPC peer has.
//
// There is no wrapper for this option in golang.org/x/sys/unix - the audit
// token is not one of the shapes it knows - and GetsockoptString cannot stand
// in for one, because the token contains zero bytes and would be truncated at
// the first of them. So the option is read through the raw getsockopt entry
// point, which is the only route that does not require cgo.
func peerAuditToken(fd int) (auditToken, error) {
	var tok auditToken
	size := uint32(unsafe.Sizeof(tok))
	_, _, errno := unix.Syscall6(
		uintptr(syscall.SYS_GETSOCKOPT),
		uintptr(fd),
		uintptr(unix.SOL_LOCAL),
		uintptr(unix.LOCAL_PEERTOKEN),
		uintptr(unsafe.Pointer(&tok[0])),
		uintptr(unsafe.Pointer(&size)),
		0,
	)
	if errno != 0 {
		return tok, errno
	}
	if size != uint32(unsafe.Sizeof(tok)) {
		return tok, fmt.Errorf("LOCAL_PEERTOKEN returned %d bytes, not %d; the kernel's audit token is not the shape this package knows", size, unsafe.Sizeof(tok))
	}
	return tok, nil
}

// processStartTime reads the peer's creation time. Unlike the Linux equivalent
// this one is exact: the kernel keeps p_starttime as a wall-clock timeval, so
// the comparison against Options.ConnectedAt needs no tolerance and none is
// given. A clock stepped backwards can cause a false refusal, which is the safe
// direction.
func processStartTime(pid int) (time.Time, error) {
	kp, err := unix.SysctlKinfoProc("kern.proc.pid", pid)
	if err != nil {
		return time.Time{}, err
	}
	if kp.Proc.P_pid != int32(pid) {
		// The pid was reassigned between the socket read and this one.
		return time.Time{}, fmt.Errorf("kern.proc.pid %d answered about pid %d", pid, kp.Proc.P_pid)
	}
	tv := kp.Proc.P_starttime
	return time.Unix(tv.Sec, int64(tv.Usec)*1000), nil
}

// processExecPath reads the path the kernel recorded when the process last
// exec'd, from the head of the kern.procargs2 buffer.
//
// It is a fallback. When the Security framework is available the path comes off
// the code object whose signature was verified, which is a statement about the
// running code; this one is a string the kernel kept, about a file that may
// since have been replaced. It also fails with EINVAL for a process owned by
// another user unless this service is root, which is the common case for the
// service this package was written for and not for a per-user one.
func processExecPath(pid int) (string, error) {
	buf, err := unix.SysctlRaw("kern.procargs2", pid)
	if err != nil {
		return "", err
	}
	// int32 argc, then the executable path as a C string, then argv.
	if len(buf) < 4 {
		return "", errors.New("kern.procargs2 returned no argument block")
	}
	rest := buf[binary.Size(int32(0)):]
	i := bytes.IndexByte(rest, 0)
	if i <= 0 {
		return "", errors.New("kern.procargs2 has no executable path")
	}
	return string(rest[:i]), nil
}
