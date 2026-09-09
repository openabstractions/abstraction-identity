package listen

import (
	"errors"
	"fmt"
	"io/fs"
	"net"
	"os"
	"sync"
	"syscall"
	"time"
	"unsafe"

	identity "github.com/openabstractions/abstraction-identity"
	"golang.org/x/sys/windows"
)

var (
	kernel32         = syscall.NewLazyDLL("kernel32.dll")
	createNamedPipe  = kernel32.NewProc("CreateNamedPipeW")
	connectNamedPipe = kernel32.NewProc("ConnectNamedPipe")
	cancelIoEx       = kernel32.NewProc("CancelIoEx")
	createEvent      = kernel32.NewProc("CreateEventW")
	overlappedResult = kernel32.NewProc("GetOverlappedResult")
	waitNamedPipe    = kernel32.NewProc("WaitNamedPipeW")
)

const (
	errPipeConnected   = syscall.Errno(535)
	errPipeBusy        = syscall.Errno(231)
	busyWait           = 5000
	pipeAccessDuplex   = 3
	fileFlagOverlapped = 0x40000000
	fileFlagFirstPipe  = 0x00080000
	pipeRejectRemote   = 8
	unlimitedInstances = 255
	integrityMedium    = 0x2000
)

var (
	errConnect = errors.New("listen: a client left before it was connected")
	ErrTaken   = errors.New("listen: the name is taken: another listener holds it, or a client of the last one has not hung up")
)

type pipeConn struct {
	*os.File
	h  syscall.Handle
	at time.Time
}

func (c *pipeConn) Bind() (*identity.Binding, error) {
	return identity.Bind(identity.Handle(c.h), &identity.Options{ConnectedAt: c.at})
}

type pipeListener struct {
	name    *uint16
	sa      *windows.SecurityAttributes
	mu      sync.Mutex
	waiting syscall.Handle
	closed  bool
}

func Listen(name string) (Listener, error) {
	n, err := syscall.UTF16PtrFromString(name)
	if err != nil {
		return nil, err
	}
	sa, err := ownAccountOnly()
	if err != nil {
		return nil, err
	}
	l := &pipeListener{name: n, sa: sa}
	if l.waiting, err = l.instance(fileFlagFirstPipe); errors.Is(err, syscall.ERROR_ACCESS_DENIED) {
		return nil, fmt.Errorf("%w: %s", ErrTaken, name)
	} else if err != nil {
		return nil, err
	}
	return l, nil
}

// A pipe created with no descriptor of its own does not get a closed door. The
// pipe filesystem supplies one that grants Everyone and ANONYMOUS LOGON read,
// and no integrity label, so a sandboxed process in this account reads it too.
// Both were measured, and both are attacked in listen_attack_windows_test.go.
func ownAccountOnly() (*windows.SecurityAttributes, error) {
	tok := windows.Token(windows.GetCurrentProcessToken())
	u, err := tok.GetTokenUser()
	if err != nil {
		return nil, fmt.Errorf("listen: whose account this is could not be read: %w", err)
	}
	sd, err := windows.SecurityDescriptorFromString(
		"D:P(A;;FA;;;" + u.User.Sid.String() + ")S:(ML;;NRNWNX;;;" + ourLabel(tok) + ")")
	if err != nil {
		return nil, fmt.Errorf("listen: the pipe's door could not be built: %w", err)
	}
	return &windows.SecurityAttributes{
		Length:             uint32(unsafe.Sizeof(windows.SecurityAttributes{})),
		SecurityDescriptor: sd,
	}, nil
}

// Medium is the integrity of the ordinary interactive process every client of
// this layer is, and it is the level below which a process can no longer write
// to the account's own profile - so below it a process is in the account
// without being able to act for it. Nothing may label an object above itself,
// and that refusal would arrive as the ACCESS_DENIED Listen reports as a taken
// name, so a service running lower than medium labels at its own level instead
// of failing with the wrong sentence.
func ourLabel(tok windows.Token) string {
	var n uint32
	windows.GetTokenInformation(tok, windows.TokenIntegrityLevel, nil, 0, &n)
	if n == 0 {
		return "ME"
	}
	buf := make([]byte, n)
	if err := windows.GetTokenInformation(tok, windows.TokenIntegrityLevel, &buf[0], n, &n); err != nil {
		return "ME"
	}
	sid := (*windows.Tokenmandatorylabel)(unsafe.Pointer(&buf[0])).Label.Sid
	if sid == nil || sid.SubAuthorityCount() == 0 {
		return "ME"
	}
	if sid.SubAuthority(uint32(sid.SubAuthorityCount())-1) < integrityMedium {
		return "LW"
	}
	return "ME"
}

// The first instance claims the name, so nothing is already listening on it.
// It does not stop something starting beside it afterwards: the flag is a
// promise to whoever passes it, and an attacker omitting it is answered by the
// descriptor instead, which admits one account and nothing else.
// TestWhoCanStillTakeTheName is where that boundary is measured.
func (l *pipeListener) instance(claim uintptr) (syscall.Handle, error) {
	h, _, err := createNamedPipe.Call(uintptr(unsafe.Pointer(l.name)), pipeAccessDuplex|fileFlagOverlapped|claim, pipeRejectRemote,
		unlimitedInstances, 4096, 4096, 0, uintptr(unsafe.Pointer(l.sa)))
	if syscall.Handle(h) == syscall.InvalidHandle {
		return 0, err
	}
	return syscall.Handle(h), nil
}

func (l *pipeListener) Accept() (Conn, error) {
	l.mu.Lock()
	h, closed := l.waiting, l.closed
	l.mu.Unlock()
	if closed {
		return nil, net.ErrClosed
	}

	cerr := connect(h)
	at := time.Now()
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed {
		return nil, net.ErrClosed
	}
	next, err := l.instance(0)
	if err != nil {
		syscall.CloseHandle(h)
		return nil, err
	}
	l.waiting = next
	if cerr != nil {
		syscall.CloseHandle(h)
		return nil, errConnect
	}
	return &pipeConn{File: os.NewFile(uintptr(h), "pipe"), h: h, at: at}, nil
}

func connect(h syscall.Handle) error {
	ev, _, err := createEvent.Call(0, 1, 0, 0)
	if ev == 0 {
		return err
	}
	defer syscall.CloseHandle(syscall.Handle(ev))
	o := syscall.Overlapped{HEvent: syscall.Handle(ev)}
	r, _, err := connectNamedPipe.Call(uintptr(h), uintptr(unsafe.Pointer(&o)))
	if r != 0 || errors.Is(err, errPipeConnected) {
		return nil
	}
	if !errors.Is(err, syscall.ERROR_IO_PENDING) {
		return err
	}
	var n uint32
	if r, _, err = overlappedResult.Call(uintptr(h), uintptr(unsafe.Pointer(&o)), uintptr(unsafe.Pointer(&n)), 1); r == 0 {
		return err
	}
	return nil
}

func (l *pipeListener) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.closed = true
	cancelIoEx.Call(uintptr(l.waiting), 0)
	return syscall.CloseHandle(l.waiting)
}

// identifyOnly is the authority this side hands the server it reaches.
// CreateFile with no quality of service defaults a named-pipe client to
// SecurityImpersonation, so the server may act as this process - open its
// files, reach the network as it - from the instant the handle opens, before
// this side has learned anything about who answered. Ordering is the whole
// problem: a client cannot verify first and grant afterwards.
// SECURITY_IDENTIFICATION is what a server needs to read this caller's
// identity and one level below what lets it wear that identity, and reading
// identity is all this layer's servers do.
const identifyOnly = windows.SECURITY_SQOS_PRESENT | windows.SECURITY_IDENTIFICATION

func Dial(name string) (net.Conn, error) {
	n, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return nil, &fs.PathError{Op: "open", Path: name, Err: err}
	}
	for {
		h, err := windows.CreateFile(n, windows.GENERIC_READ|windows.GENERIC_WRITE,
			windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE, nil, windows.OPEN_EXISTING, identifyOnly, 0)
		if err == nil {
			return fileConn{os.NewFile(uintptr(h), name)}, nil
		}
		if !errors.Is(err, errPipeBusy) {
			return nil, &fs.PathError{Op: "open", Path: name, Err: err}
		}
		if r, _, err := waitNamedPipe.Call(uintptr(unsafe.Pointer(n)), busyWait); r == 0 {
			return nil, &fs.PathError{Op: "open", Path: name, Err: err}
		}
	}
}

type fileConn struct{ *os.File }

func (fileConn) LocalAddr() net.Addr              { return nil }
func (fileConn) RemoteAddr() net.Addr             { return nil }
func (fileConn) SetDeadline(time.Time) error      { return nil }
func (fileConn) SetReadDeadline(time.Time) error  { return nil }
func (fileConn) SetWriteDeadline(time.Time) error { return nil }

func Endpoint(service string) string { return `\\.\pipe\openabstractions-` + service }
