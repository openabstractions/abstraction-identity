package listen

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"testing"
	"unsafe"

	identity "github.com/openabstractions/abstraction-identity"
	"golang.org/x/sys/windows"
)

// What Dial hands the server it reaches, measured by a server that is a real
// second process.
//
// A client cannot ask this question of itself. ImpersonateNamedPipeClient reads
// the quality of service the *client* asked for when it opened the pipe, and
// only the server end can call it, so the level Dial grants is only observable
// from the other side of a process boundary. Every test here starts this same
// binary again as a server, dials it, and reads back what it got.
//
// legacyDial is the call Dial used to make. It is the control: the same server,
// the same probes, one flag apart.

const (
	serverEnv = "LISTEN_SQOS_SERVER"
	probeEnv  = "LISTEN_SQOS_PROBE_FILE"

	serverFailed = 4
	probeFrame   = "who am I to you"
)

// report is what the server process saw. It travels as one JSON line on the
// server's stdout, because the connection itself is the thing under test.
type report struct {
	Level     uint32 `json:"level"`
	LevelWhy  string `json:"level_why"`
	Opened    bool   `json:"opened"`
	OpenErr   string `json:"open_err"`
	OpenErrno uint32 `json:"open_errno"`
	Primary   bool   `json:"primary"`
	PrimErr   string `json:"prim_err"`
	PrimErrno uint32 `json:"prim_errno"`
	Caller    Seen   `json:"caller"`
	Receive   string `json:"receive_err"`
	Recheck   string `json:"recheck_err"`
	Frame     string `json:"frame"`
}

var procImpersonateNamedPipeClient = windows.NewLazySystemDLL("advapi32.dll").NewProc("ImpersonateNamedPipeClient")

func impersonateClient(pipe syscall.Handle) error {
	r, _, e := syscall.SyscallN(procImpersonateNamedPipeClient.Addr(), uintptr(pipe))
	if r == 0 {
		return e
	}
	return nil
}

// runServer is this binary in its server role: it serves one connection, binds
// the caller through the ordinary path, then asks the two questions this task
// exists for - what level was granted, and can that level be used.
func runServer(name string) int {
	l, err := Listen(name)
	if err != nil {
		fmt.Fprintln(os.Stderr, "server: Listen:", err)
		return serverFailed
	}
	defer l.Close()
	// The client must not dial before the pipe exists, and it must not sleep
	// waiting for it either. This line is the notification.
	fmt.Println("listening")

	c, err := l.Accept()
	if err != nil {
		fmt.Fprintln(os.Stderr, "server: Accept:", err)
		return serverFailed
	}
	defer c.Close()

	var r report
	k, rerr := Receive(c, Program, 4096)
	r.Caller = k.Caller
	r.Frame = string(k.Frame)
	if rerr != nil {
		r.Receive = rerr.Error()
	} else if err := k.Recheck(); err != nil {
		r.Recheck = err.Error()
	}

	probeLevel(c.(*pipeConn).h, &r)

	line, err := json.Marshal(r)
	if err != nil {
		fmt.Fprintln(os.Stderr, "server:", err)
		return serverFailed
	}
	fmt.Println(string(line))
	return 0
}

// probeLevel impersonates the client and, while wearing whatever it was given,
// tries the two things impersonation authority is for: reaching an object as
// the client, and minting a primary token to run code as the client. The
// thread is locked and reverted the way identity.withPeerToken does it, for the
// same reason: a goroutine that moves threads leaves one wearing the client.
func probeLevel(pipe syscall.Handle, r *report) {
	done := make(chan struct{})
	go func() {
		defer close(done)
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()

		if err := impersonateClient(pipe); err != nil {
			r.LevelWhy = "ImpersonateNamedPipeClient: " + err.Error()
			return
		}
		defer windows.RevertToSelf()

		th, err := windows.GetCurrentThread()
		if err != nil {
			r.LevelWhy = "GetCurrentThread: " + err.Error()
			return
		}
		var tok windows.Token
		if err := windows.OpenThreadToken(th, windows.TOKEN_QUERY|windows.TOKEN_DUPLICATE, true, &tok); err != nil {
			r.LevelWhy = "OpenThreadToken: " + err.Error()
			return
		}
		defer tok.Close()

		var n uint32
		if err := windows.GetTokenInformation(tok, windows.TokenImpersonationLevel,
			(*byte)(unsafe.Pointer(&r.Level)), uint32(unsafe.Sizeof(r.Level)), &n); err != nil {
			r.LevelWhy = "TokenImpersonationLevel: " + err.Error()
			return
		}

		if f := os.Getenv(probeEnv); f != "" {
			p, err := windows.UTF16PtrFromString(f)
			if err != nil {
				r.OpenErr = err.Error()
			} else {
				h, err := windows.CreateFile(p, windows.GENERIC_READ, windows.FILE_SHARE_READ, nil,
					windows.OPEN_EXISTING, 0, 0)
				if err == nil {
					r.Opened = true
					windows.CloseHandle(h)
				} else {
					r.OpenErr, r.OpenErrno = err.Error(), errnoOf(err)
				}
			}
		}

		var prim windows.Token
		if err := windows.DuplicateTokenEx(tok, windows.TOKEN_ALL_ACCESS, nil,
			windows.SecurityImpersonation, windows.TokenPrimary, &prim); err == nil {
			r.Primary = true
			prim.Close()
		} else {
			r.PrimErr, r.PrimErrno = err.Error(), errnoOf(err)
		}
	}()
	<-done
}

func errnoOf(err error) uint32 {
	var e syscall.Errno
	if errors.As(err, &e) {
		return uint32(e)
	}
	return 0
}

// legacyDial is Dial as it stood before SECURITY_SQOS_PRESENT was added: the
// same open with no quality of service asked for. It exists so every assertion
// below has a control, and so the defect can be re-measured rather than
// remembered.
func legacyDial(name string) (*os.File, error) { return os.OpenFile(name, os.O_RDWR, 0) }

// serve starts this binary as a server, waits for it to say it is listening,
// dials it with the given dialer, sends one frame and reads back what the
// server saw.
func serve(t *testing.T, dial func(string) (io.ReadWriteCloser, error)) report {
	t.Helper()
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	probe := filepath.Join(t.TempDir(), "a-file-of-the-caller")
	if err := os.WriteFile(probe, []byte("the client's own file\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	name := fmt.Sprintf(`\\.\pipe\openabstractions-test-%d-%s`, os.Getpid(), t.Name())
	cmd := exec.Command(exe)
	cmd.Env = append(os.Environ(), serverEnv+"="+name, probeEnv+"="+probe)
	cmd.Stderr = os.Stderr
	out, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cmd.Wait() })

	sc := bufio.NewScanner(out)
	if !sc.Scan() {
		t.Fatal("the server process never said it was listening")
	}
	if sc.Text() != "listening" {
		t.Fatalf("the server process said %q, not that it was listening", sc.Text())
	}

	c, err := dial(name)
	if err != nil {
		t.Fatalf("dialling the server: %v", err)
	}
	defer c.Close()
	if _, err := c.Write([]byte(probeFrame + "\n")); err != nil {
		t.Fatalf("writing to the server: %v", err)
	}

	if !sc.Scan() {
		t.Fatal("the server process reported nothing")
	}
	var r report
	if err := json.Unmarshal(sc.Bytes(), &r); err != nil {
		t.Fatalf("the server's report was not readable (%q): %v", sc.Text(), err)
	}
	return r
}

func dialed(name string) (io.ReadWriteCloser, error)       { return Dial(name) }
func dialedLegacy(name string) (io.ReadWriteCloser, error) { return legacyDial(name) }

// TestTheServerIsGivenIdentificationOnly is acceptance (1) and (3) together,
// with the old dialer beside it as the control.
//
// Level 2 is SecurityImpersonation - the server may act as the caller. Level 1
// is SecurityIdentification - it may read who the caller is and nothing more.
// The two probes are the difference stated as behaviour rather than as a
// number: an object opened as the caller, and a primary token that would run
// code as the caller. Both are refused with ERROR_BAD_IMPERSONATION_LEVEL at
// level 1, which is the proof the authority is gone and not merely unused.
func TestTheServerIsGivenIdentificationOnly(t *testing.T) {
	before := serve(t, dialedLegacy)
	t.Logf("the old dialer: level %d (%s), opened the caller's file %v, minted a primary token %v",
		before.Level, levelName(before.Level), before.Opened, before.Primary)
	if before.Level != windows.SecurityImpersonation {
		t.Fatalf("the control is not the defect: the old dialer granted level %d, want %d",
			before.Level, windows.SecurityImpersonation)
	}
	if !before.Opened || !before.Primary {
		t.Fatalf("the control could not use the authority it was given (open %v %s, primary %v %s); "+
			"the probes are wrong, not the dialer", before.Opened, before.OpenErr, before.Primary, before.PrimErr)
	}

	now := serve(t, dialed)
	t.Logf("Dial: level %d (%s), opened the caller's file %v (%s), minted a primary token %v (%s)",
		now.Level, levelName(now.Level), now.Opened, now.OpenErr, now.Primary, now.PrimErr)
	if now.LevelWhy != "" {
		t.Fatalf("the server could not read the level it was given: %s", now.LevelWhy)
	}
	if now.Level != windows.SecurityIdentification {
		t.Fatalf("Dial granted the server level %d (%s), want %d (identification)",
			now.Level, levelName(now.Level), windows.SecurityIdentification)
	}
	if now.Opened {
		t.Fatal("the server opened a file of the caller's while impersonating it, so it still has the authority to act as the caller")
	}
	if now.OpenErrno != uint32(windows.ERROR_BAD_IMPERSONATION_LEVEL) {
		t.Fatalf("the open was refused for the wrong reason (%d: %s), want ERROR_BAD_IMPERSONATION_LEVEL",
			now.OpenErrno, now.OpenErr)
	}
	if now.Primary {
		t.Fatal("the server minted a primary token from the caller's, so it could still run code as the caller")
	}
	if now.PrimErrno != uint32(windows.ERROR_BAD_IMPERSONATION_LEVEL) {
		t.Fatalf("the duplication was refused for the wrong reason (%d: %s), want ERROR_BAD_IMPERSONATION_LEVEL",
			now.PrimErrno, now.PrimErr)
	}
}

// TestIdentityStillBindsAcrossTheChangedDialer is acceptance (2). Identification
// level is the level identity reads at - withPeerToken opens the peer token for
// TOKEN_QUERY and says in its own doc that it never acts as the client - so
// every answer must be the answer it was before, from the same process
// boundary, over a connection that granted one level less.
func TestIdentityStillBindsAcrossTheChangedDialer(t *testing.T) {
	before := serve(t, dialedLegacy)
	now := serve(t, dialed)

	if now.Receive != "" {
		t.Fatalf("the caller was not bound and checked: %s", now.Receive)
	}
	if !now.Caller.Bound {
		t.Fatalf("the caller was not bound: %s", now.Caller.Why)
	}
	if now.Recheck != "" {
		t.Fatalf("the connection stopped answering for its caller: %s", now.Recheck)
	}
	if now.Frame != probeFrame {
		t.Fatalf("the server got frame %q, want %q", now.Frame, probeFrame)
	}

	me, err := windows.Token(windows.GetCurrentProcessToken()).GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(now.Caller.User, me.User.Sid.String()) {
		t.Fatalf("the server did not see this process's SID %s in %q", me.User.Sid, now.Caller.User)
	}
	if !strings.Contains(now.Caller.Path, exe) {
		t.Fatalf("the server did not see this process's image %s in %q", exe, now.Caller.Path)
	}
	for _, field := range []struct{ what, was, is string }{
		{"user", before.Caller.User, now.Caller.User},
		{"path", before.Caller.Path, now.Caller.Path},
		{"code", before.Caller.Code, now.Caller.Code},
	} {
		if field.was != field.is {
			t.Fatalf("the %s the server binds changed with the dialer: was %q, now %q", field.what, field.was, field.is)
		}
	}
	t.Logf("bound over both dialers alike: %s", now.Caller)
}

// TestWhatIdentificationLevelIsReportedAs is the owner's ruling written as a
// test: identification level is normal capability information, not a shortfall.
// Nothing may downgrade a proof for it, and Check against Program must pass.
func TestWhatIdentificationLevelIsReportedAs(t *testing.T) {
	now := serve(t, dialed)
	if now.Receive != "" {
		t.Fatalf("Check(Program) failed over a connection at identification level: %s", now.Receive)
	}
	if now.Caller.Notes != "" {
		t.Logf("the note every binding on Windows now carries: %s", now.Caller.Notes)
	}
	l := identity.Ceiling()
	if !l.Bindable || l.Best.User != identity.ProofKernel || l.Best.Process != identity.ProofKernel ||
		l.Best.Path != identity.ProofBound {
		t.Fatalf("Ceiling no longer describes what this transport proves: %+v", l.Best)
	}
	if l.Stronger != "" {
		t.Fatalf("Ceiling names a stronger transport it did not name before: %s", l.Stronger)
	}
}

func levelName(level uint32) string {
	switch level {
	case windows.SecurityAnonymous:
		return "anonymous"
	case windows.SecurityIdentification:
		return "identification"
	case windows.SecurityImpersonation:
		return "impersonation"
	case 3:
		return "delegation"
	}
	return "unknown"
}
