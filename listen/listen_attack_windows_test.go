package listen

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"
)

// The door this listener creates, attacked from outside it.
//
// A named pipe created with no security descriptor of its own is not an
// unlocked door, it is a door the pipe filesystem furnishes, and what it
// furnishes was measured on this listener before these tests existed:
//
//	D:(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;<the user>)(A;;FR;;;WD)(A;;FR;;;AN)
//
// Everyone and ANONYMOUS LOGON read, and no integrity label, so a sandboxed
// process in this same account reads it too. The first line of every protocol
// on these pipes carries a secret and the services behind them answer for the
// account, so each of those three is attacked here by a process that really
// runs, and each must be refused.

const (
	attackEnv  = "LISTEN_ATTACK_PIPE"
	attackMode = "LISTEN_ATTACK_MODE"

	attackerGotIn   = 0
	attackerRefused = 3
)

func TestMain(m *testing.M) {
	if name := os.Getenv(attackEnv); name != "" {
		os.Exit(runAttacker(name, os.Getenv(attackMode)))
	}
	os.Exit(m.Run())
}

func runAttacker(name, mode string) int {
	n, err := windows.UTF16PtrFromString(name)
	if err != nil {
		fmt.Fprintln(os.Stderr, "attacker:", err)
		return 1
	}
	switch mode {
	case "take":
		// The call this listener made before it claimed the name: a second
		// instance of a pipe somebody else is already serving.
		h, err := windows.CreateNamedPipe(n, windows.PIPE_ACCESS_DUPLEX,
			windows.PIPE_REJECT_REMOTE_CLIENTS, windows.PIPE_UNLIMITED_INSTANCES, 4096, 4096, 0, nil)
		if err != nil {
			fmt.Fprintln(os.Stderr, "attacker: CreateNamedPipe refused:", err)
			return attackerRefused
		}
		windows.CloseHandle(h)
		return attackerGotIn
	case "read", "rw":
		access := uint32(windows.GENERIC_READ)
		if mode == "rw" {
			access |= windows.GENERIC_WRITE
		}
		h, err := windows.CreateFile(n, access, 0, nil, windows.OPEN_EXISTING, 0, 0)
		if err != nil {
			fmt.Fprintln(os.Stderr, "attacker: CreateFile refused:", err)
			return attackerRefused
		}
		windows.CloseHandle(h)
		return attackerGotIn
	}
	fmt.Fprintln(os.Stderr, "attacker: unknown mode", mode)
	return 1
}

// attack runs this test binary again as the attacker, under tok, and reports
// whether it got in. A separate process is the only honest form of the
// question: an access check reads the token of whoever asks, so an attacker
// inside this process would be answered as this process.
func attack(t *testing.T, tok windows.Token, name, mode string) bool {
	t.Helper()
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(exe)
	cmd.Env = append(os.Environ(), attackEnv+"="+name, attackMode+"="+mode)
	cmd.Stderr = os.Stderr
	if tok != 0 {
		cmd.SysProcAttr = &syscall.SysProcAttr{Token: syscall.Token(tok)}
	}
	err = cmd.Run()
	if err == nil {
		return true
	}
	var exit *exec.ExitError
	if errors.As(err, &exit) && exit.ExitCode() == attackerRefused {
		return false
	}
	t.Fatalf("the attacker neither got in nor was refused: %v", err)
	return false
}

func descriptorOf(t *testing.T, l Listener) string {
	t.Helper()
	p, ok := l.(*pipeListener)
	if !ok {
		t.Fatalf("Listen returned %T, not a pipe listener", l)
	}
	sd, err := windows.GetSecurityInfo(windows.Handle(p.waiting), windows.SE_KERNEL_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION|windows.LABEL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatalf("GetSecurityInfo: %v", err)
	}
	return sd.String()
}

func ourSID(t *testing.T) string {
	t.Helper()
	u, err := windows.Token(windows.GetCurrentProcessToken()).GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	return u.User.Sid.String()
}

func serving(t *testing.T) (Listener, string) {
	t.Helper()
	name := fmt.Sprintf(`\\.\pipe\openabstractions-test-%d-%s`, os.Getpid(), t.Name())
	l, err := Listen(name)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	return l, name
}

// TestThePipeNamesOneAccountAndNoOneElse is the descriptor stated in a form a
// reader can check against ownAccountOnly, and against the measured default
// quoted at the top of this file.
func TestThePipeNamesOneAccountAndNoOneElse(t *testing.T) {
	l, _ := serving(t)
	sddl := descriptorOf(t, l)
	t.Logf("the pipe's own descriptor: %s", sddl)

	dacl := sddl
	if i := strings.Index(dacl, "S:"); i >= 0 {
		dacl = dacl[:i]
	}
	if want := "(A;;FA;;;" + ourSID(t) + ")"; !strings.Contains(dacl, want) {
		t.Fatalf("the account that created the listener is not admitted: want %s in %s", want, dacl)
	}
	if strings.Count(dacl, "(A;") != 1 {
		t.Fatalf("the pipe admits more than one principal: %s", dacl)
	}
	if !strings.Contains(dacl, "D:P") {
		t.Fatalf("the DACL is not protected, so something above it can still be inherited in: %s", dacl)
	}
	for who, sddlSID := range map[string]string{"Everyone": "WD", "ANONYMOUS LOGON": "AN", "Administrators": "BA"} {
		if strings.Contains(dacl, ";;;"+sddlSID+")") {
			t.Fatalf("%s is admitted, which is the pipe filesystem's default and not ours: %s", who, dacl)
		}
	}

	label := ""
	if i := strings.Index(sddl, "(ML;"); i >= 0 {
		label = sddl[i:]
	}
	if label == "" {
		t.Fatal("the pipe carries no integrity label, so a sandboxed process in this account may read it")
	}
	if !strings.Contains(label, "NR") || !strings.Contains(label, "NW") {
		t.Fatalf("the label allows reading or writing up: %s", label)
	}
	t.Logf("admitted: %s only, at or above the label %s", ourSID(t), label)
}

// TestAProcessWithNoClaimToThisAccountIsRefused is the Everyone ACE, attacked.
//
// The attacker is this same binary run under a restricted token whose only
// restricting SID is Everyone. Every access check it makes is answered twice,
// and the second answer knows nothing about this account - so it gets in only
// through an ACE that names Everyone, which is exactly the ACE the pipe
// filesystem supplies and this listener now does not. Measured before the
// descriptor landed: GENERIC_READ OPENED.
func TestAProcessWithNoClaimToThisAccountIsRefused(t *testing.T) {
	l, name := serving(t)
	tok := restrictedToEveryone(t)
	defer tok.Close()

	if attack(t, tok, name, "read") {
		t.Fatal("a process whose only identity is Everyone opened the pipe for read")
	}
	if attack(t, tok, name, "rw") {
		t.Fatal("a process whose only identity is Everyone opened the pipe for reading and writing")
	}

	// The control: the same attack, unrestricted, must still get in, or this
	// test would pass just as well against a pipe nobody is serving.
	if !attack(t, 0, name, "read") {
		t.Fatal("this account was refused its own pipe; the descriptor is wrong, not the attacker")
	}
	_ = l
}

// TestASandboxedProcessInThisAccountIsRefused is the missing label, attacked.
//
// A low-integrity process is this same account with its authority taken away -
// a browser renderer, an AppContainer, anything an exploit lands in. Mandatory
// integrity refuses it writing up by default but permits reading up, so before
// the label this attacker opened the pipe for read and was refused only the
// write. Measured before: GENERIC_READ OPENED, RW refused.
func TestASandboxedProcessInThisAccountIsRefused(t *testing.T) {
	l, name := serving(t)
	tok := loweredToLowIntegrity(t)
	defer tok.Close()

	if attack(t, tok, name, "read") {
		t.Fatal("a low-integrity process in this account opened the pipe for read")
	}
	if attack(t, tok, name, "rw") {
		t.Fatal("a low-integrity process in this account opened the pipe for reading and writing")
	}
	if !attack(t, 0, name, "read") {
		t.Fatal("this account was refused its own pipe; the descriptor is wrong, not the attacker")
	}
	_ = l
}

// TestWhoCanStillTakeTheName is the name-claim, attacked across a process
// boundary rather than inside one, and it records a limit rather than a fix.
//
// FILE_FLAG_FIRST_PIPE_INSTANCE is a promise to the caller that passes it, not
// a lock on the name: creating an instance of a pipe that already exists is
// refused only when the new create also asks to be first. An attacker that
// simply omits the flag is answered by the descriptor instead, because adding
// an instance needs FILE_CREATE_PIPE_INSTANCE on the existing pipe.
//
// So the two attackers with no claim to this account are refused, and a process
// running as this account is not - it cannot be, because the listener's own
// Accept creates every instance after the first through exactly that right and
// no descriptor can tell one process of an account from another. That is the
// boundary this layer states, and it is the reason a client must verify the
// server it reached rather than trust the name it dialled.
func TestWhoCanStillTakeTheName(t *testing.T) {
	_, name := serving(t)

	stranger := restrictedToEveryone(t)
	defer stranger.Close()
	if attack(t, stranger, name, "take") {
		t.Fatal("a process whose only identity is Everyone added an instance of this pipe")
	}

	sandboxed := loweredToLowIntegrity(t)
	defer sandboxed.Close()
	if attack(t, sandboxed, name, "take") {
		t.Fatal("a low-integrity process in this account added an instance of this pipe")
	}

	if !attack(t, 0, name, "take") {
		t.Fatal("this account cannot add an instance of its own pipe, so Accept cannot work either")
	}
	t.Log("a process of this account can still add an instance; a stranger and a sandbox cannot")
}

// TestListenWillNotStartBesideAListener is what the first-instance flag does
// buy: this listener never joins a name somebody is already serving, so ErrTaken
// is true rather than optimistic.
func TestListenWillNotStartBesideAListener(t *testing.T) {
	name := fmt.Sprintf(`\\.\pipe\openabstractions-test-%d-%s`, os.Getpid(), t.Name())
	n, err := windows.UTF16PtrFromString(name)
	if err != nil {
		t.Fatal(err)
	}
	h, err := windows.CreateNamedPipe(n, windows.PIPE_ACCESS_DUPLEX,
		windows.PIPE_REJECT_REMOTE_CLIENTS, windows.PIPE_UNLIMITED_INSTANCES, 4096, 4096, 0, nil)
	if err != nil {
		t.Fatalf("CreateNamedPipe(%s): %v", name, err)
	}
	defer windows.CloseHandle(h)

	l, err := Listen(name)
	if err == nil {
		l.Close()
		t.Fatal("Listen joined a name that was already being served")
	}
	if !errors.Is(err, ErrTaken) {
		t.Fatalf("Listen refused for the wrong reason: %v", err)
	}
}

var procCreateRestrictedToken = windows.NewLazySystemDLL("advapi32.dll").NewProc("CreateRestrictedToken")

const disableMaxPrivilege = 0x1

func ourTokenForAChild(t *testing.T) windows.Token {
	t.Helper()
	var tok windows.Token
	err := windows.OpenProcessToken(windows.CurrentProcess(),
		windows.TOKEN_DUPLICATE|windows.TOKEN_ADJUST_DEFAULT|windows.TOKEN_QUERY|windows.TOKEN_ASSIGN_PRIMARY, &tok)
	if err != nil {
		t.Fatalf("OpenProcessToken: %v", err)
	}
	return tok
}

func restrictedToEveryone(t *testing.T) windows.Token {
	t.Helper()
	cur := ourTokenForAChild(t)
	defer cur.Close()
	everyone, err := windows.StringToSid("S-1-1-0")
	if err != nil {
		t.Fatal(err)
	}
	restrict := []windows.SIDAndAttributes{{Sid: everyone}}
	var out windows.Token
	r, _, e := procCreateRestrictedToken.Call(uintptr(cur), disableMaxPrivilege, 0, 0, 0, 0,
		uintptr(len(restrict)), uintptr(unsafe.Pointer(&restrict[0])), uintptr(unsafe.Pointer(&out)))
	if r == 0 {
		t.Fatalf("CreateRestrictedToken: %v", e)
	}
	return out
}

func loweredToLowIntegrity(t *testing.T) windows.Token {
	t.Helper()
	cur := ourTokenForAChild(t)
	defer cur.Close()
	var dup windows.Token
	if err := windows.DuplicateTokenEx(cur, 0, nil, windows.SecurityImpersonation, windows.TokenPrimary, &dup); err != nil {
		t.Fatalf("DuplicateTokenEx: %v", err)
	}
	low, err := windows.StringToSid("S-1-16-4096")
	if err != nil {
		t.Fatal(err)
	}
	label := windows.Tokenmandatorylabel{Label: windows.SIDAndAttributes{Sid: low, Attributes: windows.SE_GROUP_INTEGRITY}}
	if err := windows.SetTokenInformation(dup, windows.TokenIntegrityLevel,
		(*byte)(unsafe.Pointer(&label)), uint32(unsafe.Sizeof(label))+windows.GetLengthSid(low)); err != nil {
		dup.Close()
		t.Fatalf("SetTokenInformation(TokenIntegrityLevel): %v", err)
	}
	return dup
}
