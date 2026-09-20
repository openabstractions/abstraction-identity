//go:build windows

package identity

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"sort"
	"strings"
	"sync/atomic"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	queryPerformanceCounter   = modkernel32.NewProc("QueryPerformanceCounter")
	queryPerformanceFrequency = modkernel32.NewProc("QueryPerformanceFrequency")
)

// performanceCounter reads QueryPerformanceCounter. time.Now on Windows follows
// the interrupt clock, which is coarser than one binding.
func performanceCounter() time.Duration {
	var counter, frequency int64
	queryPerformanceCounter.Call(uintptr(unsafe.Pointer(&counter)))
	queryPerformanceFrequency.Call(uintptr(unsafe.Pointer(&frequency)))
	return time.Duration(float64(counter) / float64(frequency) * float64(time.Second))
}

// countVerifications replaces verifyFile for one test and counts real or stub
// verifications. It clears the verdict table before and after.
func countVerifications(t *testing.T, stub func(windows.Handle, string, *Options) (Code, Proof, error)) *atomic.Int32 {
	t.Helper()
	var count atomic.Int32
	clearVerdicts()
	previous := verifyFile
	verifyFile = func(proc windows.Handle, path string, opts *Options) (Code, Proof, error) {
		count.Add(1)
		return stub(proc, path, opts)
	}
	t.Cleanup(func() { verifyFile = previous; clearVerdicts() })
	return &count
}

func clearVerdicts() {
	codeVerdicts.Lock()
	defer codeVerdicts.Unlock()
	for k, e := range codeVerdicts.entries {
		dropVerdict(k, e)
	}
}

func selfInstance(t *testing.T) (windows.Handle, uint32, time.Time) {
	t.Helper()
	proc, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, uint32(os.Getpid()))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { windows.CloseHandle(proc) })
	started, err := processStartTime(proc)
	if err != nil {
		t.Fatal(err)
	}
	return proc, uint32(os.Getpid()), started
}

// TestCodeVerdictIsReusedOnlyForTheSameInstanceAndPath pins the reuse key: the
// same live process at the same image path and revocation setting verifies
// once; a different path, a different creation time, revocation, an expired
// entry and a failed verification each verify again.
func TestCodeVerdictIsReusedOnlyForTheSameInstanceAndPath(t *testing.T) {
	fail := false
	count := countVerifications(t, func(_ windows.Handle, path string, _ *Options) (Code, Proof, error) {
		if fail {
			return Code{}, ProofNone, errors.New("stub failure")
		}
		return Code{Status: "stub " + path, Trusted: true}, ProofBound, nil
	})
	proc, pid, started := selfInstance(t)
	exe := mustExe(t)
	verify := func(started time.Time, path string, opts *Options, want int32) Code {
		t.Helper()
		code, _, err := verifyProcessImage(proc, pid, started, path, opts)
		if got := count.Load(); got != want {
			t.Fatalf("after verifying %q (revocation %v, started %v): %d verifications, want %d", path, opts.checkRevocation(), started, got, want)
		}
		if err != nil && !fail {
			t.Fatal(err)
		}
		return code
	}
	first := verify(started, exe, nil, 1)
	if again := verify(started, exe, nil, 1); again != first {
		t.Fatalf("reused verdict %+v differs from %+v", again, first)
	}
	verify(started, exe+".other", nil, 2)
	verify(started, exe, &Options{CheckRevocation: true}, 3)
	verify(started, exe, &Options{CheckRevocation: true}, 3)
	// A creation time other than the pinned process's is another instance,
	// and keepVerdict refuses to hold a handle that names a different one.
	verify(started.Add(time.Millisecond), exe, nil, 4)
	verify(started.Add(time.Millisecond), exe, nil, 5)

	codeVerdicts.Lock()
	for _, e := range codeVerdicts.entries {
		e.at = e.at.Add(-codeVerdictLifetime)
	}
	codeVerdicts.Unlock()
	verify(started, exe, nil, 6)
	verify(started, exe, nil, 6)

	clearVerdicts()
	fail = true
	verify(started, exe, nil, 7)
	verify(started, exe, nil, 8)
}

// TestCodeVerdictsOfExitedProcessesAreReleased keeps a verdict for a child
// that then exits, and requires the next kept verdict to drop it and close its
// handle.
func TestCodeVerdictsOfExitedProcessesAreReleased(t *testing.T) {
	countVerifications(t, func(windows.Handle, string, *Options) (Code, Proof, error) {
		return Code{Status: "stub"}, ProofUnsigned, nil
	})
	child := exec.Command(os.Getenv("ComSpec"), "/c", "exit 0")
	if child.Path == "" || os.Getenv("ComSpec") == "" {
		t.Skip("no ComSpec")
	}
	if err := child.Start(); err != nil {
		t.Fatal(err)
	}
	pid := uint32(child.Process.Pid)
	proc, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		t.Fatal(err)
	}
	defer windows.CloseHandle(proc)
	started, err := processStartTime(proc)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := verifyProcessImage(proc, pid, started, `C:\child.exe`, nil); err != nil {
		t.Fatal(err)
	}
	child.Wait()
	self, selfPID, selfStarted := selfInstance(t)
	if _, _, err := verifyProcessImage(self, selfPID, selfStarted, mustExe(t), nil); err != nil {
		t.Fatal(err)
	}
	codeVerdicts.Lock()
	defer codeVerdicts.Unlock()
	for k := range codeVerdicts.entries {
		if k.pid == pid {
			t.Fatalf("the verdict for exited pid %d is still held", pid)
		}
	}
	if len(codeVerdicts.entries) != 1 {
		t.Fatalf("%d verdicts held, want 1", len(codeVerdicts.entries))
	}
}

// TestSignedPeerIsVerifiedOncePerProcess connects a signed Windows program to
// a pipe several times and binds each connection with signature verification
// on. The first binding verifies; every later one reuses that verdict and
// reports the same Code. Later bindings must each finish within
// laterBindBound, a bound about ten times what a binding without verification
// costs on a loaded machine, and far below the 30 to 150 ms one verification
// of a signed interpreter costs.
func TestSignedPeerIsVerifiedOncePerProcess(t *testing.T) {
	const connections = 6
	const laterBindBound = 10 * time.Millisecond
	count := countVerifications(t, verifyImage)
	name := pipeName(t)
	server := listen(t, name)
	// Node.js carries an embedded signature and a 90 MB image, the costliest
	// peer measured. Windows PowerShell is present everywhere; this verifier
	// reports its catalog signature as unsigned, and reuse is still counted.
	var child *exec.Cmd
	if node, err := exec.LookPath("node"); err == nil {
		child = exec.Command(node, "-e", fmt.Sprintf(`const net=require('net');(async()=>{for(let i=0;i<%d;i++){`+
			`await new Promise((ok,fail)=>{const s=net.connect(%q);s.on('error',fail);`+
			`s.on('connect',()=>s.write(Buffer.from([1,2,3,4])));s.on('data',()=>{s.destroy();ok();});});}})()`+
			`.catch(e=>{console.error(e);process.exit(1);});`, connections, name))
	} else {
		powershell := os.ExpandEnv(`${SystemRoot}\System32\WindowsPowerShell\v1.0\powershell.exe`)
		if _, err := os.Stat(powershell); err != nil {
			t.Skipf("no Node.js and no Windows PowerShell to connect as a peer: %v", err)
		}
		child = exec.Command(powershell, "-NoProfile", "-NonInteractive", "-Command", fmt.Sprintf(
			`$ErrorActionPreference='Stop'; for($i=0;$i -lt %d;$i++){ `+
				`$p=New-Object System.IO.Pipes.NamedPipeClientStream('.', '%s', [System.IO.Pipes.PipeDirection]::InOut); `+
				`$p.Connect(20000); $p.Write([byte[]](1,2,3,4),0,4); $p.Flush(); [void]$p.ReadByte(); $p.Dispose() }`,
			connections, strings.TrimPrefix(name, `\\.\pipe\`)))
	}
	child.Stdout, child.Stderr = os.Stdout, os.Stderr
	if err := child.Start(); err != nil {
		t.Fatal(err)
	}
	defer child.Wait()

	var first Code
	var later []time.Duration
	for i := 0; i < connections; i++ {
		at := accept(t, server)
		readFrom(t, server)
		began := performanceCounter()
		peer, err := OfHandle(Handle(server), &Options{ConnectedAt: at})
		took := performanceCounter() - began
		if err != nil {
			t.Fatalf("connection %d: %v", i, err)
		}
		if proc, err := peer.Process.AtLeast(ProofKernel); err != nil || proc.PID != child.Process.Pid {
			t.Fatalf("connection %d: peer process %v (%v), want pid %d", i, proc, err, child.Process.Pid)
		}
		code, proof := peer.Code.Get()
		if proof < ProofInvalid {
			t.Fatalf("connection %d: code %v was not verified", i, peer.Code)
		}
		if i == 0 {
			first = code
			t.Logf("first binding %v: code %v", took, peer.Code)
		} else {
			if code != first {
				t.Fatalf("connection %d: code %+v, want the first verdict %+v", i, code, first)
			}
			later = append(later, took)
		}
		var n uint32
		if err := windows.WriteFile(server, []byte{1}, &n, nil); err != nil {
			t.Fatalf("connection %d: reply: %v", i, err)
		}
		buf := make([]byte, 1)
		windows.ReadFile(server, buf, &n, nil) // ends when the client closes
		if err := windows.DisconnectNamedPipe(server); err != nil {
			t.Fatal(err)
		}
	}
	if got := count.Load(); got != 1 {
		t.Fatalf("%d verifications for %d connections from one process, want 1", got, connections)
	}
	sort.Slice(later, func(i, j int) bool { return later[i] < later[j] })
	t.Logf("later bindings: %v", later)
	if slowest := later[len(later)-1]; slowest > laterBindBound {
		t.Fatalf("a later binding took %v, above %v", slowest, laterBindBound)
	}
}
