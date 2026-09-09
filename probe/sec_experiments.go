//go:build darwin && cgo

package main

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"time"

	identity "github.com/openabstractions/abstraction-identity"
	"golang.org/x/sys/unix"
)

// clientMode is how the differently-signed peer binaries behave: dial, write,
// and stay alive while the server identifies them.
func clientMode(path string) {
	c, err := net.Dial("unix", path)
	must(err)
	_, err = c.Write([]byte("hi"))
	must(err)
	time.Sleep(20 * time.Second)
	c.Close()
}

// acceptOne accepts a connection, reads a frame, and returns the server fd.
func acceptOne(l *net.UnixListener) (*net.UnixConn, *os.File, int, time.Time) {
	l.SetDeadline(time.Now().Add(20 * time.Second))
	sc, err := l.AcceptUnix()
	must(err)
	at := time.Now()
	sc.SetReadDeadline(time.Now().Add(10 * time.Second))
	buf := make([]byte, 64)
	_, err = sc.Read(buf)
	must(err)
	sf, err := sc.File()
	must(err)
	return sc, sf, int(sf.Fd()), at
}

// ---------- experiment 4: what a signature verdict is actually worth ----------

func signatureStrength() {
	fmt.Println("\n##################################################")
	fmt.Println("# EXPERIMENT 4: proof strength of differently-signed peers")
	fmt.Println("##################################################")

	self, err := os.Executable()
	must(err)

	type variant struct {
		name string
		prep []string // codesign args after the binary is copied
	}
	variants := []variant{
		{"go-linker ad-hoc (as built)", nil},
		{"explicit ad-hoc (codesign -s -)", []string{"-f", "-s", "-"}},
		{"ad-hoc + hardened runtime", []string{"-f", "-s", "-", "-o", "runtime"}},
		{"signature removed", []string{"--remove-signature"}},
	}

	for _, v := range variants {
		dir, err := os.MkdirTemp("", "sig")
		must(err)
		bin := dir + "/peer"
		data, err := os.ReadFile(self)
		must(err)
		must(os.WriteFile(bin, data, 0o755))
		if v.prep != nil {
			args := append(append([]string{}, v.prep...), bin)
			out, err := exec.Command("/usr/bin/codesign", args...).CombinedOutput()
			if err != nil {
				fmt.Printf("\n--- %s: codesign failed: %v %s\n", v.name, err, out)
				os.RemoveAll(dir)
				continue
			}
		}
		desc, _ := exec.Command("/usr/bin/codesign", "-dv", bin).CombinedOutput()

		fmt.Printf("\n--- %s ---\n", v.name)
		l, path, cleanup := listen()
		cmd := exec.Command(bin, "client", path)
		if err := cmd.Start(); err != nil {
			fmt.Printf("could not start: %v\n", err)
			cleanup()
			os.RemoveAll(dir)
			continue
		}
		// An unsigned binary on Apple Silicon is killed at exec, so the
		// connection never arrives. Notice that rather than hanging.
		l.SetDeadline(time.Now().Add(3 * time.Second))
		probeConn, err := l.AcceptUnix()
		if err != nil {
			st := "<still running>"
			cmd.Process.Kill()
			if ps, werr := cmd.Process.Wait(); werr == nil {
				st = ps.String()
			}
			fmt.Printf("codesign -dv: %s\n", firstLines(string(desc), 4))
			fmt.Printf("PEER NEVER CONNECTED: %v -- process result: %s\n", err, st)
			cleanup()
			os.RemoveAll(dir)
			continue
		}
		at := time.Now()
		probeConn.SetReadDeadline(time.Now().Add(5 * time.Second))
		rbuf := make([]byte, 64)
		probeConn.Read(rbuf)
		sf, err := probeConn.File()
		must(err)
		sc, sfd := probeConn, int(sf.Fd())

		fmt.Printf("codesign -dv: %s\n", firstLines(string(desc), 4))
		if tk, err := rawPeerToken(sfd); err == nil {
			fmt.Printf("raw Security  : %v\n", verifyToken(tk))
		}
		p, err := identity.OfHandle(identity.Handle(sfd), &identity.Options{ConnectedAt: at})
		if err != nil {
			fmt.Printf("package       : ERROR %v\n", err)
		} else {
			code, proof := p.Code.Get()
			pkg, pkgProof := p.Package.Get()
			fmt.Printf("package Code  : proof=%v trusted=%v status=%q subject=%q team=%q\n",
				proof, code.Trusted, code.Status, code.Subject, code.TeamID)
			fmt.Printf("package Pkg   : proof=%v value=%q\n", pkgProof, pkg)
		}

		sf.Close()
		sc.Close()
		cmd.Process.Kill()
		cmd.Wait()
		cleanup()
		os.RemoveAll(dir)
	}
}

func firstLines(s string, n int) string {
	out := ""
	c := 0
	for _, r := range s {
		if r == '\n' {
			c++
			if c >= n {
				break
			}
		}
		out += string(r)
	}
	return out
}

// ---------- experiment 5: does the audit token actually bind, or is it a pid ----------

func tokenBinding() {
	fmt.Println("\n##################################################")
	fmt.Println("# EXPERIMENT 5: is kSecGuestAttributeAudit really honoured,")
	fmt.Println("# or does SecCodeCopyGuestWithAttributes just use the pid?")
	fmt.Println("##################################################")

	self, err := os.Executable()
	must(err)
	l, path, cleanup := listen()
	defer cleanup()
	cmd := exec.Command(self, "client", path)
	must(cmd.Start())
	defer func() { cmd.Process.Kill(); cmd.Wait() }()
	sc, sf, sfd, _ := acceptOne(l)
	defer sf.Close()
	defer sc.Close()

	tk, err := rawPeerToken(sfd)
	must(err)
	fmt.Printf("genuine token for peer pid %d: pidversion=%d euid=%d asid=%d\n",
		tk.pid(), tk.vers(), tk.euid(), tk.asid())
	fmt.Printf("  as-is                     : %v\n", verifyToken(tk))

	bad := tk
	bad[7] = tk.vers() + 1000
	fmt.Printf("  pidversion +1000          : %v\n", verifyToken(bad))

	bad = tk
	bad[5] = uint32(os.Getpid()) // this probe, a different program
	fmt.Printf("  pid -> this probe (%6d): %v\n", os.Getpid(), verifyToken(bad))

	bad = tk
	bad[5] = uint32(os.Getpid())
	bad[7] = 0
	fmt.Printf("  pid -> probe, pidversion 0: %v\n", verifyToken(bad))

	bad = tk
	bad[1] = 0 // euid root
	bad[3] = 0
	fmt.Printf("  euid/ruid -> 0            : %v\n", verifyToken(bad))

	bad = tk
	bad[5] = 1 // launchd
	bad[7] = 0
	fmt.Printf("  pid -> 1 (launchd), ver 0 : %v\n", verifyToken(bad))

	// A pid that does not exist.
	bad = tk
	bad[5] = 999999
	fmt.Printf("  pid -> 999999 (no such)   : %v\n", verifyToken(bad))

	execPidversion()
}

// ---------- experiment 7: the attack against a service that does everything right ----------
//
// The service sets Options.ConnectedAt in its accept loop, as the documentation
// tells it to, and demands "anchor apple" so that only Apple's own binaries are
// accepted. The caller is an ad-hoc signed binary that cannot satisfy that
// requirement. It forks a placeholder first, connects, then execs /bin/cat into
// the placeholder and makes it write.
func requirementUnderAttack() {
	fmt.Println("\n##################################################")
	fmt.Println("# EXPERIMENT 7: does CodeRequirement \"anchor apple\" survive the drift?")
	fmt.Println("##################################################")

	// (a) the honest case: this ad-hoc binary against "anchor apple"
	{
		self, _ := os.Executable()
		l, path, cleanup := listen()
		cmd := exec.Command(self, "client", path)
		must(cmd.Start())
		sc, sf, sfd, at := acceptOne(l)
		p, err := identity.OfHandle(identity.Handle(sfd), &identity.Options{
			ConnectedAt: at, CodeRequirement: "anchor apple"})
		if err != nil {
			fmt.Printf("(a) honest ad-hoc peer: ERROR %v\n", err)
		} else {
			code, proof := p.Code.Get()
			fmt.Printf("(a) honest ad-hoc peer vs \"anchor apple\": proof=%v trusted=%v status=%q\n",
				proof, code.Trusted, code.Status)
		}
		sf.Close()
		sc.Close()
		cmd.Process.Kill()
		cmd.Wait()
		cleanup()
	}

	// (b) the same caller, drifting the socket onto a pre-forked /bin/cat
	{
		l, path, cleanup := listen()
		defer cleanup()
		cfd, err := unix.Socket(unix.AF_UNIX, unix.SOCK_STREAM, 0)
		must(err)
		cf := os.NewFile(uintptr(cfd), "client")
		pr, pw, err := os.Pipe()
		must(err)
		sh := exec.Command("/bin/sh", "-c", "read a; exec /bin/cat")
		sh.Stdin = pr
		sh.Stdout = cf
		must(sh.Start())
		pr.Close()
		defer func() { pw.Close(); sh.Process.Kill(); sh.Wait() }()

		time.Sleep(300 * time.Millisecond)
		must(unix.Connect(cfd, &unix.SockaddrUnix{Name: path}))
		unix.Write(cfd, []byte("hello"))
		sc, sf, sfd, at := acceptOne(l)
		defer sf.Close()
		defer sc.Close()

		pw.Write([]byte("go\n"))
		time.Sleep(300 * time.Millisecond)
		pw.Write([]byte("i am cat\n"))
		sc.SetReadDeadline(time.Now().Add(10 * time.Second))
		sc.Read(make([]byte, 64))

		p, err := identity.OfHandle(identity.Handle(sfd), &identity.Options{
			ConnectedAt: at, CodeRequirement: "anchor apple"})
		if err != nil {
			fmt.Printf("(b) drifted peer: ERROR %v\n", err)
			return
		}
		code, proof := p.Code.Get()
		path2, pathProof := p.Path.Get()
		pkg, _ := p.Package.Get()
		fmt.Printf("(b) SAME caller, socket drifted to a pre-forked /bin/cat, vs \"anchor apple\":\n")
		fmt.Printf("    Code    proof=%v trusted=%v status=%q subject=%q\n",
			proof, code.Trusted, code.Status, code.Subject)
		fmt.Printf("    Path    proof=%v value=%q\n", pathProof, path2)
		fmt.Printf("    Package value=%q\n", pkg)
		if err := p.Check(identity.Need{
			User: identity.ProofKernel, Process: identity.ProofBound,
			Path: identity.ProofBound, Code: identity.ProofBound}); err == nil {
			fmt.Printf("    >>> Peer.Check(user=kernel process=bound path=bound code=bound) PASSED <<<\n")
		} else {
			fmt.Printf("    Peer.Check refused: %v\n", err)
		}
	}
}

// execPidversion answers whether p_idversion -- the field that is supposed to
// make a pid+version pair name one instance of a process -- survives exec(2).
// The only route to it without private headers is the socket token itself, so
// the same process is made to write to a socket before and after it execs.
func execPidversion() {
	fmt.Println("\n##################################################")
	fmt.Println("# EXPERIMENT 6: does pidversion (and p_starttime) survive exec(2)?")
	fmt.Println("##################################################")

	l, path, cleanup := listen()
	defer cleanup()

	cfd, err := unix.Socket(unix.AF_UNIX, unix.SOCK_STREAM, 0)
	must(err)
	cf := os.NewFile(uintptr(cfd), "client")
	pr, pw, err := os.Pipe()
	must(err)
	// The first write comes from sh itself (echo is a builtin), so last_pid
	// names sh. After exec, the same pid is /bin/cat.
	sh := exec.Command("/bin/sh", "-c", "read a; echo pre-exec; read b; exec /bin/cat")
	sh.Stdin = pr
	sh.Stdout = cf
	must(sh.Start())
	pr.Close()
	defer func() { pw.Close(); sh.Process.Kill(); sh.Wait() }()

	must(unix.Connect(cfd, &unix.SockaddrUnix{Name: path}))
	at := time.Now()
	_, err = unix.Write(cfd, []byte("hello"))
	must(err)
	sc, sf, sfd, _ := acceptOne(l)
	defer sf.Close()
	defer sc.Close()

	buf := make([]byte, 64)
	pw.Write([]byte("go\n"))
	sc.SetReadDeadline(time.Now().Add(10 * time.Second))
	sc.Read(buf)
	before, err := rawPeerToken(sfd)
	must(err)
	st1, _ := startTime(int(before.pid()))
	fmt.Printf("  /bin/sh  pid=%d pidversion=%d start=%s exec=%s\n",
		before.pid(), before.vers(), st1.Format(time.RFC3339Nano), execPath(int(before.pid())))

	pw.Write([]byte("go2\n"))
	time.Sleep(400 * time.Millisecond)
	pw.Write([]byte("now cat\n"))
	sc.SetReadDeadline(time.Now().Add(10 * time.Second))
	sc.Read(buf)
	after, err := rawPeerToken(sfd)
	must(err)
	st2, _ := startTime(int(after.pid()))
	fmt.Printf("  /bin/cat pid=%d pidversion=%d start=%s exec=%s\n",
		after.pid(), after.vers(), st2.Format(time.RFC3339Nano), execPath(int(after.pid())))
	fmt.Printf("  same pid=%v  pidversion changed=%v  start time changed=%v\n",
		before.pid() == after.pid(), before.vers() != after.vers(), !st1.Equal(st2))
	fmt.Printf("  connectedAt=%s -> the post-exec process still predates it: %v\n",
		at.Format(time.RFC3339Nano), !st2.After(at))
}
