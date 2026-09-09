//go:build darwin && cgo

// Command probe verifies, on real hardware and with raw syscalls, the claims
// the abstraction-identity package makes about macOS. It does not use the
// package's own tests; where it consults the package it says so explicitly and
// prints the raw kernel answer beside it.
package main

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"time"
	"unsafe"

	identity "github.com/openabstractions/abstraction-identity"
	"golang.org/x/sys/unix"
)

// ---------- raw kernel reads, written from scratch here ----------

type token [8]uint32

func (t token) auid() uint32 { return t[0] }
func (t token) euid() uint32 { return t[1] }
func (t token) pid() uint32  { return t[5] }
func (t token) asid() uint32 { return t[6] }
func (t token) vers() uint32 { return t[7] }

func rawPeerToken(fd int) (token, error) {
	var tk token
	size := uint32(unsafe.Sizeof(tk))
	_, _, errno := unix.Syscall6(uintptr(syscall.SYS_GETSOCKOPT), uintptr(fd),
		uintptr(unix.SOL_LOCAL), uintptr(unix.LOCAL_PEERTOKEN),
		uintptr(unsafe.Pointer(&tk[0])), uintptr(unsafe.Pointer(&size)), 0)
	if errno != 0 {
		return tk, errno
	}
	return tk, nil
}

func rawPeerPID(fd int) (int, error) {
	return unix.GetsockoptInt(fd, unix.SOL_LOCAL, unix.LOCAL_PEERPID)
}

func rawPeerCred(fd int) (*unix.Xucred, error) {
	return unix.GetsockoptXucred(fd, unix.SOL_LOCAL, unix.LOCAL_PEERCRED)
}

func startTime(pid int) (time.Time, error) {
	kp, err := unix.SysctlKinfoProc("kern.proc.pid", pid)
	if err != nil {
		return time.Time{}, err
	}
	tv := kp.Proc.P_starttime
	return time.Unix(tv.Sec, int64(tv.Usec)*1000), nil
}

func execPath(pid int) string {
	buf, err := unix.SysctlRaw("kern.procargs2", pid)
	if err != nil || len(buf) < 5 {
		return fmt.Sprintf("<procargs2: %v>", err)
	}
	rest := buf[4:]
	for i, b := range rest {
		if b == 0 {
			return string(rest[:i])
		}
	}
	return "<no path>"
}

// report prints everything the kernel and the package will say about the peer
// of fd, at this instant.
func report(label string, sfd int, connectedAt time.Time) {
	fmt.Printf("\n=== %s ===\n", label)
	if xu, err := rawPeerCred(sfd); err != nil {
		fmt.Printf("  LOCAL_PEERCRED : ERROR %v\n", err)
	} else {
		fmt.Printf("  LOCAL_PEERCRED : version=%d uid=%d ngroups=%d gid0=%d\n",
			xu.Version, xu.Uid, xu.Ngroups, func() uint32 {
				if xu.Ngroups > 0 {
					return xu.Groups[0]
				}
				return 0
			}())
	}
	if pid, err := rawPeerPID(sfd); err != nil {
		fmt.Printf("  LOCAL_PEERPID  : ERROR %v\n", err)
	} else {
		fmt.Printf("  LOCAL_PEERPID  : %d  exec=%s\n", pid, execPath(pid))
	}
	if tk, err := rawPeerToken(sfd); err != nil {
		fmt.Printf("  LOCAL_PEERTOKEN: ERROR %v (errno %d)\n", err, err.(syscall.Errno))
	} else {
		st, sterr := startTime(int(tk.pid()))
		fmt.Printf("  LOCAL_PEERTOKEN: pid=%d pidversion=%d euid=%d auid=%d asid=%d\n",
			tk.pid(), tk.vers(), tk.euid(), tk.auid(), tk.asid())
		fmt.Printf("                   exec=%s\n", execPath(int(tk.pid())))
		if sterr != nil {
			fmt.Printf("                   start=<%v>\n", sterr)
		} else {
			fmt.Printf("                   start=%s  connectedAt=%s  startedAfterConnect=%v\n",
				st.Format(time.RFC3339Nano), connectedAt.Format(time.RFC3339Nano), st.After(connectedAt))
		}
	}
	p, err := identity.OfHandle(identity.Handle(sfd), &identity.Options{ConnectedAt: connectedAt})
	if err != nil {
		fmt.Printf("  package OfHandle: ERROR %v\n", err)
		return
	}
	fmt.Printf("  package        : %v\n", p)
	for _, n := range p.Notes {
		fmt.Printf("                   note: %s\n", n)
	}
}

func listen() (*net.UnixListener, string, func()) {
	dir, err := os.MkdirTemp("", "pb")
	must(err)
	path := filepath.Join(dir, "s")
	l, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	must(err)
	return l, path, func() { l.Close(); os.RemoveAll(dir) }
}

func must(err error) {
	if err != nil {
		panic(err)
	}
}

// ---------- experiment 1: does last_pid drift, with the drifted process ALIVE ----------

func driftLive() {
	fmt.Println("\n##################################################")
	fmt.Println("# EXPERIMENT 1: socket owner drift, impersonator STAYS ALIVE")
	fmt.Println("# (the repo's own test lets /bin/echo exit before it looks)")
	fmt.Println("##################################################")

	l, path, cleanup := listen()
	defer cleanup()

	cfd, err := unix.Socket(unix.AF_UNIX, unix.SOCK_STREAM, 0)
	must(err)
	must(unix.Connect(cfd, &unix.SockaddrUnix{Name: path}))
	connectedAt := time.Now()
	_, err = unix.Write(cfd, []byte("hello"))
	must(err)

	sc, err := l.AcceptUnix()
	must(err)
	defer sc.Close()
	buf := make([]byte, 256)
	sc.SetReadDeadline(time.Now().Add(10 * time.Second))
	n, err := sc.Read(buf)
	must(err)
	fmt.Printf("server read %q from the real caller (this probe, pid %d)\n", buf[:n], os.Getpid())

	sf, err := sc.File()
	must(err)
	defer sf.Close()
	sfd := int(sf.Fd())

	report("BASELINE: the process that connected and wrote is this probe", sfd, connectedAt)

	// Hand the connected socket to /bin/cat as its stdout and keep cat alive.
	pr, pw, err := os.Pipe()
	must(err)
	cf := os.NewFile(uintptr(cfd), "client")
	cat := exec.Command("/bin/cat")
	cat.Stdin = pr
	cat.Stdout = cf
	must(cat.Start())
	pr.Close()
	fmt.Printf("\nspawned /bin/cat as pid %d with the connected socket as its stdout\n", cat.Process.Pid)

	// Make cat perform a write on the socket, and prove it did by reading it.
	_, err = pw.Write([]byte("i am cat\n"))
	must(err)
	sc.SetReadDeadline(time.Now().Add(10 * time.Second))
	n, err = sc.Read(buf)
	must(err)
	fmt.Printf("server read %q -- written by /bin/cat, which is STILL RUNNING\n", buf[:n])

	report("AFTER DRIFT: /bin/cat (pid above) performed the last socket write and is alive", sfd, connectedAt)

	// Now let cat exit, and look again: this is the state the repo's test saw.
	pw.Close()
	cat.Wait()
	time.Sleep(100 * time.Millisecond)
	report("AFTER THE IMPERSONATOR EXITED (this is what the repo test observed)", sfd, connectedAt)
}

// ---------- experiment 2: defeat Options.ConnectedAt with a pre-existing process ----------

func driftPrefork() {
	fmt.Println("\n##################################################")
	fmt.Println("# EXPERIMENT 2: the impersonator EXISTED BEFORE the connection")
	fmt.Println("# A helper is forked first, holding the not-yet-connected socket.")
	fmt.Println("# After the connection it exec()s /bin/cat, keeping its pid and")
	fmt.Println("# its p_starttime -- which predates the connection.")
	fmt.Println("##################################################")

	l, path, cleanup := listen()
	defer cleanup()

	// The client socket exists but is NOT connected yet.
	cfd, err := unix.Socket(unix.AF_UNIX, unix.SOCK_STREAM, 0)
	must(err)
	cf := os.NewFile(uintptr(cfd), "client")

	pr, pw, err := os.Pipe()
	must(err)
	sh := exec.Command("/bin/sh", "-c", "read line; exec /bin/cat")
	sh.Stdin = pr
	sh.Stdout = cf
	must(sh.Start())
	pr.Close()
	helperPID := sh.Process.Pid
	hs, _ := startTime(helperPID)
	fmt.Printf("forked helper /bin/sh as pid %d, start=%s, exec=%s\n",
		helperPID, hs.Format(time.RFC3339Nano), execPath(helperPID))

	time.Sleep(400 * time.Millisecond)

	must(unix.Connect(cfd, &unix.SockaddrUnix{Name: path}))
	connectedAt := time.Now()
	fmt.Printf("connected at %s (helper is %s older)\n",
		connectedAt.Format(time.RFC3339Nano), connectedAt.Sub(hs))
	_, err = unix.Write(cfd, []byte("hello"))
	must(err)

	sc, err := l.AcceptUnix()
	must(err)
	defer sc.Close()
	buf := make([]byte, 256)
	sc.SetReadDeadline(time.Now().Add(10 * time.Second))
	n, err := sc.Read(buf)
	must(err)
	fmt.Printf("server read %q from the real caller (this probe, pid %d)\n", buf[:n], os.Getpid())

	sf, err := sc.File()
	must(err)
	defer sf.Close()
	sfd := int(sf.Fd())

	report("BASELINE: the connecting process is this probe", sfd, connectedAt)

	// Tell the helper to become /bin/cat, then make it write.
	_, err = pw.Write([]byte("go\n"))
	must(err)
	time.Sleep(400 * time.Millisecond)
	as, _ := startTime(helperPID)
	fmt.Printf("\nhelper pid %d after exec: exec=%s start=%s (unchanged by exec: %v)\n",
		helperPID, execPath(helperPID), as.Format(time.RFC3339Nano), as.Equal(hs))

	_, err = pw.Write([]byte("i am cat\n"))
	must(err)
	sc.SetReadDeadline(time.Now().Add(10 * time.Second))
	n, err = sc.Read(buf)
	must(err)
	fmt.Printf("server read %q -- written by the pre-existing helper now running /bin/cat\n", buf[:n])

	report("AFTER DRIFT TO A PRE-EXISTING PROCESS RUNNING /bin/cat", sfd, connectedAt)

	pw.Close()
	sh.Process.Kill()
	sh.Wait()
}

// ---------- experiment 3: LOCAL_PEERCRED after the peer exits, and on a listener ----------

func peerCredLifetime() {
	fmt.Println("\n##################################################")
	fmt.Println("# EXPERIMENT 3: what survives the peer, and what a listening socket answers")
	fmt.Println("##################################################")

	l, path, cleanup := listen()
	defer cleanup()

	// (a) listening socket
	lf, err := l.File()
	must(err)
	lfd := int(lf.Fd())
	ac, acerr := unix.GetsockoptInt(lfd, unix.SOL_SOCKET, unix.SO_ACCEPTCONN)
	fmt.Printf("listening socket: SO_ACCEPTCONN = %d (err %v)  <-- the package refuses on this\n", ac, acerr)
	if xu, err := rawPeerCred(lfd); err != nil {
		fmt.Printf("listening socket: LOCAL_PEERCRED = ERROR %v\n", err)
	} else {
		fmt.Printf("listening socket: LOCAL_PEERCRED = uid %d (this service's own!)\n", xu.Uid)
	}
	if _, err := identity.OfHandle(identity.Handle(lfd), nil); err != nil {
		fmt.Printf("listening socket: package OfHandle = %v (ErrNotServerEnd=%v)\n",
			err, errorsIs(err, identity.ErrNotServerEnd))
	}
	lf.Close()

	// (b) a peer that connects, writes and exits
	cfd, err := unix.Socket(unix.AF_UNIX, unix.SOCK_STREAM, 0)
	must(err)
	cf := os.NewFile(uintptr(cfd), "client")
	sh := exec.Command("/bin/sh", "-c", "/bin/echo from-a-child; exit 0")
	sh.Stdout = cf
	must(unix.Connect(cfd, &unix.SockaddrUnix{Name: path}))
	connectedAt := time.Now()
	must(sh.Start())

	sc, err := l.AcceptUnix()
	must(err)
	defer sc.Close()
	buf := make([]byte, 256)
	sc.SetReadDeadline(time.Now().Add(10 * time.Second))
	n, _ := sc.Read(buf)
	fmt.Printf("server read %q\n", buf[:n])
	sh.Wait()
	cf.Close() // drop the parent's handle too; nothing alive owns the peer end
	time.Sleep(200 * time.Millisecond)

	sf, err := sc.File()
	must(err)
	defer sf.Close()
	report("PEER (and every process that touched it) HAS EXITED", int(sf.Fd()), connectedAt)
}

func errorsIs(err, target error) bool {
	for err != nil {
		if err == target {
			return true
		}
		u, ok := err.(interface{ Unwrap() error })
		if !ok {
			return false
		}
		err = u.Unwrap()
	}
	return false
}

func main() {
	fmt.Printf("probe pid %d uid %d\n", os.Getpid(), os.Getuid())
	fmt.Printf("ceiling: %+v\n", identity.Ceiling())
	which := "all"
	if len(os.Args) > 1 {
		which = os.Args[1]
	}
	switch which {
	case "client":
		clientMode(os.Args[2])
	case "1":
		driftLive()
	case "2":
		driftPrefork()
	case "3":
		peerCredLifetime()
	case "4":
		signatureStrength()
		requirementUnderAttack()
	case "9":
		listenerDetection()
	case "8":
		connectSetsLastPid()
	case "7":
		requirementUnderAttack()
	case "5":
		tokenBinding()
	default:
		driftLive()
		driftPrefork()
		peerCredLifetime()
		signatureStrength()
		requirementUnderAttack()
		tokenBinding()
	}
}
