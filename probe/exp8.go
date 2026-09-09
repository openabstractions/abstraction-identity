//go:build darwin && cgo

package main

import (
	"fmt"
	"os"
	"os/exec"
	"time"

	"golang.org/x/sys/unix"
)

// connectSetsLastPid answers whether last_pid is set by connect(2) itself, or
// only by a subsequent read/write. If connect sets it, a service can pin the
// audit token in its accept loop and detect every later drift; if it does not,
// there is no instant at which the socket is known to name the connector and
// pinning has nothing to pin.
func connectSetsLastPid() {
	fmt.Println("\n##################################################")
	fmt.Println("# EXPERIMENT 8: is last_pid set by connect(2), before any write?")
	fmt.Println("##################################################")

	l, path, cleanup := listen()
	defer cleanup()

	// A child connects and does NOT write. The parent never touches the
	// client socket at all.
	cfd, err := unix.Socket(unix.AF_UNIX, unix.SOCK_STREAM, 0)
	must(err)
	cf := os.NewFile(uintptr(cfd), "client")
	pr, pw, err := os.Pipe()
	must(err)
	// sh holds the socket as stdout but writes nothing until told.
	sh := exec.Command("/bin/sh", "-c", "read a; echo from-sh; read b")
	sh.Stdin = pr
	sh.Stdout = cf
	must(sh.Start())
	pr.Close()
	defer func() { pw.Close(); sh.Process.Kill(); sh.Wait() }()

	must(unix.Connect(cfd, &unix.SockaddrUnix{Name: path}))
	at := time.Now()
	fmt.Printf("parent pid %d called connect(); child sh is pid %d; nobody has written\n",
		os.Getpid(), sh.Process.Pid)

	l.SetDeadline(time.Now().Add(10 * time.Second))
	sc, err := l.AcceptUnix()
	must(err)
	defer sc.Close()
	sf, err := sc.File()
	must(err)
	defer sf.Close()
	sfd := int(sf.Fd())

	if pid, err := rawPeerPID(sfd); err != nil {
		fmt.Printf("  at accept, before any write: LOCAL_PEERPID ERROR %v\n", err)
	} else {
		fmt.Printf("  at accept, before any write: LOCAL_PEERPID = %d (%s)\n", pid, execPath(pid))
		fmt.Printf("    connector(parent)=%d  holder(child sh)=%d\n", os.Getpid(), sh.Process.Pid)
	}
	if tk, err := rawPeerToken(sfd); err != nil {
		fmt.Printf("  at accept, before any write: LOCAL_PEERTOKEN ERROR %v\n", err)
	} else {
		fmt.Printf("  at accept, before any write: token pid=%d pidversion=%d\n", tk.pid(), tk.vers())
	}

	// Now let the child write and look again.
	pw.Write([]byte("go\n"))
	sc.SetReadDeadline(time.Now().Add(10 * time.Second))
	sc.Read(make([]byte, 64))
	if tk, err := rawPeerToken(sfd); err == nil {
		fmt.Printf("  after the CHILD wrote:       token pid=%d (%s)\n", tk.pid(), execPath(int(tk.pid())))
	}
	_ = at
}
