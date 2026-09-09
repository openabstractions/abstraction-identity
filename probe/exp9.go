//go:build darwin && cgo

package main

import (
	"fmt"
	"os"
	"os/exec"
	"time"

	"golang.org/x/sys/unix"
)

func describe(tag string, fd int) {
	sn, snerr := unix.Getsockname(fd)
	pn, pnerr := unix.Getpeername(fd)
	ac, acerr := unix.GetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_ACCEPTCONN)
	_, pcerr := rawPeerCred(fd)
	fmt.Printf("  %-34s getsockname=%v/%v getpeername=%v/%v SO_ACCEPTCONN=%d/%v PEERCRED=%v\n",
		tag, sockAddrStr(sn), snerr, sockAddrStr(pn), pnerr, ac, acerr, pcerr)
}

func sockAddrStr(sa unix.Sockaddr) string {
	if u, ok := sa.(*unix.SockaddrUnix); ok {
		return fmt.Sprintf("unix:%q", u.Name)
	}
	if sa == nil {
		return "<nil>"
	}
	return fmt.Sprintf("%T", sa)
}

// listenerDetection finds a way to tell a listening AF_UNIX socket from an
// accepted one on macOS, where SO_ACCEPTCONN is ENOPROTOOPT.
func listenerDetection() {
	fmt.Println("\n##################################################")
	fmt.Println("# EXPERIMENT 9: how to detect a listening AF_UNIX socket on darwin")
	fmt.Println("##################################################")

	l, path, cleanup := listen()
	defer cleanup()

	lf, err := l.File()
	must(err)
	describe("LISTENING socket", int(lf.Fd()))

	cfd, err := unix.Socket(unix.AF_UNIX, unix.SOCK_STREAM, 0)
	must(err)
	cf := os.NewFile(uintptr(cfd), "client")
	sh := exec.Command("/bin/sh", "-c", "read a; echo hi; read b")
	pr, pw, err := os.Pipe()
	must(err)
	sh.Stdin = pr
	sh.Stdout = cf
	must(sh.Start())
	pr.Close()
	must(unix.Connect(cfd, &unix.SockaddrUnix{Name: path}))
	unix.Write(cfd, []byte("x"))

	l.SetDeadline(time.Now().Add(10 * time.Second))
	sc, err := l.AcceptUnix()
	must(err)
	sc.SetReadDeadline(time.Now().Add(5 * time.Second))
	sc.Read(make([]byte, 8))
	sf, err := sc.File()
	must(err)
	describe("ACCEPTED conn, peer alive", int(sf.Fd()))

	describe("CLIENT end (not server end!)", cfd)

	pw.Close()
	sh.Process.Kill()
	sh.Wait()
	cf.Close()
	time.Sleep(200 * time.Millisecond)
	describe("ACCEPTED conn, peer gone", int(sf.Fd()))

	sf.Close()
	sc.Close()
	lf.Close()
}
