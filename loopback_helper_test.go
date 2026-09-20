//go:build windows || linux || darwin

package identity

// The client half of the loopback tests, run as a child of the test binary.
//
// loopbackPassEnv selects the passing client: it dials the address, reports
// its pid, waits for one line on stdin, starts a holder child that inherits the
// connected socket, reports the holder's pid and exits. The holder keeps the
// socket open until it is killed. After that the connection is still
// established, and the process that opened it is gone.

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"os/exec"
	"time"
)

const (
	loopbackPassEnv = "IDENTITY_TEST_LOOPBACK_PASS"
	loopbackHoldEnv = "IDENTITY_TEST_LOOPBACK_HOLD"
)

func loopbackHelperMain() (bool, int) {
	switch {
	case os.Getenv(loopbackHoldEnv) != "":
		time.Sleep(60 * time.Second)
		return true, 0
	case os.Getenv(loopbackPassEnv) != "":
		return true, runLoopbackPasser(os.Getenv(loopbackPassEnv))
	}
	return false, 0
}

func runLoopbackPasser(addr string) int {
	c, err := net.Dial("tcp4", addr)
	if err != nil {
		fmt.Fprintln(os.Stderr, "passer: dial:", err)
		return 1
	}
	fmt.Printf("pid %d\n", os.Getpid())
	if _, err := bufio.NewReader(os.Stdin).ReadString('\n'); err != nil {
		fmt.Fprintln(os.Stderr, "passer: no signal:", err)
		return 1
	}
	exe, err := os.Executable()
	if err != nil {
		return 1
	}
	holder := exec.Command(exe)
	holder.Env = append(os.Environ(), loopbackPassEnv+"=", loopbackHoldEnv+"=1")
	if err := inheritSocket(holder, c.(*net.TCPConn)); err != nil {
		fmt.Fprintln(os.Stderr, "passer: inherit:", err)
		return 1
	}
	if err := holder.Start(); err != nil {
		fmt.Fprintln(os.Stderr, "passer: start holder:", err)
		return 1
	}
	fmt.Printf("holder %d\n", holder.Process.Pid)
	// Exit without closing: the holder keeps the connection established.
	os.Exit(0)
	return 0
}
