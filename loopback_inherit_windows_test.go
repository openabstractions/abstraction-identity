//go:build windows

package identity

import (
	"net"
	"os/exec"
	"syscall"

	"golang.org/x/sys/windows"
)

// inheritSocket marks the connected socket inheritable and names it in the
// child's handle list, so the child holds the same socket after this process
// exits.
func inheritSocket(cmd *exec.Cmd, c *net.TCPConn) error {
	raw, err := c.SyscallConn()
	if err != nil {
		return err
	}
	var h uintptr
	if err := raw.Control(func(fd uintptr) { h = fd }); err != nil {
		return err
	}
	if err := windows.SetHandleInformation(windows.Handle(h), windows.HANDLE_FLAG_INHERIT, windows.HANDLE_FLAG_INHERIT); err != nil {
		return err
	}
	cmd.SysProcAttr = &syscall.SysProcAttr{AdditionalInheritedHandles: []syscall.Handle{syscall.Handle(h)}}
	return nil
}
