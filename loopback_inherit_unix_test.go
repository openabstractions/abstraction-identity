//go:build linux || darwin

package identity

import (
	"net"
	"os/exec"
)

// inheritSocket gives the child a duplicate of the connected socket as its
// descriptor 3, so the child holds the same socket after this process exits.
func inheritSocket(cmd *exec.Cmd, c *net.TCPConn) error {
	f, err := c.File()
	if err != nil {
		return err
	}
	cmd.ExtraFiles = append(cmd.ExtraFiles, f)
	return nil
}
