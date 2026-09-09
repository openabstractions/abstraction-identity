//go:build !windows

package listen

import (
	"net"
	"os"
	"time"

	identity "github.com/openabstractions/abstraction-identity"
)

type unixConn struct {
	net.Conn
	binding *identity.Binding
	err     error
}

func (c *unixConn) Bind() (*identity.Binding, error) { return c.binding, c.err }

func (c *unixConn) Close() error {
	if c.binding != nil {
		c.binding.Close()
	}
	return c.Conn.Close()
}

type unixListener struct{ net.Listener }

func Listen(path string) (Listener, error) {
	os.Remove(path)
	l, err := net.Listen("unix", path)
	if err != nil {
		return nil, err
	}
	os.Chmod(path, 0o600)
	return unixListener{l}, nil
}

func (l unixListener) Accept() (Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	b, berr := identity.BindConn(c, &identity.Options{ConnectedAt: time.Now()})
	return &unixConn{Conn: c, binding: b, err: berr}, nil
}

func (l unixListener) Close() error { return l.Listener.Close() }

func Dial(path string) (net.Conn, error) { return net.Dial("unix", path) }

func Endpoint(service string) string {
	if d := os.Getenv("XDG_RUNTIME_DIR"); d != "" {
		return d + "/openabstractions-" + service + ".sock"
	}
	return os.TempDir() + "/openabstractions-" + service + "-" + os.Getenv("USER") + ".sock"
}
