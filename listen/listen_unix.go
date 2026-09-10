//go:build !windows

package listen

import (
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"syscall"
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

type unixListener struct {
	net.Listener
	lock *os.File
}

// The endpoint belongs to whoever holds the lock beside it, never to whoever
// unlinked last. Removing the socket before binding, which is what this did,
// lets a second start detach a healthy first listener from its address, and a
// probe before the unlink only narrows that window - the answer is stale by
// the time it is acted on. The lock is taken first and held for the listener's
// life, so a socket at the path is stale exactly when nobody holds the lock,
// only the holder ever removes one, and two starts race on the lock rather
// than on the address.
func Listen(path string) (Listener, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	lock, err := os.OpenFile(path+".lock", os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		lock.Close()
		if errors.Is(err, syscall.EWOULDBLOCK) {
			return nil, fmt.Errorf("%w: another listener holds %s", ErrTaken, path)
		}
		return nil, err
	}
	if err := clearStale(path); err != nil {
		lock.Close()
		return nil, err
	}
	l, err := net.Listen("unix", path)
	if err != nil {
		lock.Close()
		return nil, err
	}
	if err := os.Chmod(path, 0o600); err != nil {
		l.Close()
		lock.Close()
		return nil, fmt.Errorf("listen: %s was bound but could not be shut to other accounts: %w", path, err)
	}
	return &unixListener{Listener: l, lock: lock}, nil
}

// Only the lock's holder reaches here, so a socket at the path answers to
// nobody and goes. Anything that is not a socket is somebody else's file,
// whatever this path was meant to be, and is refused rather than deleted.
func clearStale(path string) error {
	fi, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if fi.Mode().Type()&os.ModeSocket == 0 {
		return fmt.Errorf("%w: %s is not a socket, and a listener does not remove it", ErrTaken, path)
	}
	return os.Remove(path)
}

func (l *unixListener) Accept() (Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	b, berr := identity.BindConn(c, &identity.Options{ConnectedAt: time.Now()})
	return &unixConn{Conn: c, binding: b, err: berr}, nil
}

// The socket is unlinked by the listener it belongs to, and the lock is let go
// only after that, so nothing sees an address with no listener behind it. The
// lock file itself stays: removing it is what would put two starters back on
// one race.
func (l *unixListener) Close() error {
	err := l.Listener.Close()
	l.lock.Close()
	return err
}

func Dial(path string) (net.Conn, error) { return net.Dial("unix", path) }

func Endpoint(service string) string {
	if d := os.Getenv("XDG_RUNTIME_DIR"); d != "" {
		return d + "/openabstractions-" + service + ".sock"
	}
	return os.TempDir() + "/openabstractions-" + service + "-" + os.Getenv("USER") + ".sock"
}
