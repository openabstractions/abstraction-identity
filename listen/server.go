package listen

import (
	"context"
	"errors"
	"fmt"
	"net"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	identity "github.com/openabstractions/abstraction-identity"
)

var ErrServerUntrusted = errors.New("listen: connected server is not trusted")

// ServerExpectation comes from trusted caller configuration or installation
// evidence. Never populate it from a server response or a provider identifier.
// Principal matches Kind plus SID (Windows) or UID (POSIX); other User fields
// are descriptive. Program is an absolute image path, with Windows case folding.
// This proves the platform's process/path identity, not code integrity. Process,
// when supplied, additionally pins PID and nonzero creation time. Treat this
// configuration as immutable while clients use it.
type ServerExpectation struct {
	Principal identity.User
	Program   string
	Process   *identity.Process
}

func (e ServerExpectation) validate() error {
	validUser := e.Principal.Kind == "windows" && e.Principal.SID != "" || e.Principal.Kind == "posix" && e.Principal.UID >= 0
	if !validUser || !filepath.IsAbs(e.Program) || strings.IndexByte(e.Program, 0) >= 0 || e.Process != nil && (e.Process.PID <= 0 || e.Process.StartTime.IsZero()) {
		return fmt.Errorf("%w: incomplete principal, absolute program, or process instance", ErrServerUntrusted)
	}
	return nil
}

func (e ServerExpectation) check(b *identity.Binding) error {
	p, err := b.Peer()
	if err != nil {
		return err
	}
	u, err := p.User.AtLeast(identity.ProofBound)
	if err != nil {
		return err
	}
	process, err := p.Process.AtLeast(identity.ProofKernel)
	if err != nil {
		return err
	}
	path, err := p.Path.AtLeast(identity.ProofBound)
	if err != nil {
		return err
	}
	if u.Kind != e.Principal.Kind || u.Kind == "windows" && u.SID != e.Principal.SID || u.Kind == "posix" && u.UID != e.Principal.UID {
		return errors.New("server principal mismatch")
	}
	match := filepath.Clean(path) == filepath.Clean(e.Program)
	if runtime.GOOS == "windows" {
		match = strings.EqualFold(filepath.Clean(path), filepath.Clean(e.Program))
	}
	if !match {
		return errors.New("server program mismatch")
	}
	if e.Process != nil && (process.PID != e.Process.PID || !process.StartTime.Equal(e.Process.StartTime)) {
		return errors.New("server process instance mismatch")
	}
	return nil
}

type serverConn struct {
	net.Conn
	ctx         context.Context
	mu          sync.Mutex
	closed      bool
	binding     *identity.Binding
	expectation *ServerExpectation
}

func (c *serverConn) authenticate(e *ServerExpectation, at time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return net.ErrClosed
	}
	if err := c.ctx.Err(); err != nil {
		return err
	}
	if e == nil {
		return nil
	}
	copy := *e
	if e.Process != nil {
		process := *e.Process
		copy.Process = &process
	}
	c.expectation = &copy
	b, err := identity.BindServerConn(c.Conn, &identity.Options{ConnectedAt: at, SkipCodeSignature: true})
	if err != nil {
		return fmt.Errorf("%w: %w", ErrServerUntrusted, err)
	}
	c.binding = b
	return c.checkLocked()
}

func (c *serverConn) checkLocked() error {
	if c.closed {
		return net.ErrClosed
	}
	if err := c.ctx.Err(); err != nil {
		return err
	}
	if c.binding == nil {
		return nil
	}
	if err := c.expectation.check(c.binding); err != nil {
		return fmt.Errorf("%w: %w", ErrServerUntrusted, err)
	}
	return nil
}

func (c *serverConn) check() error { c.mu.Lock(); defer c.mu.Unlock(); return c.checkLocked() }
func (c *serverConn) Read(p []byte) (int, error) {
	if err := c.check(); err != nil {
		return 0, err
	}
	n, err := c.Conn.Read(p)
	if checkErr := c.check(); checkErr != nil {
		return 0, checkErr
	}
	return n, err
}
func (c *serverConn) Write(p []byte) (int, error) {
	if err := c.check(); err != nil {
		return 0, err
	}
	return c.Conn.Write(p)
}
func (c *serverConn) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return nil
	}
	c.closed = true
	if c.binding != nil {
		c.binding.Close()
	}
	return c.Conn.Close()
}
