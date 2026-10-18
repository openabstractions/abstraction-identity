//go:build darwin

package identity

import (
	"errors"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// ID-T8 on macOS: a dialed AF_UNIX connection has no server binding, so
// BindUnixServer answers ErrNoBinding rather than a process it found by number
// or a refusal that names the wrong end.
func TestBindUnixServerHasNoBindingOnMacOS(t *testing.T) {
	dir, err := os.MkdirTemp("/tmp", "oa-us")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	l, err := net.Listen("unix", filepath.Join(dir, "s"))
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	go func() {
		if c, err := l.Accept(); err == nil {
			defer c.Close()
			var b [1]byte
			_, _ = c.Read(b[:])
		}
	}()
	conn, err := net.Dial("unix", filepath.Join(dir, "s"))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	binding, err := BindUnixServer(conn, &Options{ConnectedAt: time.Now(), SkipCodeSignature: true})
	if binding != nil || !errors.Is(err, ErrNoBinding) || errors.Is(err, ErrNotServerEnd) {
		t.Fatalf("BindUnixServer on macOS: binding %v, error %v; want ErrNoBinding", binding != nil, err)
	}
}
