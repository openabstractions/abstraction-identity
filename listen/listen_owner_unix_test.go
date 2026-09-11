//go:build !windows

package listen

import (
	"errors"
	"io/fs"
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"
)

func TestASocketBelongsToTheFirstListener(t *testing.T) {
	path := filepath.Join(shortSocketDir(t), "first.sock")
	first, err := Listen(path)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()

	second, err := Listen(path)
	if err == nil {
		second.Close()
		t.Fatal("a second listener took an address that was already served")
	}
	if !errors.Is(err, ErrTaken) {
		t.Fatalf("the second listener was refused for the wrong reason: %v", err)
	}

	c, err := Dial(path)
	if err != nil {
		t.Fatalf("the refused start left the first listener unreachable: %v", err)
	}
	c.Close()
	if _, err := first.Accept(); err != nil {
		t.Fatalf("the first listener stopped accepting: %v", err)
	}
}

func TestAnExistingFileIsNeverRemoved(t *testing.T) {
	path := filepath.Join(shortSocketDir(t), "not-a-socket")
	want := []byte("somebody else's file")
	if err := os.WriteFile(path, want, 0o600); err != nil {
		t.Fatal(err)
	}
	l, err := Listen(path)
	if err == nil {
		l.Close()
		t.Fatal("a regular file was bound over")
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("the file was removed: %v", err)
	}
	if string(got) != string(want) {
		t.Fatalf("the file was rewritten: %q", got)
	}
}

func TestAStaleSocketIsReplaced(t *testing.T) {
	path := filepath.Join(shortSocketDir(t), "stale.sock")
	first, err := Listen(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	// A listener that died without closing leaves the socket behind; Go's Close
	// unlinks it, so the abandoned case is written by hand.
	dead, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	if u, ok := dead.(*net.UnixListener); ok {
		u.SetUnlinkOnClose(false)
	}
	dead.Close()
	if _, err := os.Lstat(path); err != nil {
		t.Fatalf("the abandoned socket was not left behind, so nothing stale is under test: %v", err)
	}

	again, err := Listen(path)
	if err != nil {
		t.Fatalf("a stale socket was not cleaned up: %v", err)
	}
	defer again.Close()
	c, err := Dial(path)
	if err != nil {
		t.Fatal(err)
	}
	c.Close()
}

func TestTheSocketIsShutToOtherAccounts(t *testing.T) {
	path := filepath.Join(shortSocketDir(t), "mode.sock")
	l, err := Listen(path)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	fi, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm()&^fs.FileMode(0o600) != 0 {
		t.Fatalf("the socket is open to accounts other than this one: %v", fi.Mode())
	}
}

func TestConcurrentStartsElectOneListener(t *testing.T) {
	path := filepath.Join(shortSocketDir(t), "race.sock")
	const starters = 8
	var wg sync.WaitGroup
	won := make(chan Listener, starters)
	lost := make(chan error, starters)
	start := make(chan struct{})
	for i := 0; i < starters; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			l, err := Listen(path)
			if err != nil {
				lost <- err
				return
			}
			won <- l
		}()
	}
	close(start)
	wg.Wait()
	close(won)
	close(lost)

	if len(won) != 1 {
		t.Fatalf("%d of %d concurrent starts bound the same address", len(won), starters)
	}
	for err := range lost {
		if !errors.Is(err, ErrTaken) {
			t.Fatalf("a losing start failed for the wrong reason: %v", err)
		}
	}
	l := <-won
	defer l.Close()
	c, err := Dial(path)
	if err != nil {
		t.Fatalf("the winning listener is unreachable: %v", err)
	}
	c.Close()
}
