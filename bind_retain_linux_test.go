package identity

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestRetainProcessLinuxKeepsExecGuardAfterConnectionClose(t *testing.T) {
	if ok, why := pidfdSupport(); !ok {
		t.Skip(why)
	}
	victim, err := filepath.EvalSymlinks("/bin/cat")
	if err != nil {
		t.Skip(err)
	}
	l, path := listenUnix(t)
	a := startAttacker(t, execDriftEnv, path, os.Stderr)
	conn, at := acceptOnly(t, l)
	b := bindOrFail(t, conn, at)
	pin, err := b.RetainProcess()
	if err != nil {
		t.Fatal(err)
	}
	defer pin.Close()
	b.Close()
	conn.Close()
	if _, err = pin.Peer(); err != nil {
		t.Fatal(err)
	}
	a.release(t)
	waitForExe(t, a.pid(), victim)
	if _, err = pin.Peer(); !errors.Is(err, ErrPeerMoved) {
		t.Fatalf("exec contradiction: %v", err)
	}
	if _, err = pin.RetainProcess(); !errors.Is(err, ErrPeerMoved) {
		t.Fatalf("retain moved process: %v", err)
	}
}
