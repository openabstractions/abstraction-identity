//go:build windows && oa_source_probe

package identity

import (
	"context"
	"errors"
	"io"
	"net"
	"os"
	"os/exec"
	"sync"
	"testing"
	"time"

	"golang.org/x/sys/windows"
)

func TestSourceObservationChild(t *testing.T) {
	if os.Getenv("OA_SOURCE_OBSERVATION_CHILD") != "1" {
		return
	}
	io.Copy(io.Discard, os.Stdin)
	os.Exit(259)
}

func TestSourceProcessObservationNativeLifetime(t *testing.T) {
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(exe, "-test.run=^TestSourceObservationChild$", "-test.count=1")
	cmd.Env = append(os.Environ(), "OA_SOURCE_OBSERVATION_CHILD=1")
	in, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err = cmd.Start(); err != nil {
		t.Fatal(err)
	}
	var stop sync.Once
	finish := func() {
		stop.Do(func() {
			in.Close()
			err := cmd.Wait()
			var exit *exec.ExitError
			if !errors.As(err, &exit) || exit.ExitCode() != 259 {
				t.Errorf("owned child exit: %v", err)
			}
		})
	}
	t.Cleanup(finish)
	proc, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION|windows.SYNCHRONIZE, false, uint32(cmd.Process.Pid))
	if err != nil {
		t.Fatal(err)
	}
	defer windows.CloseHandle(proc)
	birth, err := processStartTime(proc)
	if err != nil {
		t.Fatal(err)
	}
	account, err := serverPrincipal(proc)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	expected := Process{PID: cmd.Process.Pid, StartTime: birth}
	obs, err := OpenSourceProcessObservation(ctx, expected, account.SID)
	if err != nil {
		t.Fatal(err)
	}
	defer obs.Close()
	if obs.Process.PID != cmd.Process.Pid || !obs.Process.StartTime.Equal(birth) || obs.Account != account.SID || obs.ImagePath == "" {
		t.Fatal("kernel observation incomplete", obs)
	}
	if live, err := obs.Alive(); !live || err != nil {
		t.Fatal(live, err)
	}
	for name, args := range map[string]struct {
		process Process
		account string
	}{
		"birth":         {Process{PID: cmd.Process.Pid, StartTime: birth.Add(time.Second)}, account.SID},
		"account":       {expected, account.SID + "-mismatch"},
		"zero-birth":    {Process{PID: cmd.Process.Pid}, account.SID},
		"empty-account": {expected, ""},
		"zero-pid":      {Process{StartTime: birth}, account.SID},
		"negative-pid":  {Process{PID: -1, StartTime: birth}, account.SID},
		"large-pid":     {Process{PID: 1 << 32, StartTime: birth}, account.SID},
		"recycled":      {Process{PID: cmd.Process.Pid, StartTime: birth, Recycled: true}, account.SID},
	} {
		t.Run(name, func(t *testing.T) {
			if bad, err := OpenSourceProcessObservation(ctx, args.process, args.account); err == nil {
				bad.Close()
				t.Fatal("mismatched locator admitted")
			}
		})
	}
	second, err := OpenSourceProcessObservation(ctx, expected, account.SID)
	if err != nil {
		t.Fatal(err)
	}
	if err := second.Close(); err != nil {
		t.Fatal(err)
	}
	if err := second.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := second.Alive(); !errors.Is(err, net.ErrClosed) {
		t.Fatal(err)
	}
	if err := obs.Recheck(); err != nil {
		t.Fatal("independent retained handle", err)
	}
	finish()
	if live, err := obs.Alive(); live || err != nil {
		t.Fatal("exit259 reported alive", live, err)
	}
	if err := obs.Recheck(); !errors.Is(err, ErrPeerGone) {
		t.Fatal("retired process", err)
	}
	if bad, err := OpenSourceProcessObservation(ctx, expected, account.SID); err == nil {
		bad.Close()
		t.Fatal("exited process admitted")
	}
	cancel()
	if _, err := obs.Alive(); !errors.Is(err, context.Canceled) {
		t.Fatal("cancellation", err)
	}
}
