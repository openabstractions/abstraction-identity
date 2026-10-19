package listen

import (
	"context"
	"errors"
	identity "github.com/openabstractions/abstraction-identity"
	"io"
	"net"
	"os"
	"os/exec"
	"sync"
	"testing"
	"time"
)

func TestFramedRetainProcessChild(t *testing.T) {
	name := os.Getenv("OA_FRAMED1608_CHILD")
	if name == "" {
		return
	}
	c, err := Dial(name)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if err = WriteFrameTo(c, []byte("{}"), 4096); err != nil {
		t.Fatal(err)
	}
	if _, err = io.Copy(io.Discard, os.Stdin); err != nil {
		t.Fatal(err)
	}
}

func TestFramedRetainProcessOutlivesRequestAndEndsAtExit(t *testing.T) {
	endpoint := framedEndpoint(t)
	l, err := ListenFramed(endpoint, Program)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	calls := make(chan *FramedCall, 1)
	failed := make(chan error, 1)
	go func() {
		c, e := l.Accept()
		if e != nil {
			failed <- e
			return
		}
		k, e := ReceiveFramed(ctx, c, Program, 4096)
		if e != nil {
			c.Close()
			failed <- e
			return
		}
		calls <- k
	}()
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(exe, "-test.run=^TestFramedRetainProcessChild$", "-test.count=1")
	cmd.Env = append(os.Environ(), "OA_FRAMED1608_CHILD="+endpoint)
	in, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err = cmd.Start(); err != nil {
		t.Fatal(err)
	}
	var once sync.Once
	stop := func() {
		once.Do(func() {
			in.Close()
			if err := cmd.Wait(); err != nil {
				t.Error(err)
			}
		})
	}
	defer stop()
	var k *FramedCall
	select {
	case k = <-calls:
	case err := <-failed:
		t.Fatal(err)
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	defer k.Close()
	pin, err := k.RetainProcess()
	if err != nil {
		t.Fatal(err)
	}
	defer pin.Close()
	cancelled, stopContext := context.WithCancel(context.Background())
	stopContext()
	if _, err := (&FramedCall{ctx: cancelled, binding: k.binding}).RetainProcess(); !errors.Is(err, context.Canceled) {
		t.Fatal("cancelled request retained", err)
	}
	if !pin.BoundAt().Equal(k.binding.BoundAt()) || !pin.EvidenceValidUntil().Equal(k.binding.EvidenceValidUntil()) {
		t.Fatal("retention refreshed evidence")
	}
	k.Close()
	if _, err = k.RetainProcess(); !errors.Is(err, net.ErrClosed) {
		t.Fatal("closed request retained", err)
	}
	if alive, err := pin.Alive(); !alive || err != nil {
		t.Fatal("request close ended pin", alive, err)
	}
	stop()
	if alive, err := pin.Alive(); alive || err != nil {
		t.Fatal("exited process alive", alive, err)
	}
	if _, err := pin.Peer(); err != nil {
		t.Fatal("historical capture lost", err)
	}
	if _, err := pin.RetainProcess(); !errors.Is(err, identity.ErrPeerGone) {
		t.Fatal("exited pin retained", err)
	}
}

func TestFramedRetainProcessSessionRetirementAndPoolDiscard(t *testing.T) {
	for _, mode := range []string{"server-retirement", "client-idle-discard"} {
		t.Run(mode, func(t *testing.T) {
			pins := make(chan *identity.Binding, 1)
			s := serveSessions(t, SessionOptions{Idle: time.Minute}, Program, func(k *FramedCall) error {
				pin, err := k.RetainProcess()
				if err != nil {
					return err
				}
				pins <- pin
				return k.Reply([]byte("ok"))
			})
			client := FrameClient{Endpoint: s.endpoint, Timeout: 3 * time.Second, Sessions: true}
			if _, err := client.ExchangeFrame([]byte("request")); err != nil {
				t.Fatal(err)
			}
			pin := <-pins
			defer pin.Close()
			if mode == "client-idle-discard" {
				if conn := frames.take(client.poolKey(), time.Now().Add(poolIdle+time.Second)); conn != nil {
					conn.Close()
					t.Fatal("idle session retained")
				}
			}
			if err := s.l.Close(); err != nil {
				t.Fatal(err)
			}
			if live, err := pin.Alive(); !live || err != nil {
				t.Fatal("session/pool retirement ended process pin", live, err)
			}
			if _, err := pin.Peer(); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestFramedRetainProcessClosedCancelledAndMissing(t *testing.T) {
	var nilCall *FramedCall
	if _, err := nilCall.RetainProcess(); !errors.Is(err, net.ErrClosed) {
		t.Fatal(err)
	}
	k := &FramedCall{ctx: context.Background()}
	if _, err := k.RetainProcess(); !errors.Is(err, identity.ErrNoBinding) {
		t.Fatal(err)
	}
	k.closed = true
	if _, err := k.RetainProcess(); !errors.Is(err, net.ErrClosed) {
		t.Fatal(err)
	}
}
