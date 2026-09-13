package listen

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"
)

func TestFramedWaitContextCallerCancellation(t *testing.T) {
	endpoint := framedEndpoint(t)
	l, err := Listen(endpoint)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		_, err := (FrameClient{Endpoint: endpoint}).ExchangeFrameContext(ctx, []byte("wait"))
		done <- err
	}()
	c, err := l.Accept()
	if err != nil {
		t.Fatal(err)
	}
	k, err := ReceiveFramed(context.Background(), c, framingNeed, 16)
	if err != nil {
		t.Fatal(err)
	}
	defer k.Close()
	wait := k.WaitContext()
	if wait.Err() != nil {
		t.Fatal("live caller already canceled", wait.Err())
	}
	if wait != k.WaitContext() {
		t.Fatal("waiting context changed")
	}
	cancel()
	select {
	case <-wait.Done():
	case <-time.After(time.Second):
		t.Fatal("caller close did not end server wait")
	}
	if k.ctx.Err() != nil {
		t.Fatal("caller waiting canceled the independent call context", k.ctx.Err())
	}
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("client did not cancel")
	}
}

func TestFramedWaitContextSharesReplyDrain(t *testing.T) {
	endpoint := framedEndpoint(t)
	l, err := Listen(endpoint)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	done := make(chan error, 1)
	go func() {
		body, err := (FrameClient{Endpoint: endpoint}).ExchangeFrame([]byte("wait"))
		if err == nil && string(body) != "reply" {
			err = errors.New("wrong reply")
		}
		done <- err
	}()
	c, err := l.Accept()
	if err != nil {
		t.Fatal(err)
	}
	k, err := ReceiveFramed(context.Background(), c, framingNeed, 16)
	if err != nil {
		t.Fatal(err)
	}
	defer k.Close()
	wait := k.WaitContext()
	if err := k.Reply([]byte("reply")); err != nil {
		t.Fatal("EOF reader interfered with reply", err)
	}
	select {
	case <-wait.Done():
	case <-time.After(time.Second):
		t.Fatal("reply receiver did not release wait")
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestFramedWaitContextTrailingBytesAndClose(t *testing.T) {
	for _, trailing := range []bool{true, false} {
		endpoint := framedEndpoint(t)
		l, err := Listen(endpoint)
		if err != nil {
			t.Fatal(err)
		}
		dialed := make(chan net.Conn, 1)
		failed := make(chan error, 1)
		go func() {
			c, e := Dial(endpoint)
			if e == nil {
				e = writeFrame(c, []byte("wait"), 16)
			}
			if e != nil {
				failed <- e
				return
			}
			dialed <- c
		}()
		server, err := l.Accept()
		if err != nil {
			t.Fatal(err)
		}
		k, err := ReceiveFramed(context.Background(), server, framingNeed, 16)
		if err != nil {
			t.Fatal(err)
		}
		var caller net.Conn
		select {
		case caller = <-dialed:
		case err := <-failed:
			t.Fatal(err)
		case <-time.After(time.Second):
			t.Fatal("caller not ready")
		}
		wait := k.WaitContext()
		if trailing {
			if _, err := caller.Write([]byte{1}); err != nil {
				t.Fatal(err)
			}
		} else {
			k.Close()
		}
		select {
		case <-wait.Done():
		case <-time.After(time.Second):
			t.Fatal("wait remained live")
		}
		select {
		case <-k.watchDone:
		case <-time.After(time.Second):
			t.Fatal("EOF reader remained blocked")
		}
		if trailing && !errors.Is(k.watchErr, ErrUnexpectedResponse) {
			t.Fatal(k.watchErr)
		}
		caller.Close()
		k.Close()
		l.Close()
	}
}
