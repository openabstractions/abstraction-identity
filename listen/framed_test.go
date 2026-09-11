package listen

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	identity "github.com/openabstractions/abstraction-identity"
)

var framedSerial atomic.Uint64

// Framing tests exercise bytes and lifecycle at the portable proof floor.
// Production Program requirements remain separate and are tested below.
var framingNeed = identity.Need{User: identity.ProofKernel, Process: identity.ProofPID, Path: identity.ProofPID}

func shortSocketDir(t *testing.T) string {
	t.Helper()
	// t.TempDir includes the test name, exceeding Darwin's sockaddr_un limit.
	dir, err := os.MkdirTemp("", "oa-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(dir); err != nil {
			t.Error(err)
		}
	})
	return dir
}

func framedEndpoint(t *testing.T) string {
	t.Helper()
	if runtime.GOOS == "windows" {
		return Endpoint(fmt.Sprintf("frame-test-%d-%d", os.Getpid(), framedSerial.Add(1)))
	}
	return filepath.Join(shortSocketDir(t), "frame.sock")
}
func TestFramedRoundtrip(t *testing.T) {
	for _, exchange := range []bool{false, true} {
		for _, payload := range [][]byte{nil, []byte("a\n\x00b\r\n"), bytes.Repeat([]byte{0, 1, 255, 10}, 65536)} {
			endpoint := framedEndpoint(t)
			l, err := Listen(endpoint)
			if err != nil {
				t.Fatal(err)
			}
			result := make(chan error, 1)
			go func() {
				c, err := l.Accept()
				if err != nil {
					result <- err
					return
				}
				k, err := ReceiveFramed(context.Background(), c, framingNeed, 0)
				if err != nil {
					result <- err
					return
				}
				defer k.Close()
				if !k.Caller.Bound || !bytes.Equal(k.Frame, payload) {
					result <- errors.New("identity or byte mismatch")
					return
				}
				if exchange {
					err = k.Reply(k.Frame)
				}
				result <- err
			}()
			client := FrameClient{Endpoint: endpoint, Timeout: 2 * time.Second}
			if exchange {
				reply, err := client.ExchangeFrame(payload)
				if err != nil || !bytes.Equal(reply, payload) {
					t.Fatalf("exchange: %v", err)
				}
			} else {
				if err := client.WriteFrame(payload); err != nil {
					t.Fatal(err)
				}
			}
			if err := <-result; err != nil {
				t.Fatal(err)
			}
			l.Close()
		}
	}
}

type refusingFrameConn struct {
	net.Conn
	binds atomic.Int32
}

var denied = errors.New("test identity refusal")

func (c *refusingFrameConn) Bind() (*identity.Binding, error) { c.binds.Add(1); return nil, denied }
func TestFramedRejectBeforeExposure(t *testing.T) {
	for _, tc := range []struct {
		name  string
		wire  []byte
		want  error
		binds int32
	}{
		{"empty", nil, io.EOF, 0}, {"short header", []byte{0, 0}, io.ErrUnexpectedEOF, 0},
		{"oversize", []byte{255, 255, 255, 255}, ErrFrameTooLarge, 0},
		{"legacy line", []byte("{\"x\":1}\n"), ErrFrameTooLarge, 0},
		{"binding refusal", []byte{0, 0, 0, 1, 42}, denied, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a, b := net.Pipe()
			c := &refusingFrameConn{Conn: a}
			go func() { b.Write(tc.wire); b.Close() }()
			k, err := ReceiveFramed(context.Background(), c, framingNeed, 16)
			if k != nil || !errors.Is(err, tc.want) || c.binds.Load() != tc.binds {
				t.Fatalf("call=%v err=%v binds=%d", k, err, c.binds.Load())
			}
		})
	}
}
func TestFramedCancellation(t *testing.T) {
	a, b := net.Pipe()
	defer b.Close()
	c := &refusingFrameConn{Conn: a}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		k, err := ReceiveFramed(ctx, c, framingNeed, 16)
		if k != nil {
			err = errors.New("exposed cancelled frame")
		}
		done <- err
	}()
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("cancellation did not close blocked connection")
	}
	if c.binds.Load() != 0 {
		t.Fatal("bound after cancellation")
	}
}
func TestFramedTruncatedBody(t *testing.T) {
	endpoint := framedEndpoint(t)
	l, err := Listen(endpoint)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	done := make(chan error, 1)
	go func() {
		c, err := l.Accept()
		if err != nil {
			done <- err
			return
		}
		k, err := ReceiveFramed(context.Background(), c, framingNeed, 16)
		if k != nil {
			err = errors.New("truncated body exposed")
		}
		done <- err
	}()
	c, err := Dial(endpoint)
	if err != nil {
		t.Fatal(err)
	}
	c.Write([]byte{0, 0, 0, 4, 1})
	time.Sleep(20 * time.Millisecond)
	c.Close()
	if err := <-done; !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("got %v", err)
	}
}
func TestFramedClientBoundaries(t *testing.T) {
	c := FrameClient{Endpoint: "must-not-open", MaxFrame: 2}
	if err := c.WriteFrame([]byte{1, 2, 3}); !errors.Is(err, ErrFrameTooLarge) {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := c.WriteFrameContext(ctx, nil); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	for i, wire := range [][]byte{{255, 255, 255, 255}, {0, 0, 0, 3, 42}} {
		endpoint := framedEndpoint(t)
		l, err := Listen(endpoint)
		if err != nil {
			t.Fatal(err)
		}
		go func() {
			conn, err := l.Accept()
			if err != nil {
				return
			}
			defer conn.Close()
			readFrame(conn, 16)
			conn.Write(wire)
			time.Sleep(20 * time.Millisecond)
		}()
		client := FrameClient{Endpoint: endpoint, MaxFrame: 16, Timeout: time.Second}
		reply, err := client.ExchangeFrame(nil)
		want := ErrFrameTooLarge
		if i == 1 {
			want = io.ErrUnexpectedEOF
		}
		if reply != nil || !errors.Is(err, want) {
			t.Fatalf("reply=%v err=%v want=%v", reply, err, want)
		}
		l.Close()
	}
}
func TestFramedOneWayUnexpectedResponse(t *testing.T) {
	endpoint := framedEndpoint(t)
	l, err := Listen(endpoint)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	go func() {
		c, err := l.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		readFrame(c, 16)
		c.Write([]byte("x"))
		time.Sleep(20 * time.Millisecond)
	}()
	if err := (FrameClient{Endpoint: endpoint}).WriteFrame(nil); !errors.Is(err, ErrUnexpectedResponse) {
		t.Fatal(err)
	}
}
func TestFramedDeadlineAcrossReads(t *testing.T) {
	endpoint := framedEndpoint(t)
	l, err := Listen(endpoint)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	go func() {
		c, err := l.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		readFrame(c, 16)
		var h [4]byte
		binary.BigEndian.PutUint32(h[:], 3)
		c.Write(h[:])
		for _, b := range []byte{1, 2, 3} {
			time.Sleep(50 * time.Millisecond)
			if _, err := c.Write([]byte{b}); err != nil {
				return
			}
		}
	}()
	start := time.Now()
	_, err = (FrameClient{Endpoint: endpoint, Timeout: 90 * time.Millisecond}).ExchangeFrame(nil)
	var timeout net.Error
	if !errors.Is(err, context.DeadlineExceeded) && !(errors.As(err, &timeout) && timeout.Timeout()) {
		t.Fatalf("wanted timeout, got %v", err)
	}
	if time.Since(start) > time.Second {
		t.Fatal("deadline unbounded")
	}
}

func TestFramedProofRefusal(t *testing.T) {
	endpoint := framedEndpoint(t)
	l, err := Listen(endpoint)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	done := make(chan error, 1)
	go func() {
		c, err := l.Accept()
		if err != nil {
			done <- err
			return
		}
		k, err := ReceiveFramed(context.Background(), c, identity.Need{User: identity.ProofSigned}, 16)
		if k != nil {
			err = errors.New("proof refusal exposed frame")
		}
		done <- err
	}()
	// One-way EOF means submission, including a peer that refuses identity.
	_ = (FrameClient{Endpoint: endpoint}).WriteFrame(nil)
	err = <-done
	var proof *identity.ProofError
	if !errors.As(err, &proof) || proof.Want != identity.ProofSigned {
		t.Fatalf("expected proof refusal, got %v", err)
	}
}

type observedFrameConn struct {
	Conn
	started chan struct{}
	once    sync.Once
}

func (c *observedFrameConn) Read(p []byte) (int, error) {
	c.once.Do(func() { close(c.started) })
	return c.Conn.Read(p)
}
func (c *observedFrameConn) SetDeadline(d time.Time) error {
	return c.Conn.(interface{ SetDeadline(time.Time) error }).SetDeadline(d)
}
func TestFramedCancelBlockedNativeReceive(t *testing.T) {
	endpoint := framedEndpoint(t)
	l, err := Listen(endpoint)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	started := make(chan struct{})
	done := make(chan error, 1)
	go func() {
		c, err := l.Accept()
		if err != nil {
			done <- err
			return
		}
		k, err := ReceiveFramed(ctx, &observedFrameConn{Conn: c, started: started}, framingNeed, 16)
		if k != nil {
			err = errors.New("cancelled native read exposed a call")
		}
		done <- err
	}()
	c, err := Dial(endpoint)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("native read did not start")
	}
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("native read stayed blocked after cancellation")
	}
}

func TestFramedExpiredBeforeDispatch(t *testing.T) {
	a, b := net.Pipe()
	defer b.Close()
	c := &refusingFrameConn{Conn: a}
	ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer cancel()
	k, err := ReceiveFramed(ctx, c, framingNeed, 16)
	if k != nil || !errors.Is(err, context.DeadlineExceeded) || c.binds.Load() != 0 {
		t.Fatalf("call=%v err=%v binds=%d", k, err, c.binds.Load())
	}
}

func TestFramedPeerTypedAndClosed(t *testing.T) {
	for _, cancelled := range []bool{false, true} {
		endpoint := framedEndpoint(t)
		l, err := Listen(endpoint)
		if err != nil {
			t.Fatal(err)
		}
		clientDone := make(chan error, 1)
		go func() { clientDone <- (FrameClient{Endpoint: endpoint}).WriteFrame([]byte("peer")) }()
		c, err := l.Accept()
		if err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithCancel(context.Background())
		k, err := ReceiveFramed(ctx, c, framingNeed, 16)
		if err != nil {
			cancel()
			l.Close()
			t.Fatal(err)
		}
		p, err := k.Peer()
		if err != nil {
			k.Close()
			l.Close()
			t.Fatal(err)
		}
		path, pathProof := p.Path.Get()
		user, userProof := p.User.Get()
		process, processProof := p.Process.Get()
		if path == "" || path == k.Caller.Path || pathProof < framingNeed.Path || user.Kind == "" || userProof < framingNeed.User || process.PID != os.Getpid() || processProof < framingNeed.Process || p.Platform != runtime.GOOS {
			t.Fatalf("wrong typed peer: path=%q proof=%v user=%+v proof=%v process=%+v proof=%v", path, pathProof, user, userProof, process, processProof)
		}
		// Exercise recheck concurrently with resource release under the race detector.
		checked := make(chan struct{})
		go func() {
			defer close(checked)
			for i := 0; i < 20; i++ {
				_, _ = k.Peer()
			}
		}()
		if cancelled {
			cancel()
		} else {
			k.Close()
		}
		peer, err := k.Peer()
		if peer != nil || (!errors.Is(err, net.ErrClosed) && !errors.Is(err, context.Canceled)) {
			t.Fatalf("peer after shutdown=%v err=%v", peer, err)
		}
		k.Close()
		cancel()
		<-checked
		if peer, err := k.Peer(); peer != nil || !errors.Is(err, net.ErrClosed) {
			t.Fatalf("peer after close=%v err=%v", peer, err)
		}
		if err := k.Recheck(); !errors.Is(err, net.ErrClosed) {
			t.Fatalf("recheck after close: %v", err)
		}
		if err := <-clientDone; err != nil {
			t.Fatal(err)
		}
		l.Close()
	}
}

// A working framing transport must not upgrade the platform's proof ceiling.
func TestFramedProgramRefusesBelowCeiling(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("Darwin's process proof ceiling is below Program")
	}
	endpoint := framedEndpoint(t)
	l, err := Listen(endpoint)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	done := make(chan error, 1)
	go func() { done <- (FrameClient{Endpoint: endpoint}).WriteFrame([]byte("request")) }()
	c, err := l.Accept()
	if err != nil {
		t.Fatal(err)
	}
	call, err := ReceiveFramed(context.Background(), c, Program, 16)
	if call != nil {
		call.Close()
		t.Fatal("Program accepted a caller below its proof requirement")
	}
	if !errors.Is(err, identity.ErrNotProven) {
		t.Fatalf("expected proof refusal, got %v", err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}
