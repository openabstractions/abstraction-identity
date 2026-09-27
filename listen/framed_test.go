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
	"syscall"
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
	for _, oneWay := range []bool{false, true} {
		endpoint := framedEndpoint(t)
		l, err := Listen(endpoint)
		if err != nil {
			t.Fatal(err)
		}
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
		client := FrameClient{Endpoint: endpoint, Timeout: 2 * time.Second}
		if oneWay {
			err = client.WriteFrame(nil)
		} else {
			_, err = client.ExchangeFrame(nil)
		}
		var refusal *ProofRefusal
		if !errors.As(err, &refusal) || !errors.Is(err, ErrCallerProofUnmet) || !errors.Is(err, identity.ErrNotProven) ||
			refusal.Attribute != "user" || refusal.Required != identity.ProofSigned {
			t.Fatalf("oneWay=%t client refusal=%v", oneWay, err)
		}
		err = <-done
		var proof *identity.ProofError
		if !errors.As(err, &proof) || proof.Want != identity.ProofSigned {
			t.Fatalf("expected server proof refusal, got %v", err)
		}
		l.Close()
	}
}

type proofDenyFrameConn struct{ net.Conn }

func (c *proofDenyFrameConn) Bind() (*identity.Binding, error) {
	return nil, &identity.ProofError{Attribute: "code", Want: identity.ProofSigned, Got: identity.ProofNone}
}

func TestProofRefusalPrecedesBodyRead(t *testing.T) {
	a, b := net.Pipe()
	defer b.Close()
	done := make(chan error, 1)
	go func() {
		_, err := ReceiveFramed(context.Background(), &proofDenyFrameConn{a}, identity.Need{Code: identity.ProofSigned}, 16)
		done <- err
	}()
	// Promise a body but send only the fixed header. The receiver must answer
	// the proof failure without waiting for or inspecting an application byte.
	if _, err := b.Write([]byte{0, 0, 0, 5}); err != nil {
		t.Fatal(err)
	}
	var control [6]byte
	if _, err := io.ReadFull(b, control[:]); err != nil {
		t.Fatal(err)
	}
	if control != [6]byte{0xff, 0xff, 0xff, 0xfe, 5, 8} {
		t.Fatalf("control=%x", control)
	}
	if err := <-done; !errors.Is(err, identity.ErrNotProven) {
		t.Fatal(err)
	}
}

func TestProofRefusalRequiresCompleteValidControl(t *testing.T) {
	if got := frameLimit(^uint32(0)); got != lengthMask {
		t.Fatalf("effective frame ceiling=%d, want %d", got, lengthMask)
	}
	for _, tc := range []struct {
		name string
		wire []byte
		want error
	}{
		{"truncated", []byte{0xff, 0xff, 0xff, 0xfe, 1}, io.ErrUnexpectedEOF},
		{"bad attribute", []byte{0xff, 0xff, 0xff, 0xfe, 6, 8}, ErrProofRefusalProtocol},
		{"bad proof", []byte{0xff, 0xff, 0xff, 0xfe, 1, 9}, ErrProofRefusalProtocol},
		{"old close", nil, io.EOF},
		{"oversize", []byte{0x40, 0, 0, 0}, ErrFrameTooLarge},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ReadFrameFrom(bytes.NewReader(tc.wire), ^uint32(0))
			if !errors.Is(err, tc.want) || errors.Is(err, identity.ErrNotProven) {
				t.Fatalf("read error=%v, want %v without proof refusal", err, tc.want)
			}
		})
	}
}

func TestProofRefusalFixedVocabulary(t *testing.T) {
	for code, attribute := range []string{"", "user", "process", "path", "package", "code"} {
		if code == 0 {
			continue
		}
		word := proofRefusalBytes(&identity.ProofError{Attribute: attribute, Want: identity.ProofSigned})
		if word[4] != byte(code) || word[5] != byte(identity.ProofSigned) {
			t.Fatalf("%s encoded as %x", attribute, word)
		}
		err := readProofRefusal(bytes.NewReader(word[4:]))
		var refusal *ProofRefusal
		if !errors.As(err, &refusal) || refusal.Attribute != attribute || refusal.Required != identity.ProofSigned {
			t.Fatalf("%s decoded as %v", attribute, err)
		}
	}
	unknown := proofRefusalBytes(&identity.ProofError{Attribute: "machine-secret", Want: identity.ProofSigned})
	if unknown[4] != 0 || unknown[5] != 0 {
		t.Fatalf("unknown attribute disclosed: %x", unknown)
	}
}

type failedDirectWriteConn struct {
	net.Conn
	response io.Reader
	writes   int
	reads    int
	onWrite  func()
}

func (c *failedDirectWriteConn) Read(p []byte) (int, error) {
	c.reads++
	return c.response.Read(p)
}
func (c *failedDirectWriteConn) Write([]byte) (int, error) {
	c.writes++
	if c.onWrite != nil {
		c.onWrite()
	}
	return 0, syscall.EPIPE
}
func (c *failedDirectWriteConn) SetDeadline(time.Time) error { return nil }
func (c *failedDirectWriteConn) Close() error                { return nil }

func TestDirectWriteFailureUsesOnlyCompleteProofRefusal(t *testing.T) {
	marker := proofRefusalBytes(&identity.ProofError{Attribute: "user", Want: identity.ProofSigned})
	invalid := marker
	invalid[4] = 0xFF
	for _, oneWay := range []bool{false, true} {
		for _, tc := range []struct {
			name        string
			response    []byte
			wantRefusal bool
		}{
			{"complete refusal", marker[:], true},
			{"partial header", marker[:3], false},
			{"partial tokens", marker[:5], false},
			{"invalid tokens", invalid[:], false},
			{"other header", []byte{0, 0, 0, 1}, false},
			{"EOF", nil, false},
		} {
			t.Run(fmt.Sprintf("oneWay=%t/%s", oneWay, tc.name), func(t *testing.T) {
				conn := &failedDirectWriteConn{response: bytes.NewReader(tc.response)}
				dials := 0
				client := FrameClient{Endpoint: "fixture", Timeout: time.Second, Dialer: func(context.Context, string) (net.Conn, error) {
					dials++
					return conn, nil
				}}
				var err error
				if oneWay {
					err = client.WriteFrame([]byte("effect"))
				} else {
					_, err = client.ExchangeFrame([]byte("effect"))
				}
				var refusal *ProofRefusal
				if tc.wantRefusal {
					if !errors.As(err, &refusal) || refusal.Attribute != "user" || refusal.Required != identity.ProofSigned {
						t.Fatalf("proof refusal = %v", err)
					}
				} else if !errors.Is(err, syscall.EPIPE) {
					t.Fatalf("original write error = %v", err)
				}
				if dials != 1 || conn.writes != 1 {
					t.Fatalf("dials = %d, writes = %d, want one each", dials, conn.writes)
				}
			})
		}
	}
}

type readUntilContextDone struct{ ctx context.Context }

func (r readUntilContextDone) Read([]byte) (int, error) {
	<-r.ctx.Done()
	return 0, r.ctx.Err()
}

func TestDirectWriteFailureKeepsContextPriority(t *testing.T) {
	t.Run("canceled", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		conn := &failedDirectWriteConn{response: bytes.NewReader(nil), onWrite: cancel}
		client := FrameClient{Endpoint: "fixture", Dialer: func(context.Context, string) (net.Conn, error) {
			return conn, nil
		}}
		_, err := client.ExchangeFrameContext(ctx, []byte("effect"))
		if !errors.Is(err, context.Canceled) || conn.reads != 0 {
			t.Fatalf("canceled write = %v, refusal reads = %d", err, conn.reads)
		}
	})
	t.Run("deadline", func(t *testing.T) {
		conn := &failedDirectWriteConn{}
		client := FrameClient{Endpoint: "fixture", Timeout: 25 * time.Millisecond, Dialer: func(ctx context.Context, _ string) (net.Conn, error) {
			conn.response = readUntilContextDone{ctx: ctx}
			return conn, nil
		}}
		_, err := client.ExchangeFrame([]byte("effect"))
		if !errors.Is(err, context.DeadlineExceeded) || conn.reads != 1 {
			t.Fatalf("deadline-bound refusal read = %v, reads = %d", err, conn.reads)
		}
	})
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
	if err := <-done; !errors.Is(err, identity.ErrNotProven) {
		t.Fatal(err)
	}
}
