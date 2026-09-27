package listen

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	identity "github.com/openabstractions/abstraction-identity"
)

type testMessageConn struct {
	message  receivedMessage
	err      error
	limit    uint32
	receives atomic.Int32
	binds    atomic.Int32
	closes   atomic.Int32
	refusals atomic.Int32
	tokens   [2]byte
}

func (c *testMessageConn) receiveMessage(_ context.Context, limit uint32) (receivedMessage, error) {
	c.limit = limit
	c.receives.Add(1)
	return c.message, c.err
}
func (c *testMessageConn) Read([]byte) (int, error)         { return 0, errors.New("message transport read") }
func (c *testMessageConn) Write([]byte) (int, error)        { return 0, errors.New("message transport write") }
func (c *testMessageConn) Bind() (*identity.Binding, error) { c.binds.Add(1); return nil, denied }
func (c *testMessageConn) Close() error                     { c.closes.Add(1); return nil }
func (c *testMessageConn) refuseProof(err error) error {
	word := proofRefusalBytes(err)
	c.tokens = [2]byte{word[4], word[5]}
	c.refusals.Add(1)
	return nil
}

type testMessageListener struct {
	once   sync.Once
	conn   Conn
	closed chan struct{}
}

func (l *testMessageListener) Accept() (Conn, error) {
	var conn Conn
	l.once.Do(func() { conn = l.conn })
	if conn != nil {
		return conn, nil
	}
	<-l.closed
	return nil, net.ErrClosed
}
func (l *testMessageListener) Close() error {
	select {
	case <-l.closed:
	default:
		close(l.closed)
	}
	return nil
}

func messageTestBinding(t *testing.T) *identity.Binding {
	t.Helper()
	endpoint := framedEndpoint(t)
	listener, err := Listen(endpoint)
	if err != nil {
		t.Fatal(err)
	}
	client, err := Dial(endpoint)
	if err != nil {
		listener.Close()
		t.Fatal(err)
	}
	accepted, err := listener.Accept()
	if err != nil {
		client.Close()
		listener.Close()
		t.Fatal(err)
	}
	payload := []byte("binding")
	var header [4]byte
	binary.BigEndian.PutUint32(header[:], uint32(len(payload)))
	if _, err = client.Write(append(header[:], payload...)); err != nil {
		accepted.Close()
		client.Close()
		listener.Close()
		t.Fatal(err)
	}
	call, err := ReceiveFramed(context.Background(), accepted, framingNeed, 32)
	if err != nil {
		client.Close()
		listener.Close()
		t.Fatal(err)
	}
	binding := call.binding
	t.Cleanup(func() { binding.Close(); call.Close(); client.Close(); listener.Close() })
	return binding
}

func TestMessageReceiveKeepsRequestBindingAndDoesNotUseConnectionBind(t *testing.T) {
	binding := messageTestBinding(t)
	done := make(chan struct{})
	var replies atomic.Int32
	conn := &testMessageConn{message: receivedMessage{
		frame: []byte("request"), binding: binding, done: done,
		reply: func(_ context.Context, frame []byte) error {
			replies.Add(1)
			if !bytes.Equal(frame, []byte("reply")) {
				t.Errorf("reply %q", frame)
			}
			return nil
		},
	}}
	call, err := ReceiveFramed(context.Background(), conn, framingNeed, 16)
	if err != nil {
		t.Fatal(err)
	}
	if conn.limit != 16 || conn.receives.Load() != 1 || conn.binds.Load() != 0 {
		t.Fatalf("message path limit=%d receives=%d binds=%d", conn.limit, conn.receives.Load(), conn.binds.Load())
	}
	if !bytes.Equal(call.Frame, []byte("request")) {
		t.Fatalf("frame %q", call.Frame)
	}
	if _, err := call.Peer(); err != nil {
		t.Fatalf("peer: %v", err)
	}
	wait := call.WaitContext()
	close(done)
	select {
	case <-wait.Done():
	case <-time.After(time.Second):
		t.Fatal("message lifetime did not end wait")
	}

	binding = messageTestBinding(t)
	done = make(chan struct{})
	conn = &testMessageConn{message: receivedMessage{frame: []byte("request"), binding: binding, done: done, reply: func(_ context.Context, frame []byte) error { replies.Add(1); return nil }}}
	call, err = ReceiveFramed(context.Background(), conn, framingNeed, 16)
	if err != nil {
		t.Fatal(err)
	}
	if err := call.Reply([]byte("reply")); err != nil {
		t.Fatal(err)
	}
	if err := call.Reply([]byte("different")); err != nil {
		t.Fatal(err)
	}
	if replies.Load() != 1 {
		t.Fatalf("reply callback ran %d times", replies.Load())
	}
	if err := call.Close(); err != nil {
		t.Fatal(err)
	}
	if err := call.Close(); err != nil {
		t.Fatal(err)
	}
	if conn.closes.Load() != 1 {
		t.Fatalf("close ran %d times", conn.closes.Load())
	}
}

func TestMessageReceiveRejectsBeforeFrameExposure(t *testing.T) {
	for _, tc := range []struct {
		name         string
		frame        []byte
		need         identity.Need
		want         error
		receiveErr   error
		missingReply bool
		missingDone  bool
	}{
		{name: "receive", need: framingNeed, want: denied, receiveErr: denied},
		{name: "oversize", frame: bytes.Repeat([]byte("x"), 17), need: framingNeed, want: ErrFrameTooLarge},
		{name: "lifetime", frame: []byte("effect"), need: framingNeed, want: errMessageLifetime, missingDone: true},
		{name: "reply", frame: []byte("effect"), need: framingNeed, want: errMessageLifetime, missingReply: true},
		{name: "identity", frame: []byte("effect"), need: identity.Need{User: identity.ProofSigned}, want: identity.ErrNotProven},
		{name: "signed-code", frame: []byte("effect"), need: identity.Need{Code: identity.ProofSigned}, want: identity.ErrNotProven},
	} {
		t.Run(tc.name, func(t *testing.T) {
			binding := messageTestBinding(t)
			var replies atomic.Int32
			done := make(chan struct{})
			reply := func(context.Context, []byte) error { replies.Add(1); return nil }
			if tc.missingDone {
				done = nil
			}
			if tc.missingReply {
				reply = nil
			}
			conn := &testMessageConn{message: receivedMessage{frame: tc.frame, binding: binding, done: done, reply: reply}, err: tc.receiveErr}
			call, err := ReceiveFramed(context.Background(), conn, tc.need, 16)
			if call != nil || !errors.Is(err, tc.want) {
				t.Fatalf("call=%v error=%v, want %v", call, err, tc.want)
			}
			if replies.Load() != 0 || conn.binds.Load() != 0 || conn.closes.Load() != 1 {
				t.Fatalf("reply=%d bind=%d close=%d", replies.Load(), conn.binds.Load(), conn.closes.Load())
			}
			wantRefusals := int32(0)
			if errors.Is(tc.want, identity.ErrNotProven) {
				wantRefusals = 1
				if conn.tokens[0] == 0 || conn.tokens[1] != byte(identity.ProofSigned) {
					t.Fatalf("proof tokens=%v", conn.tokens)
				}
			}
			if got := conn.refusals.Load(); got != wantRefusals {
				t.Fatalf("refusals=%d, want %d", got, wantRefusals)
			}
			if _, peerErr := binding.Peer(); !errors.Is(peerErr, net.ErrClosed) {
				t.Fatalf("rejected binding remains open: %v", peerErr)
			}
		})
	}
}

func TestMessageReceiveCancellationClosesRequest(t *testing.T) {
	binding := messageTestBinding(t)
	ctx, cancel := context.WithCancel(context.Background())
	conn := &testMessageConn{message: receivedMessage{frame: nil, binding: binding, done: make(chan struct{}), reply: func(context.Context, []byte) error { return nil }}}
	call, err := ReceiveFramed(ctx, conn, framingNeed, 16)
	if err != nil {
		t.Fatal(err)
	}
	cancel()
	deadline := time.Now().Add(time.Second)
	for conn.closes.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if conn.closes.Load() != 1 {
		t.Fatal("cancellation did not close message request")
	}
	if _, err := call.Peer(); err == nil {
		t.Fatal("peer remained available after cancellation")
	}
}

func TestSessionsDeliversMessageTransportWithoutStreamHandshake(t *testing.T) {
	binding := messageTestBinding(t)
	conn := &testMessageConn{message: receivedMessage{
		frame: []byte("message"), binding: binding, done: make(chan struct{}),
		reply: func(context.Context, []byte) error { return nil },
	}}
	inner := &testMessageListener{conn: conn, closed: make(chan struct{})}
	listener := Sessions(inner, SessionOptions{})
	defer listener.Close()
	accepted, err := listener.Accept()
	if err != nil {
		t.Fatal(err)
	}
	call, err := ReceiveFramed(context.Background(), accepted, framingNeed, 16)
	if err != nil {
		t.Fatal(err)
	}
	defer call.Close()
	if !bytes.Equal(call.Frame, []byte("message")) || conn.receives.Load() != 1 || conn.binds.Load() != 0 {
		t.Fatalf("frame=%q receives=%d binds=%d", call.Frame, conn.receives.Load(), conn.binds.Load())
	}
}

func TestMessageReplyDeadlineInterruptsCallback(t *testing.T) {
	binding := messageTestBinding(t)
	entered := make(chan struct{})
	conn := &testMessageConn{message: receivedMessage{
		frame: []byte("request"), binding: binding, done: make(chan struct{}),
		reply: func(ctx context.Context, _ []byte) error {
			close(entered)
			<-ctx.Done()
			return ctx.Err()
		},
	}}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	call, err := ReceiveFramed(ctx, conn, framingNeed, 16)
	if err != nil {
		t.Fatal(err)
	}
	result := make(chan error, 1)
	go func() { result <- call.Reply([]byte("reply")) }()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("reply callback did not start")
	}
	select {
	case err := <-result:
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("reply: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("reply callback ignored call deadline")
	}
	deadline := time.Now().Add(time.Second)
	for conn.closes.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if conn.closes.Load() != 1 {
		t.Fatalf("deadline closed request %d times", conn.closes.Load())
	}
}
