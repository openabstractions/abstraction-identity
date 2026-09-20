package listen

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	identity "github.com/openabstractions/abstraction-identity"
)

// countingListener counts physical connections under a session listener.
type countingListener struct {
	Listener
	accepted atomic.Int32
}

func (l *countingListener) Accept() (Conn, error) {
	c, err := l.Listener.Accept()
	if err == nil {
		l.accepted.Add(1)
	}
	return c, err
}

type sessionServer struct {
	endpoint string
	physical *countingListener
	l        Listener
	calls    atomic.Int32
	frames   chan []byte
	pids     chan int
	wg       sync.WaitGroup
}

// serveSessions runs a framed echo host on a session listener: each accepted
// Conn is one exchange, handled exactly as a single-exchange host handles it.
func serveSessions(t *testing.T, opts SessionOptions, need identity.Need, handle func(*FramedCall) error) *sessionServer {
	t.Helper()
	endpoint := framedEndpoint(t)
	inner, err := Listen(endpoint)
	if err != nil {
		t.Fatal(err)
	}
	s := &sessionServer{endpoint: endpoint, physical: &countingListener{Listener: inner}, frames: make(chan []byte, 64), pids: make(chan int, 64)}
	s.l = Sessions(s.physical, opts)
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		for {
			c, err := s.l.Accept()
			if err != nil {
				return
			}
			s.wg.Add(1)
			go func() {
				defer s.wg.Done()
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				k, err := ReceiveFramed(ctx, c, need, 0)
				if err != nil {
					return
				}
				defer k.Close()
				s.calls.Add(1)
				if peer, err := k.Peer(); err == nil {
					if p, err := peer.Process.AtLeast(identity.ProofPID); err == nil {
						s.pids <- p.PID
					}
				}
				s.frames <- k.Frame
				if handle != nil {
					if err := handle(k); err != nil {
						return
					}
				}
			}()
		}
	}()
	t.Cleanup(func() { s.l.Close(); s.wg.Wait() })
	return s
}

// echo replies to every frame except "one-way", which is written with WriteFrame.
func echo(k *FramedCall) error {
	if string(k.Frame) == "one-way" {
		return nil
	}
	return k.Reply(k.Frame)
}

func TestSessionCarriesSequentialExchangesOnOneConnection(t *testing.T) {
	s := serveSessions(t, SessionOptions{}, framingNeed, echo)
	client := FrameClient{Endpoint: s.endpoint, Timeout: 2 * time.Second, Sessions: true}
	for i := 0; i < 20; i++ {
		payload := bytes.Repeat([]byte{byte(i), 0, '\n'}, i*1000)
		reply, err := client.ExchangeFrame(payload)
		if err != nil || !bytes.Equal(reply, payload) {
			t.Fatalf("exchange %d: %v", i, err)
		}
		if pid := <-s.pids; pid != os.Getpid() {
			t.Fatalf("exchange %d bound pid %d, want %d", i, pid, os.Getpid())
		}
	}
	for i := 0; i < 5; i++ {
		if err := client.WriteFrame([]byte("one-way")); err != nil {
			t.Fatalf("write %d: %v", i, err)
		}
	}
	if got := s.calls.Load(); got != 25 {
		t.Fatalf("server handled %d calls, want 25", got)
	}
	if got := s.physical.accepted.Load(); got != 1 {
		t.Fatalf("%d connections carried 25 calls, want 1", got)
	}
}

func TestSessionClientFallsBackToSingleExchangeServer(t *testing.T) {
	endpoint := framedEndpoint(t)
	inner, err := Listen(endpoint)
	if err != nil {
		t.Fatal(err)
	}
	physical := &countingListener{Listener: inner}
	defer physical.Close()
	go func() {
		for {
			c, err := physical.Accept()
			if err != nil {
				return
			}
			go func() {
				k, err := ReceiveFramed(context.Background(), c, framingNeed, 0)
				if err != nil {
					return
				}
				defer k.Close()
				k.Reply(k.Frame)
			}()
		}
	}()
	client := FrameClient{Endpoint: endpoint, Timeout: 2 * time.Second, Sessions: true}
	for i := 0; i < 3; i++ {
		reply, err := client.ExchangeFrame([]byte("plain"))
		if err != nil || string(reply) != "plain" {
			t.Fatalf("exchange %d: %q %v", i, reply, err)
		}
	}
	// The first connection answers the session request as unsupported and
	// serves its exchange; then one connection per call.
	if got := physical.accepted.Load(); got != 3 {
		t.Fatalf("%d connections, want 3", got)
	}
}

// TestSessionClientFallsBackWhenAServerClosesTheRequest serves the way a
// server built before sessions does: an oversized header is refused and the
// connection closed. The client serves the call on a new connection.
func TestSessionClientFallsBackWhenAServerClosesTheRequest(t *testing.T) {
	endpoint := framedEndpoint(t)
	inner, err := Listen(endpoint)
	if err != nil {
		t.Fatal(err)
	}
	physical := &countingListener{Listener: inner}
	defer physical.Close()
	go func() {
		for {
			c, err := physical.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				c.(deadlineConn).SetDeadline(time.Now().Add(2 * time.Second))
				header, _, err := readUint32(c)
				if err != nil || header > DefaultMaxFrame {
					return
				}
				body := make([]byte, header)
				if _, err := io.ReadFull(c, body); err != nil {
					return
				}
				if writeFrame(c, body, DefaultMaxFrame) == nil {
					waitFrameEOF(c)
				}
			}()
		}
	}()
	client := FrameClient{Endpoint: endpoint, Timeout: 2 * time.Second, Sessions: true}
	for i := 0; i < 3; i++ {
		reply, err := client.ExchangeFrame([]byte("old"))
		if err != nil || string(reply) != "old" {
			t.Fatalf("exchange %d: %q %v", i, reply, err)
		}
	}
	if got := physical.accepted.Load(); got != 4 {
		t.Fatalf("%d connections, want 4: the closed session request, then one per call", got)
	}
}

func TestSingleExchangeClientOnSessionListener(t *testing.T) {
	s := serveSessions(t, SessionOptions{}, framingNeed, echo)
	client := FrameClient{Endpoint: s.endpoint, Timeout: 2 * time.Second}
	for i := 0; i < 3; i++ {
		reply, err := client.ExchangeFrame([]byte("single"))
		if err != nil || string(reply) != "single" {
			t.Fatalf("exchange %d: %q %v", i, reply, err)
		}
		if err := client.WriteFrame([]byte("one-way")); err != nil {
			t.Fatal(err)
		}
	}
	if got := s.physical.accepted.Load(); got != 6 {
		t.Fatalf("%d connections, want 6", got)
	}
}

func TestIdleSessionIsRetiredAndReplaced(t *testing.T) {
	s := serveSessions(t, SessionOptions{Idle: 50 * time.Millisecond}, framingNeed, echo)
	client := FrameClient{Endpoint: s.endpoint, Timeout: 2 * time.Second, Sessions: true}
	for i := 0; i < 2; i++ {
		if _, err := client.ExchangeFrame([]byte("x")); err != nil {
			t.Fatal(err)
		}
		time.Sleep(200 * time.Millisecond)
	}
	if got, calls := s.physical.accepted.Load(), s.calls.Load(); got != 2 || calls != 2 {
		t.Fatalf("%d connections and %d calls, want 2 and 2", got, calls)
	}
}

// rawSession opens a session by hand and completes one exchange on it.
func rawSession(t *testing.T, endpoint string) Conn {
	t.Helper()
	conn, err := dialFramed(context.Background(), endpoint)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	conn.SetDeadline(time.Now().Add(3 * time.Second))
	if err := writeUint32(conn, sessionFlag|1); err != nil {
		t.Fatal(err)
	}
	if ack, _, err := readUint32(conn); err != nil || ack != sessionAccept {
		t.Fatalf("ack %#x %v", ack, err)
	}
	if _, err := conn.Write([]byte("a")); err != nil {
		t.Fatal(err)
	}
	header, _, err := readUint32(conn)
	if err != nil || header != sessionFlag|1 {
		t.Fatalf("reply header %#x %v", header, err)
	}
	if _, err := io.ReadFull(conn, make([]byte, 1)); err != nil {
		t.Fatal(err)
	}
	return rawConn{conn}
}

type rawConn struct{ io.ReadWriteCloser }

func (rawConn) Bind() (*identity.Binding, error) { return nil, errors.New("client side") }

type bufferedSessionConn struct {
	input  *bytes.Reader
	output bytes.Buffer
}

func (c *bufferedSessionConn) Read(p []byte) (int, error)  { return c.input.Read(p) }
func (c *bufferedSessionConn) Write(p []byte) (int, error) { return c.output.Write(p) }
func (*bufferedSessionConn) Close() error                  { return nil }
func (*bufferedSessionConn) Bind() (*identity.Binding, error) {
	return nil, errors.New("fixture has no peer")
}
func (*bufferedSessionConn) SetDeadline(time.Time) error     { return nil }
func (*bufferedSessionConn) SetReadDeadline(time.Time) error { return nil }

func TestRetiredSessionRejectsAHeaderThatWonTheDeadlineRace(t *testing.T) {
	var header [4]byte
	binary.BigEndian.PutUint32(header[:], sessionFlag|1)
	pc := &bufferedSessionConn{input: bytes.NewReader(header[:])}
	s := &session{pc: pc, idle: true, retiring: true}

	if got, ok := s.nextHeader(); ok {
		t.Fatalf("retired session accepted buffered header %#x", got)
	}
	if pc.output.Len() != 0 {
		t.Fatalf("retired session answered after reading request bytes: %x", pc.output.Bytes())
	}
}

// TestRetiredSessionNeverDispatchesALaterRequest retires an idle session while
// its client writes a request, and requires the client to read the closing
// marker or an ended connection, and the server to dispatch nothing more.
func TestRetiredSessionNeverDispatchesALaterRequest(t *testing.T) {
	s := serveSessions(t, SessionOptions{MaxSessions: 1}, framingNeed, echo)
	first := rawSession(t, s.endpoint)
	<-s.frames
	// A second session takes the only slot by retiring the idle first one,
	// once the first is waiting for its next request.
	for deadline := time.Now().Add(2 * time.Second); ; time.Sleep(time.Millisecond) {
		s.l.(*sessionListener).mu.Lock()
		idle := false
		for other := range s.l.(*sessionListener).sessions {
			other.mu.Lock()
			idle = other.idle
			other.mu.Unlock()
		}
		s.l.(*sessionListener).mu.Unlock()
		if idle || time.Now().After(deadline) {
			break
		}
	}
	second := rawSession(t, s.endpoint)
	<-s.frames
	var request [5]byte
	binary.BigEndian.PutUint32(request[:], sessionFlag|1)
	request[4] = 'b'
	first.Write(request[:])
	header, _, err := readUint32(first)
	if err == nil && header != sessionClosing {
		t.Fatalf("retired session answered %#x", header)
	}
	if got := s.calls.Load(); got != 2 {
		t.Fatalf("server dispatched %d calls, want 2", got)
	}
	second.Close()
}

func TestSessionCallRefusedByNeedEndsTheConnection(t *testing.T) {
	impossible := identity.Need{Code: identity.ProofSigned}
	s := serveSessions(t, SessionOptions{}, impossible, echo)
	client := FrameClient{Endpoint: s.endpoint, Timeout: 2 * time.Second, Sessions: true}
	if _, err := client.ExchangeFrame([]byte("x")); err == nil {
		t.Fatal("a refused caller received a reply")
	}
	if got := s.calls.Load(); got != 0 {
		t.Fatalf("server dispatched %d refused calls", got)
	}
}

func TestSessionWaitContextThenReplyKeepsTheSession(t *testing.T) {
	s := serveSessions(t, SessionOptions{}, framingNeed, func(k *FramedCall) error {
		wait := k.WaitContext()
		select {
		case <-wait.Done():
			return errors.New("caller reported gone while waiting")
		case <-time.After(20 * time.Millisecond):
		}
		return k.Reply(k.Frame)
	})
	client := FrameClient{Endpoint: s.endpoint, Timeout: 2 * time.Second, Sessions: true}
	for i := 0; i < 5; i++ {
		payload := []byte{byte('a' + i)}
		reply, err := client.ExchangeFrame(payload)
		if err != nil || !bytes.Equal(reply, payload) {
			t.Fatalf("exchange %d: %q %v", i, reply, err)
		}
	}
	if got := s.physical.accepted.Load(); got != 1 {
		t.Fatalf("%d connections, want 1", got)
	}
}

func TestSessionCancelledCallIsNotReused(t *testing.T) {
	release := make(chan struct{})
	s := serveSessions(t, SessionOptions{}, framingNeed, func(k *FramedCall) error {
		if string(k.Frame) == "slow" {
			<-release
		}
		return k.Reply(k.Frame)
	})
	client := FrameClient{Endpoint: s.endpoint, Timeout: 2 * time.Second, Sessions: true}
	if _, err := client.ExchangeFrame([]byte("fast")); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if _, err := client.ExchangeFrameContext(ctx, []byte("slow")); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("slow call: %v", err)
	}
	close(release)
	reply, err := client.ExchangeFrame([]byte("after"))
	if err != nil || string(reply) != "after" {
		t.Fatalf("after cancellation: %q %v", reply, err)
	}
	if got := s.physical.accepted.Load(); got != 2 {
		t.Fatalf("%d connections, want 2: the cancelled one must not be reused", got)
	}
}
