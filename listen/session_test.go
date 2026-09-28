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
	"runtime"
	"sync"
	"sync/atomic"
	"syscall"
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
	attempts atomic.Int32
	frames   chan []byte
	pids     chan int
	wg       sync.WaitGroup
}

// serveSessions runs a framed echo host on a session listener: each accepted
// Conn is one exchange, handled exactly as a single-exchange host handles it.
func serveSessions(t *testing.T, opts SessionOptions, need identity.Need, handle func(*FramedCall) error) *sessionServer {
	return serveSessionsWithNeeds(t, opts, func(int32) identity.Need { return need }, handle)
}

func serveSessionsWithNeeds(t *testing.T, opts SessionOptions, needAt func(int32) identity.Need, handle func(*FramedCall) error) *sessionServer {
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
				k, err := ReceiveFramed(ctx, c, needAt(s.attempts.Add(1)), 0)
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

type heldAcceptListener struct {
	entered chan struct{}
	closed  chan struct{}
	release chan struct{}
	once    sync.Once
}

func (l *heldAcceptListener) Accept() (Conn, error) {
	l.once.Do(func() { close(l.entered) })
	<-l.release
	return nil, net.ErrClosed
}

func (l *heldAcceptListener) Close() error {
	close(l.closed)
	return nil
}

func TestSessionCloseWaitsForAcceptToReleaseItsHandle(t *testing.T) {
	inner := &heldAcceptListener{entered: make(chan struct{}), closed: make(chan struct{}), release: make(chan struct{})}
	l := Sessions(inner, SessionOptions{})
	<-inner.entered
	closed := make(chan error, 1)
	go func() { closed <- l.Close() }()
	<-inner.closed
	select {
	case err := <-closed:
		t.Fatalf("Close returned before Accept released its handle: %v", err)
	default:
	}
	close(inner.release)
	select {
	case err := <-closed:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Close did not finish after Accept released its handle")
	}
}

func TestSessionCloseLetsActiveCallFinishAndDrainsItsTransport(t *testing.T) {
	entered := make(chan struct{})
	release := make(chan struct{})
	s := serveSessions(t, SessionOptions{}, framingNeed, func(k *FramedCall) error {
		close(entered)
		<-release
		return k.Reply(k.Frame)
	})
	client := FrameClient{Endpoint: s.endpoint, Timeout: 2 * time.Second, Sessions: true}
	response := make(chan error, 1)
	go func() {
		_, err := client.ExchangeFrame([]byte("active"))
		response <- err
	}()
	select {
	case <-entered:
	case <-time.After(2 * time.Second):
		close(release)
		t.Fatal("active call was not delivered")
	}
	closed := make(chan error, 1)
	go func() { closed <- s.l.Close() }()
	select {
	case err := <-closed:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		close(release)
		t.Fatal("listener Close waited for the active handler")
	}
	close(release)
	select {
	case err := <-response:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("active call did not finish")
	}
	s.wg.Wait()
	l := s.l.(*sessionListener)
	l.mu.Lock()
	remaining := len(l.sessions)
	l.mu.Unlock()
	if remaining != 0 {
		t.Fatalf("host worker finished while %d session transport remained open", remaining)
	}
	again, err := Listen(s.endpoint)
	if err != nil {
		t.Fatalf("the endpoint could not be rebound after its worker finished: %v", err)
	}
	again.Close()
}

type queuedSessionListener struct {
	conn   Conn
	closed chan struct{}
	once   sync.Once
}

func (l *queuedSessionListener) Accept() (Conn, error) {
	if l.conn != nil {
		c := l.conn
		l.conn = nil
		return c, nil
	}
	<-l.closed
	return nil, net.ErrClosed
}

func (l *queuedSessionListener) Close() error {
	l.once.Do(func() { close(l.closed) })
	return nil
}

type gatedSessionConn struct {
	net.Conn
	closing chan struct{}
	release chan struct{}
}

func (c *gatedSessionConn) Bind() (*identity.Binding, error) { return nil, nil }
func (c *gatedSessionConn) Close() error {
	close(c.closing)
	<-c.release
	return c.Conn.Close()
}

func TestSessionCloseDrainsAnUndeliveredCall(t *testing.T) {
	server, client := net.Pipe()
	defer client.Close()
	conn := &gatedSessionConn{Conn: server, closing: make(chan struct{}), release: make(chan struct{})}
	inner := &queuedSessionListener{conn: conn, closed: make(chan struct{})}
	l := Sessions(inner, SessionOptions{}).(*sessionListener)
	opened := make(chan error, 1)
	go func() {
		if err := writeUint32(client, sessionFlag); err != nil {
			opened <- err
			return
		}
		ack, _, err := readUint32(client)
		if err == nil && ack != sessionAccept {
			err = fmt.Errorf("session answer %#x", ack)
		}
		opened <- err
	}()
	if err := <-opened; err != nil {
		t.Fatal(err)
	}
	// The session has answered its opening header and is waiting to hand its
	// first call to Accept. There is deliberately no Accept caller.
	closed := make(chan error, 1)
	go func() { closed <- l.Close() }()
	select {
	case <-conn.closing:
	case <-time.After(2 * time.Second):
		t.Fatal("the undelivered session did not begin closing")
	}
	select {
	case err := <-closed:
		t.Fatalf("Close returned before the undelivered pipe was closed: %v", err)
	default:
	}
	close(conn.release)
	select {
	case err := <-closed:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Close did not finish after the pipe closed")
	}
}

func TestSessionCloseLeavesDeliveredPlainConnectionWithItsCaller(t *testing.T) {
	server, client := net.Pipe()
	defer client.Close()
	conn := &gatedSessionConn{Conn: server, closing: make(chan struct{}), release: make(chan struct{})}
	inner := &queuedSessionListener{conn: conn, closed: make(chan struct{})}
	l := Sessions(inner, SessionOptions{})
	go client.Write([]byte{0})
	owned, err := l.Accept()
	if err != nil {
		t.Fatal(err)
	}
	closed := make(chan error, 1)
	go func() { closed <- l.Close() }()
	select {
	case err := <-closed:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		close(conn.release)
		t.Fatal("Close waited on a connection already delivered to the caller")
	}
	select {
	case <-conn.closing:
		t.Fatal("Close interrupted a connection already delivered to the caller")
	default:
	}
	close(conn.release)
	if err := owned.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestPendingSessionConnectionOwnershipTransfer(t *testing.T) {
	for _, releaseFirst := range []bool{true, false} {
		server, client := net.Pipe()
		conn := &gatedSessionConn{Conn: server, closing: make(chan struct{}), release: make(chan struct{})}
		close(conn.release)
		p := &pendingSessionConn{conn: conn, owned: true}
		if releaseFirst {
			if !p.release() {
				t.Fatal("live connection was not released to the caller")
			}
			p.interrupt()
			select {
			case <-conn.closing:
				t.Fatal("shutdown closed caller-owned connection")
			default:
			}
			conn.Close()
		} else {
			p.interrupt()
			if p.release() {
				t.Fatal("closed connection was released to the caller")
			}
			select {
			case <-conn.closing:
			default:
				t.Fatal("shutdown did not close its pending connection")
			}
		}
		client.Close()
	}
}

func TestFreshSessionCallerProofRefusalIsTerminal(t *testing.T) {
	for _, oneWay := range []bool{false, true} {
		s := serveSessions(t, SessionOptions{}, identity.Need{User: identity.ProofSigned}, echo)
		client := FrameClient{Endpoint: s.endpoint, Timeout: 2 * time.Second, Sessions: true}
		var err error
		if oneWay {
			err = client.WriteFrame([]byte("one-way"))
		} else {
			_, err = client.ExchangeFrame([]byte("effect"))
		}
		var refusal *ProofRefusal
		if !errors.As(err, &refusal) || refusal.Attribute != "user" || refusal.Required != identity.ProofSigned {
			t.Fatalf("oneWay=%t refusal=%v", oneWay, err)
		}
		if got := s.calls.Load(); got != 0 {
			t.Fatalf("refused request dispatched %d times", got)
		}
		if got := s.physical.accepted.Load(); got != 1 {
			t.Fatalf("terminal refusal opened %d connections", got)
		}
	}
}

type failedSessionWriteConn struct {
	net.Conn
	response io.Reader
	writes   int
}

func (c *failedSessionWriteConn) Read(p []byte) (int, error) { return c.response.Read(p) }
func (c *failedSessionWriteConn) Write([]byte) (int, error) {
	c.writes++
	return 0, syscall.EPIPE
}

func TestSessionWriteFailureRecognizesOnlyCompleteProofRefusal(t *testing.T) {
	marker := proofRefusalBytes(&identity.ProofError{Attribute: "user", Want: identity.ProofSigned})
	tests := []struct {
		name        string
		response    []byte
		wantRefusal bool
	}{
		{"complete refusal", marker[:], true},
		{"partial header", marker[:3], false},
		{"partial tokens", marker[:5], false},
		{"wrong marker", []byte{0x80, 0, 0, 0}, false},
		{"EOF", nil, false},
	}
	for _, pooled := range []bool{false, true} {
		for _, oneWay := range []bool{false, true} {
			for _, tc := range tests {
				t.Run(fmt.Sprintf("pooled=%t/oneWay=%t/%s", pooled, oneWay, tc.name), func(t *testing.T) {
					response := append([]byte(nil), tc.response...)
					if !pooled {
						var accept [4]byte
						binary.BigEndian.PutUint32(accept[:], sessionAccept)
						response = append(accept[:], response...)
					}
					conn := &failedSessionWriteConn{response: bytes.NewReader(response)}
					if !pooled {
						ack, _, err := readUint32(conn)
						if err != nil || ack != sessionAccept {
							t.Fatalf("session acceptance = %#x, %v", ack, err)
						}
					}
					frame := []byte("effect")
					flags := sessionFlag | uint32(len(frame))
					if oneWay {
						flags |= oneWayFlag
					}
					var writeErr error
					if pooled {
						_, writeErr = writeHeadedCount(conn, flags, frame)
					} else {
						writeErr = writeAll(conn, frame)
					}
					if !errors.Is(writeErr, syscall.EPIPE) || conn.writes != 1 {
						t.Fatalf("write error = %v, writes = %d", writeErr, conn.writes)
					}
					got := refusalAfterWriteError(context.Background(), conn, writeErr, false)
					var refusal *ProofRefusal
					if tc.wantRefusal {
						if !errors.As(got, &refusal) || refusal.Attribute != "user" || refusal.Required != identity.ProofSigned {
							t.Fatalf("proof refusal = %v", got)
						}
					} else if !errors.Is(got, syscall.EPIPE) {
						t.Fatalf("original write error = %v", got)
					}
				})
			}
		}
	}
}

func TestSessionWriteFailureRefusalReadUsesCallDeadline(t *testing.T) {
	client, peer := net.Pipe()
	defer client.Close()
	defer peer.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Millisecond)
	defer cancel()
	deadline, _ := ctx.Deadline()
	if err := client.SetDeadline(deadline); err != nil {
		t.Fatal(err)
	}
	got := refusalAfterWriteError(ctx, client, syscall.EPIPE, false)
	if !errors.Is(got, syscall.EPIPE) {
		t.Fatalf("deadline-bound refusal read = %v", got)
	}
}

func TestFreshSessionHeaderWriteFailureUsesTerminalRefusal(t *testing.T) {
	marker := proofRefusalBytes(&identity.ProofError{Attribute: "user", Want: identity.ProofSigned})
	invalid := marker
	invalid[4] = 0xFF
	for _, oneWay := range []bool{false, true} {
		for _, tc := range []struct {
			name        string
			response    []byte
			wantRefusal bool
		}{
			{"accepted", appendSessionWord(sessionAccept, marker[:]), true},
			{"declined", appendSessionWord(sessionDecline, marker[:]), true},
			{"unsupported", appendSessionWord(sessionUnsupported, marker[:]), true},
			{"direct refusal", marker[:], true},
			{"partial acceptance", []byte{0x80, 0}, false},
			{"partial refusal", appendSessionWord(sessionAccept, marker[:5]), false},
			{"invalid refusal", appendSessionWord(sessionAccept, invalid[:]), false},
			{"other answer", []byte{0, 0, 0, 1}, false},
			{"EOF", nil, false},
		} {
			t.Run(fmt.Sprintf("oneWay=%t/%s", oneWay, tc.name), func(t *testing.T) {
				conn := &failedSessionWriteConn{response: bytes.NewReader(tc.response)}
				flags := sessionFlag | 6
				if oneWay {
					flags |= oneWayFlag
				}
				got := writeFreshSessionHeader(context.Background(), conn, flags)
				assertSessionWriteFailure(t, got, tc.wantRefusal)
				if conn.writes != 1 {
					t.Fatalf("header writes = %d, want 1", conn.writes)
				}
			})
		}
	}
}

func TestDeclinedSessionBodyWriteFailureUsesTerminalRefusal(t *testing.T) {
	marker := proofRefusalBytes(&identity.ProofError{Attribute: "user", Want: identity.ProofSigned})
	for _, answer := range []uint32{sessionDecline, sessionUnsupported} {
		for _, oneWay := range []bool{false, true} {
			for _, tc := range []struct {
				name        string
				response    []byte
				wantRefusal bool
			}{
				{"complete refusal", marker[:], true},
				{"partial refusal", marker[:5], false},
				{"EOF", nil, false},
			} {
				t.Run(fmt.Sprintf("answer=%#x/oneWay=%t/%s", answer, oneWay, tc.name), func(t *testing.T) {
					conn := &failedSessionWriteConn{response: bytes.NewReader(appendSessionWord(answer, tc.response))}
					gotAnswer, _, err := readUint32(conn)
					if err != nil || gotAnswer != answer {
						t.Fatalf("session answer = %#x, %v", gotAnswer, err)
					}
					_, got := singleOnSession(context.Background(), conn, []byte("effect"), DefaultMaxFrame, oneWay)
					assertSessionWriteFailure(t, got, tc.wantRefusal)
					if conn.writes != 1 {
						t.Fatalf("body writes = %d, want 1", conn.writes)
					}
				})
			}
		}
	}
}

func appendSessionWord(word uint32, tail []byte) []byte {
	var header [4]byte
	binary.BigEndian.PutUint32(header[:], word)
	return append(header[:], tail...)
}

func assertSessionWriteFailure(t *testing.T, got error, wantRefusal bool) {
	t.Helper()
	var refusal *ProofRefusal
	if wantRefusal {
		if !errors.As(got, &refusal) || refusal.Attribute != "user" || refusal.Required != identity.ProofSigned {
			t.Fatalf("proof refusal = %v", got)
		}
	} else if !errors.Is(got, syscall.EPIPE) {
		t.Fatalf("original write error = %v", got)
	}
}

func TestPooledSessionCallerProofRefusalIsTerminal(t *testing.T) {
	for _, oneWay := range []bool{false, true} {
		s := serveSessionsWithNeeds(t, SessionOptions{}, func(attempt int32) identity.Need {
			if attempt == 1 {
				return framingNeed
			}
			return identity.Need{User: identity.ProofSigned}
		}, echo)
		client := FrameClient{Endpoint: s.endpoint, Timeout: 2 * time.Second, Sessions: true}
		if reply, err := client.ExchangeFrame([]byte("warm")); err != nil || string(reply) != "warm" {
			t.Fatalf("warm exchange=%q, %v", reply, err)
		}
		var err error
		if oneWay {
			err = client.WriteFrame([]byte("one-way"))
		} else {
			_, err = client.ExchangeFrame([]byte("effect"))
		}
		var refusal *ProofRefusal
		if !errors.As(err, &refusal) || refusal.Attribute != "user" || refusal.Required != identity.ProofSigned {
			t.Fatalf("oneWay=%t refusal=%v", oneWay, err)
		}
		if got := s.calls.Load(); got != 1 {
			t.Fatalf("server dispatched %d calls, want warmup only", got)
		}
		if got := s.attempts.Load(); got != 2 {
			t.Fatalf("server attempted %d calls, want two without replay", got)
		}
		if got := s.physical.accepted.Load(); got != 1 {
			t.Fatalf("refusal opened %d physical connections", got)
		}
	}
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

func TestBusySessionRenewsBindingBeforeAnotherRequest(t *testing.T) {
	s := serveSessions(t, SessionOptions{MaxAge: 40 * time.Millisecond, Idle: time.Second}, framingNeed, echo)
	client := FrameClient{Endpoint: s.endpoint, Timeout: 2 * time.Second, Sessions: true}
	for i := 0; i < 8; i++ {
		if reply, err := client.ExchangeFrame([]byte("busy")); err != nil || string(reply) != "busy" {
			t.Fatalf("exchange %d: %q, %v", i, reply, err)
		}
		<-s.frames
		time.Sleep(15 * time.Millisecond)
	}
	if got := s.calls.Load(); got != 8 {
		t.Fatalf("%d dispatched calls, want eight", got)
	}
	if got := s.physical.accepted.Load(); got < 2 {
		t.Fatalf("%d physical connections kept the original binding beyond MaxAge", got)
	}
}

func TestSessionMaxAgeCannotExceedVerdictBound(t *testing.T) {
	s := serveSessions(t, SessionOptions{MaxAge: time.Hour}, framingNeed, echo)
	if got := s.l.(*sessionListener).opts.MaxAge; got != DefaultSessionMaxAge {
		t.Fatalf("session MaxAge %s exceeds verdict bound %s", got, DefaultSessionMaxAge)
	}
}

func TestSessionDeadlineUsesRemainingEvidenceLifetime(t *testing.T) {
	boundAt := time.Now()
	evidenceUntil := boundAt.Add(30 * time.Second)
	if got := sessionDeadline(boundAt, DefaultSessionMaxAge, evidenceUntil); !got.Equal(evidenceUntil) {
		t.Fatalf("session deadline %s extends older evidence past %s", got, evidenceUntil)
	}
	if got := sessionDeadline(boundAt, 10*time.Second, evidenceUntil); !got.Equal(boundAt.Add(10 * time.Second)) {
		t.Fatalf("shorter configured age was lost: %s", got)
	}
}

func TestSessionAcceptedCallCanReplyAfterBindingExpiry(t *testing.T) {
	s := serveSessions(t, SessionOptions{MaxAge: 40 * time.Millisecond}, framingNeed, func(k *FramedCall) error {
		time.Sleep(90 * time.Millisecond)
		return k.Reply(k.Frame)
	})
	client := FrameClient{Endpoint: s.endpoint, Timeout: 2 * time.Second, Sessions: true}
	if reply, err := client.ExchangeFrame([]byte("accepted")); err != nil || string(reply) != "accepted" {
		t.Fatalf("accepted call after binding expiry: %q, %v", reply, err)
	}
}

func TestSessionDoesNotDispatchBodyCompletedAfterBindingExpiry(t *testing.T) {
	s := serveSessions(t, SessionOptions{MaxAge: 40 * time.Millisecond}, framingNeed, echo)
	conn, err := dialFramed(context.Background(), s.endpoint)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if err := writeUint32(conn, sessionFlag|2); err != nil {
		t.Fatal(err)
	}
	if ack, _, err := readUint32(conn); err != nil || ack != sessionAccept {
		t.Fatalf("session acknowledgement %#x, %v", ack, err)
	}
	if _, err := conn.Write([]byte("a")); err != nil {
		t.Fatal(err)
	}
	time.Sleep(90 * time.Millisecond)
	// The peer may close as soon as it notices expiry. Either way the second
	// byte must never turn the old binding into a dispatched frame.
	conn.Write([]byte("b"))
	var b [1]byte
	_, err = conn.Read(b[:])
	if err == nil {
		t.Fatalf("expired request received response byte %#x", b[0])
	}
	if got := s.calls.Load(); got != 0 {
		t.Fatalf("%d frames dispatched after binding expiry", got)
	}
}

type completeWriteErrorConn struct {
	net.Conn
	dispatched  <-chan []byte
	failure     error
	underreport bool
}

type partialWriteErrorConn struct {
	net.Conn
	failure error
}

func (c *partialWriteErrorConn) SyscallConn() (syscall.RawConn, error) {
	return c.Conn.(syscall.Conn).SyscallConn()
}

func (c *partialWriteErrorConn) Write(p []byte) (int, error) {
	n, err := c.Conn.Write(p[:len(p)-1])
	if err != nil {
		return n, err
	}
	return n, c.failure
}

func (c *completeWriteErrorConn) SyscallConn() (syscall.RawConn, error) {
	return c.Conn.(syscall.Conn).SyscallConn()
}

func (c *completeWriteErrorConn) Write(p []byte) (int, error) {
	n, err := c.Conn.Write(p)
	if err != nil || n != len(p) {
		return n, err
	}
	select {
	case <-c.dispatched:
		if c.underreport {
			return 0, c.failure
		}
		return n, c.failure
	case <-time.After(2 * time.Second):
		return n, errors.New("server did not dispatch the complete request")
	}
}

func TestPooledSessionDoesNotReplayACompleteWriteWithError(t *testing.T) {
	s := serveSessions(t, SessionOptions{}, framingNeed, echo)
	client := FrameClient{Endpoint: s.endpoint, Timeout: 2 * time.Second, Sessions: true}
	if _, err := client.ExchangeFrame([]byte("warm")); err != nil {
		t.Fatal(err)
	}
	<-s.frames
	failure := errors.New("injected error after complete request write")
	key := client.poolKey()
	frames.mu.Lock()
	idle := frames.idle[key]
	if len(idle) != 1 {
		frames.mu.Unlock()
		t.Fatalf("%d pooled connections, want one", len(idle))
	}
	idle[0].conn.Conn = &completeWriteErrorConn{Conn: idle[0].conn.Conn, dispatched: s.frames, failure: failure}
	frames.mu.Unlock()
	_, err := client.ExchangeFrame([]byte("effect"))
	if !errors.Is(err, failure) {
		t.Fatalf("complete write error was retried or lost: %v", err)
	}
	if got := s.calls.Load(); got != 2 {
		t.Fatalf("server dispatched %d calls, want warmup and one effect", got)
	}
}

func TestPooledWindowsSessionDoesNotReplayAnUnderreportedWrite(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("Windows overlapped pipe write counts can underreport accepted bytes on failure")
	}
	s := serveSessions(t, SessionOptions{}, framingNeed, echo)
	client := FrameClient{Endpoint: s.endpoint, Timeout: 2 * time.Second, Sessions: true}
	if _, err := client.ExchangeFrame([]byte("warm")); err != nil {
		t.Fatal(err)
	}
	<-s.frames
	failure := errors.New("injected failed write with an unreported complete request")
	key := client.poolKey()
	frames.mu.Lock()
	idle := frames.idle[key]
	if len(idle) != 1 {
		frames.mu.Unlock()
		t.Fatalf("%d pooled connections, want one", len(idle))
	}
	idle[0].conn.Conn = &completeWriteErrorConn{Conn: idle[0].conn.Conn, dispatched: s.frames, failure: failure, underreport: true}
	frames.mu.Unlock()
	_, err := client.ExchangeFrame([]byte("effect"))
	if !errors.Is(err, failure) {
		t.Fatalf("underreported write error was retried or lost: %v", err)
	}
	if got := s.calls.Load(); got != 2 {
		t.Fatalf("server dispatched %d calls, want warmup and one effect", got)
	}
}

func TestPooledSessionDoesNotReplayAnIncompleteRequest(t *testing.T) {
	s := serveSessions(t, SessionOptions{}, framingNeed, echo)
	client := FrameClient{Endpoint: s.endpoint, Timeout: 2 * time.Second, Sessions: true}
	if _, err := client.ExchangeFrame([]byte("warm")); err != nil {
		t.Fatal(err)
	}
	<-s.frames
	key := client.poolKey()
	frames.mu.Lock()
	idle := frames.idle[key]
	if len(idle) != 1 {
		frames.mu.Unlock()
		t.Fatalf("%d pooled connections, want one", len(idle))
	}
	failure := errors.New("injected short write")
	idle[0].conn.Conn = &partialWriteErrorConn{Conn: idle[0].conn.Conn, failure: failure}
	frames.mu.Unlock()
	reply, err := client.ExchangeFrame([]byte("effect"))
	if !errors.Is(err, failure) {
		t.Fatalf("incomplete write error was lost: %q, %v", reply, err)
	}
	if got := s.calls.Load(); got != 1 {
		t.Fatalf("server dispatched %d calls, want warmup only", got)
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

// A failed deadline does not prove that Read will fail or remain bounded.
type refusedIdleDeadlineConn struct {
	bufferedSessionConn
	reads  int
	closed bool
}

func (c *refusedIdleDeadlineConn) SetDeadline(time.Time) error { return errors.New("deadline refused") }
func (c *refusedIdleDeadlineConn) Read(p []byte) (int, error) {
	c.reads++
	return c.bufferedSessionConn.Read(p)
}
func (c *refusedIdleDeadlineConn) Close() error { c.closed = true; return nil }

func TestSessionClosesWhenIdleDeadlineCannotBeSet(t *testing.T) {
	pc := &refusedIdleDeadlineConn{bufferedSessionConn: bufferedSessionConn{input: bytes.NewReader(nil)}}
	l := &sessionListener{calls: make(chan Conn), done: make(chan struct{}),
		opts: SessionOptions{Idle: time.Second, MaxAge: time.Minute}, sessions: map[*session]struct{}{}}
	defer close(l.done)
	s := &session{l: l, pc: pc}
	l.sessions[s] = struct{}{}
	finished := make(chan struct{})
	go func() { s.run(sessionFlag); close(finished) }()
	select {
	case conn := <-l.calls:
		call := conn.(*sessionCall)
		call.continued = true
		close(call.done)
	case <-time.After(time.Second):
		t.Fatal("first call was not delivered")
	}
	select {
	case <-finished:
	case <-time.After(time.Second):
		t.Fatal("session did not close after deadline failure")
	}
	if pc.reads != 0 || !pc.closed || len(l.sessions) != 0 {
		t.Fatalf("deadline failure: reads=%d closed=%t retained=%d", pc.reads, pc.closed, len(l.sessions))
	}
}
