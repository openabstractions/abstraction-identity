package listen

import (
	"encoding/binary"
	"errors"
	"io"
	"net"
	"os"
	"sync"
	"time"

	identity "github.com/openabstractions/abstraction-identity"
)

// Sessions carry several sequential framed exchanges on one connection. See
// FRAMING.md "Sessions" for the wire rules; this file is the server half.
const (
	sessionFlag    uint32 = 1 << 31
	oneWayFlag     uint32 = 1 << 30
	lengthMask     uint32 = oneWayFlag - 1
	sessionAccept  uint32 = sessionFlag
	sessionDecline uint32 = 0
	// sessionUnsupported answers a session request on a connection that is
	// served once; the client need not ask this endpoint again for a while.
	sessionUnsupported uint32 = oneWayFlag
	sessionClosing     uint32 = 0xFFFFFFFF
)

// DefaultSessionIdle is how long a server session waits for its next request.
const DefaultSessionIdle = 30 * time.Second

// DefaultMaxSessions bounds the connections one listener holds in session mode.
const DefaultMaxSessions = 64

// ErrSessionProtocol is a peer breaking the session rules; the connection ends.
var ErrSessionProtocol = errors.New("listen: session protocol violation")

// SessionOptions bound a session listener. Zero values select the defaults.
type SessionOptions struct {
	// Idle is how long a session waits for its next request before the
	// server retires it with the closing marker.
	Idle time.Duration
	// MaxSessions bounds connections held in session mode, active or idle.
	// When it is reached an idle session is retired; with none idle, a new
	// connection is declined and serves one exchange.
	MaxSessions int
	// FirstRequest bounds how long a new connection may take to send its
	// first header, and how many connections may be waiting to (twice
	// MaxSessions).
	FirstRequest time.Duration
}

// Sessions wraps a framed listener so a client may keep a connection for
// several sequential exchanges. Each exchange is returned by Accept as its own
// Conn, and ReceiveFramed, Reply and Close work on it unchanged. Bind returns a
// shared view of the connection's one binding; ReceiveFramed checks the need
// against it, and it rechecks the peer, for every exchange. A connection whose
// first byte does not open a session (a single-exchange framed client, or any
// other protocol) is returned once, unchanged, with that byte replayed.
func Sessions(l Listener, opts SessionOptions) Listener {
	if opts.Idle <= 0 {
		opts.Idle = DefaultSessionIdle
	}
	if opts.MaxSessions <= 0 {
		opts.MaxSessions = DefaultMaxSessions
	}
	if opts.FirstRequest <= 0 {
		opts.FirstRequest = DefaultFrameTimeout
	}
	s := &sessionListener{inner: l, opts: opts, calls: make(chan Conn), done: make(chan struct{}), sessions: map[*session]struct{}{}}
	go s.acceptLoop()
	return s
}

type deadlineConn interface {
	Conn
	SetDeadline(time.Time) error
	SetReadDeadline(time.Time) error
}

type sessionListener struct {
	inner    Listener
	opts     SessionOptions
	calls    chan Conn
	done     chan struct{}
	once     sync.Once
	mu       sync.Mutex
	err      error
	waiting  int
	sessions map[*session]struct{}
}

func (l *sessionListener) acceptLoop() {
	for {
		c, err := l.inner.Accept()
		if err != nil {
			l.mu.Lock()
			if l.err == nil {
				l.err = err
			}
			l.mu.Unlock()
			l.Close()
			return
		}
		l.mu.Lock()
		full := l.waiting >= 2*l.opts.MaxSessions
		if !full {
			l.waiting++
		}
		l.mu.Unlock()
		if full {
			c.Close()
			continue
		}
		go l.serve(c)
	}
}

func (l *sessionListener) Accept() (Conn, error) {
	select {
	case c := <-l.calls:
		return c, nil
	case <-l.done:
		l.mu.Lock()
		defer l.mu.Unlock()
		if l.err != nil && !errors.Is(l.err, net.ErrClosed) {
			return nil, l.err
		}
		return nil, net.ErrClosed
	}
}

func (l *sessionListener) Close() error {
	var err error
	l.once.Do(func() {
		close(l.done)
		err = l.inner.Close()
		l.mu.Lock()
		for s := range l.sessions {
			s.retire()
		}
		l.mu.Unlock()
	})
	return err
}

// deliver hands one Conn to Accept, or closes it once the listener is closed.
func (l *sessionListener) deliver(c Conn) bool {
	select {
	case l.calls <- c:
		return true
	case <-l.done:
		c.Close()
		return false
	}
}

func (l *sessionListener) serve(c Conn) {
	header, pc, ok := l.firstHeader(c)
	l.mu.Lock()
	l.waiting--
	l.mu.Unlock()
	if !ok {
		return
	}
	s := &session{l: l, pc: pc}
	l.mu.Lock()
	admitted := len(l.sessions) < l.opts.MaxSessions
	if !admitted {
		for other := range l.sessions {
			if other.retire() {
				admitted = true
				break
			}
		}
	}
	select {
	case <-l.done:
		admitted = false
	default:
	}
	if admitted {
		l.sessions[s] = struct{}{}
	}
	l.mu.Unlock()
	if !admitted {
		// Declined: one exchange, served as a single-exchange connection.
		if err := writeUint32(pc, sessionDecline); err != nil {
			pc.Close()
			return
		}
		pc.SetDeadline(time.Time{})
		var plain [4]byte
		binary.BigEndian.PutUint32(plain[:], header&lengthMask)
		l.deliver(&replayConn{deadlineConn: pc, prefix: plain[:]})
		return
	}
	s.run(header)
}

// firstHeader reads a new connection's first session header. A connection that
// does not open a session is delivered unchanged and reported not ok, as is
// one that failed or closed.
func (l *sessionListener) firstHeader(c Conn) (uint32, deadlineConn, bool) {
	pc, ok := c.(deadlineConn)
	if !ok {
		l.deliver(c)
		return 0, nil, false
	}
	var h [4]byte
	if err := pc.SetDeadline(time.Now().Add(l.opts.FirstRequest)); err != nil {
		pc.Close()
		return 0, nil, false
	}
	if _, err := io.ReadFull(pc, h[:1]); err != nil {
		pc.Close()
		return 0, nil, false
	}
	if h[0]&0x80 == 0 {
		// Not a session: this connection is served exactly as before.
		pc.SetDeadline(time.Time{})
		l.deliver(&replayConn{deadlineConn: pc, prefix: []byte{h[0]}})
		return 0, nil, false
	}
	if _, err := io.ReadFull(pc, h[1:]); err != nil {
		pc.Close()
		return 0, nil, false
	}
	header := binary.BigEndian.Uint32(h[:])
	if header == sessionClosing {
		pc.Close()
		return 0, nil, false
	}
	return header, pc, true
}

// replayConn returns bytes the listener already read before reading on.
type replayConn struct {
	deadlineConn
	mu     sync.Mutex
	prefix []byte
}

func (c *replayConn) Read(p []byte) (int, error) {
	c.mu.Lock()
	if len(c.prefix) > 0 {
		n := copy(p, c.prefix)
		c.prefix = c.prefix[n:]
		c.mu.Unlock()
		return n, nil
	}
	c.mu.Unlock()
	return c.deadlineConn.Read(p)
}

type session struct {
	l        *sessionListener
	pc       deadlineConn
	binding  *identity.Binding
	bindErr  error
	mu       sync.Mutex
	idle     bool
	retiring bool
}

// retire asks an idle session to end with the closing marker, or an active one
// to end after its current exchange. It reports whether the session was idle.
func (s *session) retire() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.retiring = true
	if s.idle {
		s.pc.SetReadDeadline(time.Now())
		return true
	}
	return false
}

func (s *session) isRetiring() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.retiring
}

func (s *session) run(header uint32) {
	defer func() {
		s.l.mu.Lock()
		delete(s.l.sessions, s)
		s.l.mu.Unlock()
		if s.binding != nil {
			s.binding.Close()
		}
		s.pc.Close()
	}()
	if err := writeUint32(s.pc, sessionAccept); err != nil {
		return
	}
	s.binding, s.bindErr = s.pc.Bind()
	for {
		if header&sessionFlag == 0 || header == sessionClosing {
			return
		}
		call := &sessionCall{s: s, remaining: header & lengthMask, oneWay: header&oneWayFlag != 0, done: make(chan struct{})}
		binary.BigEndian.PutUint32(call.header[:], header&lengthMask)
		if !s.l.deliver(call) {
			return
		}
		<-call.done
		if call.broken || !call.continued {
			return
		}
		s.mu.Lock()
		if s.retiring {
			s.mu.Unlock()
			// The client was told it may send again; tell it not to.
			s.pc.SetDeadline(time.Now().Add(DefaultFrameTimeout))
			writeUint32(s.pc, sessionClosing)
			return
		}
		s.idle = true
		s.pc.SetDeadline(time.Now().Add(s.l.opts.Idle))
		s.mu.Unlock()
		next, ok := s.nextHeader()
		if !ok {
			return
		}
		header = next
	}
}

// nextHeader moves an idle session back to active under the same lock retire
// uses. If retirement won that transition, bytes made readable by the racing
// client are never dispatched from this connection.
func (s *session) nextHeader() (uint32, bool) {
	var h [4]byte
	n, err := io.ReadFull(s.pc, h[:])
	s.mu.Lock()
	s.idle = false
	retiring := s.retiring
	s.mu.Unlock()
	if retiring {
		if n == 0 {
			// Nothing of a next request was read, so the marker tells the
			// client it is safe to repeat on another connection.
			s.pc.SetDeadline(time.Now().Add(DefaultFrameTimeout))
			writeUint32(s.pc, sessionClosing)
		}
		return 0, false
	}
	if n == 0 {
		if os.IsTimeout(err) {
			// A natural idle timeout with no next request retires the session.
			s.pc.SetDeadline(time.Now().Add(DefaultFrameTimeout))
			writeUint32(s.pc, sessionClosing)
		}
		return 0, false
	}
	if err != nil {
		if !os.IsTimeout(err) {
			return 0, false
		}
		// A request that began before a natural idle timeout is completed and
		// served. Explicit retirement was handled above.
		s.pc.SetDeadline(time.Now().Add(s.l.opts.FirstRequest))
		if _, err := io.ReadFull(s.pc, h[n:]); err != nil {
			return 0, false
		}
	}
	s.pc.SetDeadline(time.Time{})
	return binary.BigEndian.Uint32(h[:]), true
}

func writeUint32(w io.Writer, v uint32) error {
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], v)
	_, err := w.Write(b[:])
	return err
}

// sessionCall is one exchange on a session connection, as a Conn.
type sessionCall struct {
	s         *session
	mu        sync.Mutex
	header    [4]byte
	headerAt  int
	remaining uint32
	oneWay    bool
	out       [4]byte
	outAt     int
	outLeft   uint32
	replied   bool
	continued bool
	closed    bool
	broken    bool
	reading   int
	readDone  *sync.Cond
	done      chan struct{}
}

func (c *sessionCall) Bind() (*identity.Binding, error) {
	if c.s.bindErr != nil {
		return nil, c.s.bindErr
	}
	return c.s.binding.Shared(), nil
}

func (c *sessionCall) SetDeadline(t time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return net.ErrClosed
	}
	return c.s.pc.SetDeadline(t)
}

func (c *sessionCall) Read(p []byte) (int, error) {
	c.mu.Lock()
	switch {
	case c.closed:
		c.mu.Unlock()
		return 0, net.ErrClosed
	case c.headerAt < len(c.header):
		n := copy(p, c.header[c.headerAt:])
		c.headerAt += n
		c.mu.Unlock()
		return n, nil
	case c.remaining > 0:
		if uint64(len(p)) > uint64(c.remaining) {
			p = p[:c.remaining]
		}
	case c.replied:
		c.mu.Unlock()
		return 0, io.EOF
	default:
		// The request is consumed and no reply is written: a read here waits
		// for the client to hang up, as on a single-exchange connection.
		p = p[:min(len(p), 1)]
	}
	c.reading++
	c.mu.Unlock()
	n, err := c.s.pc.Read(p)
	c.mu.Lock()
	defer c.mu.Unlock()
	c.reading--
	if c.readDone != nil {
		c.readDone.Broadcast()
	}
	if c.remaining > 0 {
		c.remaining -= uint32(n)
	} else if n > 0 {
		// A byte beyond the request before the reply breaks the session.
		c.broken = true
		return n, nil
	}
	if err != nil && !os.IsTimeout(err) {
		c.broken = true
	}
	return n, err
}

func (c *sessionCall) Write(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return 0, net.ErrClosed
	}
	if c.oneWay {
		c.broken = true
		return 0, ErrUnexpectedResponse
	}
	written := 0
	if c.outAt < len(c.out) {
		n := copy(c.out[c.outAt:], p)
		c.outAt += n
		p = p[n:]
		written += n
		if c.outAt < len(c.out) {
			return written, nil
		}
		length := binary.BigEndian.Uint32(c.out[:])
		if length > lengthMask {
			c.broken = true
			return written, ErrFrameTooLarge
		}
		c.outLeft = length
		next := length | sessionFlag
		if c.s.isRetiring() {
			next = length
		}
		// One write carries the header and whatever body arrived with it.
		body := p[:min(uint64(len(p)), uint64(length))]
		buf := make([]byte, 4+len(body))
		binary.BigEndian.PutUint32(buf, next)
		copy(buf[4:], body)
		if _, err := c.s.pc.Write(buf); err != nil {
			c.broken = true
			return written, err
		}
		c.continued = next&sessionFlag != 0
		c.outLeft -= uint32(len(body))
		written += len(body)
		p = p[len(body):]
	}
	if len(p) > 0 && c.outLeft > 0 {
		chunk := p[:min(uint64(len(p)), uint64(c.outLeft))]
		n, err := c.s.pc.Write(chunk)
		c.outLeft -= uint32(n)
		written += n
		if err != nil {
			c.broken = true
			return written, err
		}
		p = p[n:]
	}
	if c.outLeft == 0 {
		c.replied = true
	}
	if len(p) > 0 {
		c.broken = true
		return written, ErrSessionProtocol
	}
	return written, nil
}

func (c *sessionCall) Close() error {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return nil
	}
	c.closed = true
	if c.reading > 0 {
		// A read waiting for the client to hang up must end before the
		// session reads its next request.
		c.readDone = sync.NewCond(&c.mu)
		c.s.pc.SetReadDeadline(time.Now())
		for c.reading > 0 {
			c.readDone.Wait()
		}
	}
	switch {
	case c.broken:
	case c.headerAt < len(c.header) || c.remaining > 0:
		// Refused before the request was read: the connection ends, as a
		// single-exchange connection does.
		c.broken = true
	case c.oneWay:
		complete := sessionFlag
		if c.s.isRetiring() {
			complete = 0
		}
		if err := writeUint32(c.s.pc, complete); err != nil {
			c.broken = true
		}
		c.continued = complete != 0
	case !c.replied:
		c.broken = true
	}
	c.mu.Unlock()
	close(c.done)
	return nil
}
