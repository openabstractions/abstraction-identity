package listen

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"os"
	"strconv"
	"sync"
	"time"
)

// The client half of sessions (FRAMING.md "Sessions"): a bounded pool of
// verified connections per endpoint and server expectation.
const (
	// poolIdle is how long a connection may wait in the pool. It is shorter
	// than DefaultSessionIdle so a server rarely retires one a client picks.
	poolIdle = 10 * time.Second
	// poolPerEndpoint bounds idle connections kept for one endpoint and
	// expectation; a concurrent burst beyond it closes its extra connections.
	poolPerEndpoint = 4
	// singleMemory is how long an endpoint that closed a session request
	// before answering is served one connection per call.
	singleMemory = 30 * time.Second
	// sessionAttempts bounds retries after a server's closing marker.
	sessionAttempts = 3
)

type framePool struct {
	mu     sync.Mutex
	idle   map[string][]pooled
	single map[string]time.Time
}

type pooled struct {
	conn  *serverConn
	since time.Time
}

var frames = &framePool{idle: map[string][]pooled{}, single: map[string]time.Time{}}

func (c FrameClient) poolKey() string {
	key := c.Endpoint
	if s := c.Server; s != nil {
		key += "\x00" + s.Principal.Kind + "\x00" + s.Principal.SID + "\x00" + strconv.Itoa(s.Principal.UID) + "\x00" + s.Program
		if s.Process != nil {
			key += "\x00" + strconv.Itoa(s.Process.PID) + "\x00" + s.Process.StartTime.String()
		}
	}
	return key
}

func (p *framePool) isSingle(key string, now time.Time) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	until, ok := p.single[key]
	if ok && now.After(until) {
		delete(p.single, key)
		return false
	}
	return ok
}

func (p *framePool) markSingle(key string, now time.Time) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.single[key] = now.Add(singleMemory)
}

// take returns the most recently used intact idle connection, closing any
// that waited too long or that the server has ended.
func (p *framePool) take(key string, now time.Time) *serverConn {
	for {
		p.mu.Lock()
		list := p.idle[key]
		if len(list) == 0 {
			p.mu.Unlock()
			return nil
		}
		last := list[len(list)-1]
		p.idle[key] = list[:len(list)-1]
		p.mu.Unlock()
		if now.Sub(last.since) < poolIdle && idleIntact(last.conn.Conn) {
			return last.conn
		}
		last.conn.Close()
	}
}

func (p *framePool) put(key string, conn *serverConn, now time.Time) {
	p.mu.Lock()
	list := p.idle[key]
	var expired []pooled
	for len(list) > 0 && now.Sub(list[0].since) >= poolIdle {
		expired = append(expired, list[0])
		list = list[1:]
	}
	if len(list) >= poolPerEndpoint {
		p.idle[key] = list
		p.mu.Unlock()
		conn.Close()
	} else {
		p.idle[key] = append(list, pooled{conn: conn, since: now})
		p.mu.Unlock()
	}
	for _, e := range expired {
		e.conn.Close()
	}
}

func readUint32(r io.Reader) (uint32, int, error) {
	var b [4]byte
	n, err := io.ReadFull(r, b[:])
	if err != nil {
		return 0, n, err
	}
	return binary.BigEndian.Uint32(b[:]), n, nil
}

// errNoSession means the server closed a new connection before answering a
// session request: nothing was sent that it could act on.
var errNoSession = errors.New("listen: the endpoint does not serve sessions")

// sessionCall makes one exchange (or one one-way write) through the pool.
func (c FrameClient) sessionCall(ctx context.Context, frame []byte, limit uint32, oneWay bool) ([]byte, error) {
	key := c.poolKey()
	flags := sessionFlag | uint32(len(frame))
	if oneWay {
		flags |= oneWayFlag
	}
	for attempt := 0; attempt < sessionAttempts; attempt++ {
		conn := frames.take(key, time.Now())
		fresh := conn == nil
		if fresh {
			var err error
			if conn, err = c.dialSession(ctx); err != nil {
				return nil, err
			}
		}
		stop, err := conn.use(ctx)
		if err != nil {
			conn.Close()
			return nil, err
		}
		keep := false
		finish := func() {
			if stop() && keep && ctx.Err() == nil {
				frames.put(key, conn, time.Now())
				return
			}
			conn.Close()
		}
		if fresh {
			if err := writeUint32(conn, flags); err != nil {
				finish()
				return nil, err
			}
			ack, n, err := readUint32(conn)
			switch {
			case err != nil && n == 0 && ctx.Err() == nil && !os.IsTimeout(err):
				finish()
				return nil, errNoSession
			case err != nil:
				finish()
				return nil, err
			case ack == sessionClosing:
				finish()
				continue
			case ack == sessionDecline, ack == sessionUnsupported:
				if ack == sessionUnsupported {
					frames.markSingle(key, time.Now())
				}
				reply, err := singleOnSession(conn, frame, limit, oneWay)
				finish()
				return reply, err
			case ack != sessionAccept:
				finish()
				return nil, ErrSessionProtocol
			}
			if err := writeAll(conn, frame); err != nil {
				finish()
				return nil, err
			}
		} else if err := writeHeaded(conn, flags, frame); err != nil {
			// A pooled connection that fails to take a request was ended
			// by the server; an incomplete request is never dispatched.
			finish()
			continue
		}
		header, _, err := readUint32(conn)
		if err != nil {
			finish()
			return nil, err
		}
		if header == sessionClosing {
			// The server retired the session without reading this request.
			finish()
			continue
		}
		if header&oneWayFlag != 0 {
			finish()
			return nil, ErrSessionProtocol
		}
		length := header & lengthMask
		if oneWay {
			if length != 0 {
				finish()
				return nil, ErrUnexpectedResponse
			}
			keep = header&sessionFlag != 0
			finish()
			return nil, nil
		}
		reply, err := readFrameBody(conn, length, limit)
		keep = err == nil && header&sessionFlag != 0
		finish()
		return reply, err
	}
	return nil, ErrSessionProtocol
}

// singleOnSession finishes a declined session request as one exchange.
func singleOnSession(conn *serverConn, frame []byte, limit uint32, oneWay bool) ([]byte, error) {
	if err := writeAll(conn, frame); err != nil {
		return nil, err
	}
	if oneWay {
		return nil, waitFrameEOF(conn)
	}
	return readFrame(conn, limit)
}

func writeAll(w io.Writer, b []byte) error {
	for len(b) > 0 {
		n, err := w.Write(b)
		if err != nil {
			return err
		}
		if n <= 0 {
			return io.ErrShortWrite
		}
		b = b[n:]
	}
	return nil
}

// dialSession connects and authenticates one connection for the pool. It is
// bound to no call; use binds it to each.
func (c FrameClient) dialSession(ctx context.Context) (*serverConn, error) {
	if c.Server != nil {
		if err := c.Server.validate(); err != nil {
			return nil, err
		}
	}
	conn, err := dialFramed(ctx, c.Endpoint)
	if err != nil {
		return nil, err
	}
	connectedAt := time.Now()
	deadline, _ := ctx.Deadline()
	if err := conn.SetDeadline(deadline); err != nil {
		conn.Close()
		return nil, err
	}
	guard := &serverConn{Conn: conn, ctx: ctx}
	stop := context.AfterFunc(ctx, func() { guard.Close() })
	err = guard.authenticate(c.Server, connectedAt)
	if !stop() || err != nil {
		guard.Close()
		if err == nil {
			err = ctx.Err()
		}
		return nil, err
	}
	return guard, nil
}
