package listen

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"

	identity "github.com/openabstractions/abstraction-identity"
)

const DefaultMaxFrame uint32 = 1024 * 1024
const DefaultFrameTimeout = 5 * time.Second

var ErrFrameTooLarge = errors.New("listen: frame exceeds limit")
var ErrUnexpectedResponse = errors.New("listen: response bytes on one-way connection")
var ErrFrameDeadline = errors.New("listen: connection cannot enforce deadline")

func frameLimit(n uint32) uint32 {
	if n == 0 {
		return DefaultMaxFrame
	}
	return n
}
func writeFrame(w io.Writer, frame []byte, limit uint32) error {
	if uint64(len(frame)) > uint64(limit) {
		return ErrFrameTooLarge
	}
	var h [4]byte
	binary.BigEndian.PutUint32(h[:], uint32(len(frame)))
	for _, part := range [][]byte{h[:], frame} {
		for len(part) > 0 {
			n, err := w.Write(part)
			if err != nil {
				return err
			}
			if n <= 0 {
				return io.ErrShortWrite
			}
			part = part[n:]
		}
	}
	return nil
}
func readFrame(r io.Reader, limit uint32) ([]byte, error) {
	var h [4]byte
	if _, err := io.ReadFull(r, h[:]); err != nil {
		return nil, err
	}
	return readFrameBody(r, binary.BigEndian.Uint32(h[:]), limit)
}

// WriteFrameTo writes the shared bounded wire frame to an authenticated stream.
// Its owner supplies deadlines, cancellation, authentication and connection lifetime.
func WriteFrameTo(w io.Writer, frame []byte, limit uint32) error {
	return writeFrame(w, frame, frameLimit(limit))
}

// ReadFrameFrom reads one complete bounded frame from an authenticated stream.
// A zero limit selects DefaultMaxFrame. Oversized headers allocate no payload.
func ReadFrameFrom(r io.Reader, limit uint32) ([]byte, error) {
	return readFrame(r, frameLimit(limit))
}
func readFrameBody(r io.Reader, n, limit uint32) ([]byte, error) {
	if n > limit || uint64(n) > uint64(^uint(0)>>1) {
		return nil, ErrFrameTooLarge
	}
	frame := make([]byte, int(n))
	_, err := io.ReadFull(r, frame)
	if err != nil {
		return nil, err
	}
	return frame, nil
}
func waitFrameEOF(r io.Reader) error {
	var b [1]byte
	n, err := r.Read(b[:])
	if n != 0 {
		return ErrUnexpectedResponse
	}
	if errors.Is(err, io.EOF) {
		return nil
	}
	if err == nil {
		return io.ErrNoProgress
	}
	return err
}
func frameContext(ctx context.Context, timeout time.Duration) (context.Context, context.CancelFunc) {
	if timeout == 0 {
		timeout = DefaultFrameTimeout
	}
	return context.WithTimeout(ctx, timeout)
}
func frameError(ctx context.Context, err error) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	// Native I/O can report the configured deadline before the context timer's
	// callback runs. Preserve the same typed waiting outcome in either ordering.
	if os.IsTimeout(err) {
		if deadline, ok := ctx.Deadline(); ok && !time.Now().Before(deadline) {
			return context.DeadlineExceeded
		}
	}
	return err
}

// FrameClient opens a fresh connection per call. Timeout spans all phases.
// Zero-valued Timeout and MaxFrame use the safe defaults.
type FrameClient struct {
	Endpoint string
	Timeout  time.Duration
	MaxFrame uint32
	// Server is independent caller-supplied trust evidence. Nil preserves the
	// legacy unverified-server mode; endpoint selection alone proves no identity.
	Server *ServerExpectation
	// Dialer is an explicitly selected, authenticated stream provider. It must
	// honor ctx through connection and authentication and return an owned stream.
	// Nil uses the local platform dialer. Remote identities belong to their
	// transport; a custom Dialer cannot be combined with local Server evidence.
	Dialer func(context.Context, string) (net.Conn, error)
}

// WithContext adapts generated context-free transport interfaces for one call.
// The adapter retains ctx; create it per operation and keep the FrameClient for
// reuse with fresh contexts. The earlier context/configured deadline wins.
func (c FrameClient) WithContext(ctx context.Context) contextFrameClient {
	return contextFrameClient{client: c, ctx: ctx}
}

type contextFrameClient struct {
	client FrameClient
	ctx    context.Context
}

func (c contextFrameClient) WriteFrame(frame []byte) error {
	if err := c.ctx.Err(); err != nil {
		return err
	}
	return c.client.WriteFrameContext(c.ctx, frame)
}
func (c contextFrameClient) ExchangeFrame(frame []byte) ([]byte, error) {
	if err := c.ctx.Err(); err != nil {
		return nil, err
	}
	return c.client.ExchangeFrameContext(c.ctx, frame)
}

func (c FrameClient) WriteFrame(frame []byte) error {
	return c.WriteFrameContext(context.Background(), frame)
}
func (c FrameClient) ExchangeFrame(frame []byte) ([]byte, error) {
	return c.ExchangeFrameContext(context.Background(), frame)
}
func (c FrameClient) connect(ctx context.Context) (net.Conn, func(), error) {
	if c.Dialer != nil && c.Server != nil {
		return nil, nil, fmt.Errorf("%w: custom transport with local server expectation", ErrServerUntrusted)
	}
	if c.Server != nil {
		if err := c.Server.validate(); err != nil {
			return nil, nil, err
		}
	}
	dial := c.Dialer
	if dial == nil {
		dial = dialFramed
	}
	conn, err := dial(ctx, c.Endpoint)
	if err != nil {
		return nil, nil, err
	}
	connectedAt := time.Now() // successful dial, after any activation/retry wait
	deadline, _ := ctx.Deadline()
	if err = conn.SetDeadline(deadline); err != nil {
		conn.Close()
		return nil, nil, err
	}
	guard := &serverConn{Conn: conn, ctx: ctx}
	stop := context.AfterFunc(ctx, func() { guard.Close() })
	if err := guard.authenticate(c.Server, connectedAt); err != nil {
		stop()
		guard.Close()
		return nil, nil, err
	}
	return guard, func() { stop(); guard.Close() }, nil
}
func (c FrameClient) WriteFrameContext(parent context.Context, frame []byte) error {
	limit := frameLimit(c.MaxFrame)
	if uint64(len(frame)) > uint64(limit) {
		return ErrFrameTooLarge
	}
	ctx, cancel := frameContext(parent, c.Timeout)
	defer cancel()
	conn, close, err := c.connect(ctx)
	if err != nil {
		return frameError(ctx, err)
	}
	defer close()
	if err = writeFrame(conn, frame, limit); err == nil {
		err = waitFrameEOF(conn)
	}
	return frameError(ctx, err)
}
func (c FrameClient) ExchangeFrameContext(parent context.Context, frame []byte) ([]byte, error) {
	limit := frameLimit(c.MaxFrame)
	if uint64(len(frame)) > uint64(limit) {
		return nil, ErrFrameTooLarge
	}
	ctx, cancel := frameContext(parent, c.Timeout)
	defer cancel()
	conn, close, err := c.connect(ctx)
	if err != nil {
		return nil, frameError(ctx, err)
	}
	defer close()
	if err = writeFrame(conn, frame, limit); err != nil {
		return nil, frameError(ctx, err)
	}
	reply, err := readFrame(conn, limit)
	return reply, frameError(ctx, err)
}

// FramedCall owns the connection and binding; only ReceiveFramed constructs it.
type FramedCall struct {
	Frame         []byte
	Caller        Seen
	conn          Conn
	binding       *identity.Binding
	ctx           context.Context
	cancel        context.CancelFunc
	stop          func() bool
	limit         uint32
	mu            sync.Mutex
	closed        bool
	replyOnce     sync.Once
	replyErr      error
	watchOnce     sync.Once
	watchDone     chan struct{}
	watchErr      error
	waitCtx       context.Context
	waitCancel    context.CancelFunc
	watchStopping atomic.Bool
}

// WaitContext ends when the caller closes, sends unexpected trailing bytes,
// or the call's existing deadline/context ends. Use it for observation waits;
// accepted durable work retains its independent execution lifetime.
// Framed calls carry one request per connection. This method and Reply share
// one reader for the final EOF so a waiting handler cannot steal reply drainage.
func (k *FramedCall) WaitContext() context.Context {
	k.watchOnce.Do(func() {
		k.initWait()
		k.watchDone = make(chan struct{})
		go func() {
			k.watchErr = waitFrameEOF(k.conn)
			if !k.watchStopping.Load() || !os.IsTimeout(k.watchErr) {
				k.waitCancel()
			}
			close(k.watchDone)
		}()
	})
	return k.waitCtx
}

func (k *FramedCall) initWait() { k.waitCtx, k.waitCancel = context.WithCancel(k.ctx) }

// End the observation phase before writing the reply. Go's Windows os.File
// shares pipe offset bookkeeping across Read and Write, so a pending EOF read
// must finish before reply I/O starts. Existing deadline cancellation supplies
// the barrier; the original call deadline is restored before the write.
func (k *FramedCall) finishWatching() error {
	k.watchOnce.Do(k.initWait)
	if k.watchDone == nil {
		return nil
	}
	k.watchStopping.Store(true)
	d := k.conn.(interface{ SetDeadline(time.Time) error })
	if err := d.SetDeadline(time.Now()); err != nil {
		k.Close()
		<-k.watchDone
		return err
	}
	<-k.watchDone
	deadline, _ := k.ctx.Deadline()
	if err := d.SetDeadline(deadline); err != nil {
		return err
	}
	if os.IsTimeout(k.watchErr) {
		return k.ctx.Err()
	}
	if k.watchErr == nil {
		return io.ErrClosedPipe
	}
	return k.watchErr
}

func ReceiveFramed(parent context.Context, c Conn, need identity.Need, maxFrame uint32) (*FramedCall, error) {
	deadline, present := parent.Deadline()
	if !present {
		deadline = time.Now().Add(DefaultFrameTimeout)
	}
	ctx, cancel := context.WithDeadline(parent, deadline)
	k := &FramedCall{conn: c, ctx: ctx, cancel: cancel, limit: frameLimit(maxFrame)}
	// Close and binding checks serialize: Unix Conn.Close also releases binding.
	k.mu.Lock()
	k.stop = context.AfterFunc(ctx, func() { k.Close() })
	k.mu.Unlock()
	fail := func(err error) (*FramedCall, error) { result := frameError(ctx, err); k.Close(); return nil, result }
	if err := ctx.Err(); err != nil {
		return fail(err)
	}
	d, ok := c.(interface{ SetDeadline(time.Time) error })
	if !ok {
		return fail(ErrFrameDeadline)
	}
	if err := d.SetDeadline(deadline); err != nil {
		return fail(err)
	}
	var h [4]byte
	if _, err := io.ReadFull(c, h[:]); err != nil {
		return fail(err)
	}
	n := binary.BigEndian.Uint32(h[:])
	if n > k.limit {
		return fail(ErrFrameTooLarge)
	}
	// Windows requires a read before Bind. Check identity before body allocation.
	k.mu.Lock()
	if k.closed {
		k.mu.Unlock()
		return fail(context.Canceled)
	}
	b, err := c.Bind()
	if err == nil {
		k.binding = b
		err = b.Check(need)
	}
	if err == nil {
		k.Caller = SeenBy(b, nil)
	}
	k.mu.Unlock()
	if err != nil {
		return fail(err)
	}
	frame, err := readFrameBody(c, n, k.limit)
	if err != nil {
		return fail(err)
	}
	if err = ctx.Err(); err != nil {
		return fail(err)
	}
	k.Frame = frame
	return k, nil
}

// Peer returns the typed identity after the binding's recheck, serialized with
// Close and context cancellation. Treat the returned snapshot as read-only;
// individual attributes retain their proof levels (Get or AtLeast).
func (k *FramedCall) Peer() (*identity.Peer, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.closed {
		return nil, net.ErrClosed
	}
	if err := k.ctx.Err(); err != nil {
		return nil, err
	}
	return k.binding.Peer()
}

func (k *FramedCall) Recheck() error {
	_, err := k.Peer()
	return err
}

// Reply sends one frame and waits for client EOF so Windows writes are drained.
func (k *FramedCall) Reply(frame []byte) error {
	k.replyOnce.Do(func() {
		err := k.finishWatching()
		defer k.waitCancel()
		if err != nil {
			k.replyErr = frameError(k.ctx, err)
			return
		}
		if err := k.Recheck(); err != nil {
			k.replyErr = err
			return
		}
		k.replyErr = writeFrame(k.conn, frame, k.limit)
		if k.replyErr == nil {
			k.replyErr = waitFrameEOF(k.conn)
		}
		k.replyErr = frameError(k.ctx, k.replyErr)
	})
	return k.replyErr
}
func (k *FramedCall) Close() error {
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.closed {
		return nil
	}
	k.closed = true
	if k.stop != nil {
		k.stop()
	}
	k.cancel()
	err := k.conn.Close()
	if k.binding != nil {
		k.binding.Close()
	}
	return err
}
