package listen

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"syscall"
	"testing"
	"time"
)

type deliveryConn struct {
	net.Conn
	response io.Reader
	read     func([]byte) (int, error)
	write    func([]byte) (int, error)
	deadline error
	writes   int
}

func (c *deliveryConn) Read(p []byte) (int, error) {
	if c.read != nil {
		return c.read(p)
	}
	return c.response.Read(p)
}
func (c *deliveryConn) Write(p []byte) (int, error) {
	c.writes++
	if c.write != nil {
		return c.write(p)
	}
	return len(p), nil
}
func (c *deliveryConn) SetDeadline(time.Time) error { return c.deadline }
func (c *deliveryConn) Close() error                { return nil }

func TestCustomRequestDeliveryBeforeWrite(t *testing.T) {
	for _, oneWay := range []bool{false, true} {
		for _, phase := range []string{"dial", "deadline", "canceled", "oversize"} {
			t.Run(phase+map[bool]string{true: "/write", false: "/exchange"}[oneWay], func(t *testing.T) {
				cause := errors.New("fixture failure")
				conn := &deliveryConn{response: bytes.NewReader(nil)}
				client := FrameClient{Dialer: func(context.Context, string) (net.Conn, error) {
					if phase == "dial" {
						return nil, cause
					}
					return conn, nil
				}}
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				if phase == "deadline" {
					conn.deadline = cause
				}
				if phase == "canceled" {
					cancel()
					cause = context.Canceled
				}
				if phase == "oversize" {
					client.MaxFrame = 1
					cause = ErrFrameTooLarge
				}
				var err error
				if oneWay {
					err = client.WithContext(ctx).WriteFrame([]byte("effect"))
				} else {
					_, err = client.WithContext(ctx).ExchangeFrame([]byte("effect"))
				}
				if !errors.Is(err, ErrRequestNotSent) || errors.Is(err, ErrRequestUncertain) || !errors.Is(err, cause) || conn.writes != 0 {
					t.Fatalf("error=%v writes=%d", err, conn.writes)
				}
			})
		}
	}
}

func TestCustomRequestDeliveryAfterWrite(t *testing.T) {
	for _, oneWay := range []bool{false, true} {
		for _, count := range []int{0, 2, 8} {
			t.Run(map[bool]string{true: "write", false: "exchange"}[oneWay]+string(rune('0'+count)), func(t *testing.T) {
				conn := &deliveryConn{response: bytes.NewReader(nil), write: func([]byte) (int, error) { return count, syscall.EPIPE }}
				dials := 0
				client := FrameClient{Dialer: func(context.Context, string) (net.Conn, error) { dials++; return conn, nil }}
				var err error
				if oneWay {
					err = client.WriteFrame([]byte("effect"))
				} else {
					_, err = client.ExchangeFrame([]byte("effect"))
				}
				if !errors.Is(err, ErrRequestUncertain) || errors.Is(err, ErrRequestNotSent) || !errors.Is(err, syscall.EPIPE) || dials != 1 || conn.writes != 1 {
					t.Fatalf("error=%v dials=%d writes=%d", err, dials, conn.writes)
				}
			})
		}
	}
}

func TestCustomRequestLostOrMalformedReply(t *testing.T) {
	for _, tc := range []struct {
		name  string
		reply []byte
		cause error
	}{
		{"lost", nil, io.EOF}, {"partial header", []byte{0, 0}, io.ErrUnexpectedEOF},
		{"partial body", []byte{0, 0, 0, 2, 1}, io.ErrUnexpectedEOF},
		{"oversize", []byte{0x7f, 0xff, 0xff, 0xff}, ErrFrameTooLarge},
		{"malformed refusal", []byte{0xff, 0xff, 0xff, 0xfe, 0xff, 0xff}, ErrProofRefusalProtocol},
	} {
		t.Run(tc.name, func(t *testing.T) {
			conn := &deliveryConn{response: bytes.NewReader(tc.reply)}
			client := FrameClient{Dialer: func(context.Context, string) (net.Conn, error) { return conn, nil }}
			_, err := client.ExchangeFrame([]byte("effect"))
			if !errors.Is(err, ErrRequestUncertain) || !errors.Is(err, tc.cause) || conn.writes != 1 {
				t.Fatalf("error=%v writes=%d", err, conn.writes)
			}
		})
	}
}

func TestCustomRequestCanceledAfterWriteKeepsUncertaintyAndCause(t *testing.T) {
	for _, phase := range []string{"write", "reply"} {
		for _, deadline := range []bool{false, true} {
			t.Run(phase+"/"+map[bool]string{false: "cancel", true: "deadline"}[deadline], func(t *testing.T) {
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				want := context.Canceled
				if deadline {
					ctx, cancel = context.WithTimeout(context.Background(), 10*time.Millisecond)
					defer cancel()
					want = context.DeadlineExceeded
				}
				stop := func([]byte) (int, error) {
					if deadline {
						<-ctx.Done()
					} else {
						cancel()
					}
					return 0, net.ErrClosed
				}
				conn := &deliveryConn{response: bytes.NewReader(nil)}
				if phase == "write" {
					conn.write = stop
				} else {
					conn.read = stop
				}
				client := FrameClient{Dialer: func(context.Context, string) (net.Conn, error) { return conn, nil }}
				_, err := client.ExchangeFrameContext(ctx, []byte("effect"))
				if !errors.Is(err, ErrRequestUncertain) || !errors.Is(err, want) || phase == "write" && !errors.Is(err, net.ErrClosed) {
					t.Fatalf("error=%v", err)
				}
			})
		}
	}
}

func TestCustomRequestProofRefusalIsAuthoritative(t *testing.T) {
	conn := &deliveryConn{response: bytes.NewReader([]byte{0xff, 0xff, 0xff, 0xfe, 0, 0})}
	client := FrameClient{Dialer: func(context.Context, string) (net.Conn, error) { return conn, nil }}
	_, err := client.ExchangeFrame([]byte("effect"))
	if !errors.Is(err, ErrCallerProofUnmet) || errors.Is(err, ErrRequestUncertain) || errors.Is(err, ErrRequestNotSent) {
		t.Fatalf("error=%v", err)
	}
}
