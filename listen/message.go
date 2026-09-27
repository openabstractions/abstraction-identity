package listen

import (
	"context"
	"errors"

	identity "github.com/openabstractions/abstraction-identity"
)

var errMessageLifetime = errors.New("listen: message transport supplied no request lifetime")

// receivedMessage is one complete request from a message-oriented transport.
// The transport derives binding from this exact message and enforces limit
// before allocating or copying its payload. done closes when the sender or
// request lifetime ends. reply answers this request exactly once and must stop
// when its context ends or Close interrupts the transport; FramedCall supplies
// the exactly-once guard and applies the shared reply limit.
type receivedMessage struct {
	frame   []byte
	binding *identity.Binding
	done    <-chan struct{}
	reply   func(context.Context, []byte) error
}

// messageReceiver is the request-scoped alternative to Conn's byte stream and
// connection-scoped Bind. A returned binding transfers to ReceiveFramed even
// when receiveMessage also returns an error. A platform adapter implements it on the Conn returned
// by Listener.Accept. ReceiveFramed keeps the resulting binding with this one
// FramedCall and never routes it through Sessions.
type messageReceiver interface {
	receiveMessage(context.Context, uint32) (receivedMessage, error)
}
