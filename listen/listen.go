package listen

import (
	"bufio"
	"errors"
	"io"
	"strings"
	"sync"

	identity "github.com/openabstractions/abstraction-identity"
)

type Conn interface {
	io.ReadWriteCloser
	Bind() (*identity.Binding, error)
}

type Listener interface {
	Accept() (Conn, error)
	Close() error
}

type Seen struct {
	Bound bool   `json:"bound"`
	Why   string `json:"why,omitempty"`
	User  string `json:"user,omitempty"`
	Path  string `json:"path,omitempty"`
	Code  string `json:"code,omitempty"`
	Notes string `json:"notes,omitempty"`
}

func SeenBy(b *identity.Binding, err error) Seen {
	if err != nil {
		return Seen{Why: err.Error()}
	}
	p := b.Captured()
	return Seen{Bound: true, User: p.User.String(), Path: p.Path.String(), Code: p.Code.String(),
		Notes: strings.Join(p.Notes, "; ")}
}

func (s Seen) String() string {
	if !s.Bound {
		return "who connected is unknown: " + s.Why
	}
	return s.Path + "  " + s.User + "  " + s.Code
}

// Program is the least a service asks of a caller before acting for it. Path
// stops at ProofBound because Windows cannot verify the code a running process
// is executing, and Linux below 6.5 has no answer at all.
var Program = identity.Need{
	User:    identity.ProofKernel,
	Process: identity.ProofKernel,
	Path:    identity.ProofBound,
}

var ErrNoFrame = errors.New("listen: the caller left before saying anything")

type Call struct {
	Conn
	Caller Seen
	Frame  []byte
	sc     *bufio.Scanner
	b      *identity.Binding
	gone   chan struct{}
	drain  sync.Once
	end    sync.Once
}

// Receive is the only way a service gets a frame, and a frame never arrives
// without the caller that sent it: the caller is bound and checked against need
// first, and a caller the kernel cannot identify gets an error naming what was
// missing and no frame at all.
//
// Windows will not identify the client of a pipe nothing has been read from, so
// the bytes arrive before the caller does. They stay bytes until the caller is
// known, and they are never read as a claim about who sent them.
func Receive(c Conn, need identity.Need, maxFrame int) (*Call, error) {
	k := &Call{Conn: c, sc: bufio.NewScanner(c)}
	k.sc.Buffer(make([]byte, maxFrame), maxFrame)
	if !k.sc.Scan() {
		return k, ErrNoFrame
	}
	frame := append([]byte(nil), k.sc.Bytes()...)
	b, err := c.Bind()
	k.Caller = SeenBy(b, err)
	if err != nil {
		return k, err
	}
	k.b = b
	if err := b.Check(need); err != nil {
		return k, err
	}
	k.Frame = frame
	return k, nil
}

// Recheck asks whether the connection still answers for the caller it was
// bound to, for a service that waited between binding and acting.
func (k *Call) Recheck() error {
	_, err := k.b.Peer()
	return err
}

// Gone closes when the caller hangs up.
func (k *Call) Gone() <-chan struct{} {
	k.drain.Do(func() {
		k.gone = make(chan struct{})
		go func() {
			for k.sc.Scan() {
			}
			close(k.gone)
		}()
	})
	return k.gone
}

func (k *Call) Close() error {
	var err error
	k.end.Do(func() {
		if k.b != nil {
			k.b.Close()
		}
		err = k.Conn.Close()
	})
	return err
}
