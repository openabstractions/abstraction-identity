package identity

import (
	"net"
	"os"
	"time"
)

// BindStartedProcess captures a caller-owned unreaped child on Darwin/cgo.
// Call it after Start and before starting Wait, and serialize it against Wait
// and Release. A process obtained by FindProcess does not establish this
// precondition. Native checks require a live direct child and capture its task
// name right and kernel audit token. No bare PID is accepted as identity.
// Close the returned Binding; it does not wait, signal or own the child's exit.
// Unsupported platforms return ErrUnimplemented without inspecting the process.
func BindStartedProcess(process *os.Process) (*Binding, error) {
	inner, peer, err := bindStartedProcess(process)
	if err != nil {
		return nil, err
	}
	return &Binding{peer: peer, boundAt: time.Now(), inner: &bindingState{inner: inner}}, nil
}

type startedProcessMatcher interface {
	matchStarted(sealedResourceNative, *XPCRequest) (Code, Proof, error)
}

func (b *bindingState) matchStarted(e sealedResourceNative, request *XPCRequest) (Code, Proof, error) {
	b.mu.RLock()
	defer b.mu.RUnlock()
	if b.closed {
		return Code{}, ProofUnmet, net.ErrClosed
	}
	m, ok := b.inner.(startedProcessMatcher)
	if !ok {
		return Code{}, ProofUnmet, ErrNoBinding
	}
	return m.matchStarted(e, request)
}

func (b sharedBinder) matchStarted(e sealedResourceNative, request *XPCRequest) (Code, Proof, error) {
	m, ok := b.binder.(startedProcessMatcher)
	if !ok {
		return Code{}, ProofUnmet, ErrNoBinding
	}
	return m.matchStarted(e, request)
}

// MatchStartedProcess requires a live BindStartedProcess occurrence and a
// platform-trusted exact generation authenticated by this resource evidence.
// It conveys no rights and does not resume or contain application code.
func (e *SealedResourceEvidence) MatchStartedProcess(started *Binding) (Code, Proof, error) {
	return e.matchStarted(started, nil)
}

// MatchStartedXPCRequest requires that actual dictionary's native sender to be
// the still-live started occurrence and the same trusted sealed generation.
// Existing BindXPCRequest captures and proofs remain unchanged.
func (e *SealedResourceEvidence) MatchStartedXPCRequest(started *Binding, request *XPCRequest) (Code, Proof, error) {
	if request == nil {
		return Code{}, ProofUnmet, ErrNoBinding
	}
	return e.matchStarted(started, request)
}

func (e *SealedResourceEvidence) matchStarted(started *Binding, request *XPCRequest) (Code, Proof, error) {
	if e == nil || e.state == nil {
		return Code{}, ProofUnmet, net.ErrClosed
	}
	s := e.state
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.native == nil {
		return Code{}, ProofUnmet, net.ErrClosed
	}
	if started == nil || started.inner == nil {
		return Code{}, ProofUnmet, ErrNoBinding
	}
	m, ok := started.inner.(startedProcessMatcher)
	if !ok {
		return Code{}, ProofUnmet, ErrNoBinding
	}
	return m.matchStarted(s.native, request)
}
