package listen

import (
	"net"

	identity "github.com/openabstractions/abstraction-identity"
)

// MatchStartedProcess checks this actual native request against a live started
// occurrence and its platform-trusted sealed-resource generation. It exposes no
// raw request, changes no Caller proof, and refuses transports without native
// message evidence. Policy also keeps its account/session and channel bindings.
func (k *FramedCall) MatchStartedProcess(started *identity.Binding, evidence *identity.SealedResourceEvidence) (identity.Code, identity.Proof, error) {
	if k == nil {
		return identity.Code{}, identity.ProofUnmet, net.ErrClosed
	}
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.closed {
		return identity.Code{}, identity.ProofUnmet, net.ErrClosed
	}
	if k.ctx == nil || k.message == nil || k.message.matchStarted == nil {
		return identity.Code{}, identity.ProofUnmet, identity.ErrNoBinding
	}
	if err := k.ctx.Err(); err != nil {
		return identity.Code{}, identity.ProofUnmet, err
	}
	select {
	case <-k.message.done:
		return identity.Code{}, identity.ProofUnmet, net.ErrClosed
	default:
	}
	code, proof, err := k.message.matchStarted(started, evidence)
	if err != nil {
		return identity.Code{}, identity.ProofUnmet, err
	}
	if err = k.ctx.Err(); err != nil {
		return identity.Code{}, identity.ProofUnmet, err
	}
	select {
	case <-k.message.done:
		return identity.Code{}, identity.ProofUnmet, net.ErrClosed
	default:
	}
	return code, proof, nil
}
