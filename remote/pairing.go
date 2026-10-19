package remote

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/openabstractions/abstraction-identity/listen"
)

// PairingVersion is the sole supported ceremony major, including invitation codes.
const PairingVersion byte = 2
const pairingProtocol = "oa-pair/2"

// PairingProposalLimit bounds each opaque receiving proposal. Interpretation
// and exact-effect authorization belong to the runtime and Rights owners.
const PairingProposalLimit = 2048
const pairingChunkSize = 448
const pairingFrameLimit = 512

// ErrPairing refuses an incomplete or invalid pairing ceremony.
var ErrPairing = errors.New("remote: pairing refused")

// ErrPairingUncertain means local Confirm returned Yes. The peer may have
// received that irreversible consent; this error never asserts reciprocal No.
var ErrPairingUncertain = errors.New("remote: pairing outcome uncertain after local consent")

// PairKeys identifies the actual TLS candidate keys and local I/R role (1/2).
type PairKeys struct {
	LocalKey, PeerKey [32]byte
	Role              byte
}

// PairView is the exact frozen agreement published to the local person.
// Keys are SHA256 leaf SPKI hashes. Expires is the single ceremony deadline.
// Check compares the transcript; proposal meaning belongs to the runtime.
type PairView struct {
	Role                                 byte
	InitiatorProposal, ResponderProposal []byte
	Check                                string
	Transcript                           [32]byte
	LocalKey, PeerKey                    [32]byte
	Expires                              time.Time
}

// PairingCallbacks belong to the runtime's person-only presenter. Show returns
// after publication. Confirm is called after both publication acknowledgments;
// true is irreversible for this attempt. The runtime must persist its own native
// answer/offer/transcript correlation before true. Both callbacks must honor ctx:
// a callback that never returns remains an uncompleted owned operation.
type PairingCallbacks struct {
	// Prepare freezes the local receiving proposal before nonce commitment.
	// Validate interprets both frozen proposals before publication. Every callback
	// receives its own copies; mutating them cannot change this ceremony.
	Prepare  func(context.Context, PairKeys) ([]byte, error)
	Validate func(context.Context, PairView) error
	Show     func(context.Context, PairView) error
	Confirm  func(context.Context, PairView) (bool, error)
}

// PairCandidate is consent evidence from one completed transport invocation.
// It grants no authority and proves no durable store commit. Public fields are
// data, not an attestation: activation requires the runtime's own native answer
// and offer correlation plus its conditional store/rights reconciliation.
type PairCandidate struct {
	View        PairView
	Certificate *x509.Certificate
}

// PairInitiator owns raw and performs one pairing-only TLS1.3 ceremony. secret
// is a nonzero one-time random32-byte offer supplied by the runtime. It must
// never be placed in argv, logs or ordinary service frames. No retry occurs.
func PairInitiator(ctx context.Context, raw net.Conn, local tls.Certificate, secret [32]byte, callbacks PairingCallbacks) (PairCandidate, error) {
	return pair(ctx, raw, local, secret, callbacks, 1)
}

// PairResponder owns raw for one already-consumed offer attempt. The runtime
// must consume its displayed offer before accepting this call, including failed
// handshakes. This helper neither listens nor manages offers, pins or rules.
func PairResponder(ctx context.Context, raw net.Conn, local tls.Certificate, secret [32]byte, callbacks PairingCallbacks) (PairCandidate, error) {
	return pair(ctx, raw, local, secret, callbacks, 2)
}

type pairStream struct {
	conn       *tls.Conn
	role       byte
	transcript [32]byte
	secret     [32]byte
}

func pair(parent context.Context, raw net.Conn, local tls.Certificate, secret [32]byte, callbacks PairingCallbacks, role byte) (candidate PairCandidate, result error) {
	ctx, cancel := context.WithTimeout(parent, 120*time.Second)
	defer cancel()
	if raw == nil {
		return candidate, ErrPairing
	}
	defer raw.Close()
	closed := make(chan struct{})
	stop := context.AfterFunc(ctx, func() { raw.Close(); close(closed) })
	defer func() {
		if !stop() {
			<-closed
		}
	}()
	yes := false
	defer func() {
		if result != nil {
			candidate = PairCandidate{}
			if yes {
				result = fmt.Errorf("%w: %w", ErrPairingUncertain, result)
			} else {
				result = fmt.Errorf("%w: %w", ErrPairing, result)
			}
		}
	}()
	if secret == ([32]byte{}) || callbacks.Prepare == nil || callbacks.Validate == nil || callbacks.Show == nil || callbacks.Confirm == nil || len(local.Certificate) != 1 || local.PrivateKey == nil {
		return candidate, ErrPairing
	}
	leaf, err := x509.ParseCertificate(local.Certificate[0])
	if err != nil {
		return candidate, ErrPairing
	}
	localKey := sha256.Sum256(leaf.RawSubjectPublicKeyInfo)
	config := &tls.Config{Certificates: []tls.Certificate{local}, MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13, NextProtos: []string{pairingProtocol}, SessionTicketsDisabled: true}
	// Candidate keys have no prior pin. This exception is confined to this
	// pairing-only config; TLS still proves possession of each presented key.
	if role == 1 {
		config.InsecureSkipVerify = true
	} else {
		config.ClientAuth = tls.RequireAnyClientCert
	}
	config.VerifyConnection = func(s tls.ConnectionState) error {
		if s.Version != tls.VersionTLS13 || s.DidResume || s.NegotiatedProtocol != pairingProtocol || len(s.PeerCertificates) != 1 {
			return ErrPairing
		}
		if sha256.Sum256(s.PeerCertificates[0].RawSubjectPublicKeyInfo) == localKey {
			return ErrPairing
		}
		return nil
	}
	var conn *tls.Conn
	if role == 1 {
		conn = tls.Client(raw, config)
	} else {
		conn = tls.Server(raw, config)
	}
	handshake, finish := context.WithTimeout(ctx, 5*time.Second)
	deadline, _ := handshake.Deadline()
	if err = raw.SetDeadline(deadline); err == nil {
		err = conn.HandshakeContext(handshake)
	}
	finish()
	if err != nil {
		return candidate, err
	}
	deadline, _ = ctx.Deadline()
	if err = raw.SetDeadline(deadline); err != nil {
		return candidate, err
	}
	state := conn.ConnectionState()
	peerCert := state.PeerCertificates[0]
	peerKey := sha256.Sum256(peerCert.RawSubjectPublicKeyInfo)
	var keys [64]byte
	if role == 1 {
		copy(keys[:32], localKey[:])
		copy(keys[32:], peerKey[:])
	} else {
		copy(keys[:32], peerKey[:])
		copy(keys[32:], localKey[:])
	}
	proposal, err := callbacks.Prepare(ctx, PairKeys{LocalKey: localKey, PeerKey: peerKey, Role: role})
	if err != nil {
		return candidate, err
	}
	if err = ctx.Err(); err != nil {
		return candidate, err
	}
	if len(proposal) > PairingProposalLimit {
		return candidate, ErrPairing
	}
	proposal = bytes.Clone(proposal)
	var nonce [32]byte
	if _, err = rand.Read(nonce[:]); err != nil {
		return candidate, err
	}
	descriptor := pairDescriptor(proposal)
	commit := pairCommit(role, keys, nonce, descriptor)
	p := pairStream{conn: conn, role: role, secret: secret}
	otherCommit, err := p.exchange(1, commit[:], 32)
	if err != nil {
		return candidate, err
	}
	reveal := append(bytes.Clone(nonce[:]), descriptor[:]...)
	otherReveal, err := p.exchange(2, reveal, 68)
	if err != nil {
		return candidate, err
	}
	var otherNonce [32]byte
	copy(otherNonce[:], otherReveal[:32])
	var otherDescriptor [36]byte
	copy(otherDescriptor[:], otherReveal[32:])
	if binary.BigEndian.Uint32(otherDescriptor[:4]) > PairingProposalLimit {
		return candidate, ErrPairing
	}
	expected := pairCommit(3-role, keys, otherNonce, otherDescriptor)
	if !hmac.Equal(otherCommit, expected[:]) {
		return candidate, ErrPairing
	}
	otherProposal, err := p.proposals(proposal, int(binary.BigEndian.Uint32(otherDescriptor[:4])))
	if err != nil {
		return candidate, err
	}
	if pairDescriptor(otherProposal) != otherDescriptor {
		return candidate, ErrPairing
	}
	var proposals [2][]byte
	proposals[role-1], proposals[2-role] = proposal, otherProposal
	exporter, err := state.ExportKeyingMaterial("EXPORTER-Channel-Binding", []byte{}, 32)
	if err != nil {
		return candidate, err
	}
	h := sha256.New()
	h.Write([]byte("OA-Pair/2/transcript"))
	h.Write([]byte{PairingVersion})
	h.Write(keys[:])
	if role == 1 {
		h.Write(commit[:])
		h.Write(otherCommit)
		h.Write(nonce[:])
		h.Write(otherNonce[:])
	} else {
		h.Write(otherCommit)
		h.Write(commit[:])
		h.Write(otherNonce[:])
		h.Write(nonce[:])
	}
	h.Write(exporter)
	for _, proposal := range proposals {
		var size [4]byte
		binary.BigEndian.PutUint32(size[:], uint32(len(proposal)))
		h.Write(size[:])
		h.Write(proposal)
	}
	copy(p.transcript[:], h.Sum(nil))
	if err = p.authenticate(4, "proof", nil); err != nil {
		return candidate, err
	}
	check, err := pairCheck(p.transcript)
	if err != nil {
		return candidate, err
	}
	view := PairView{Role: role, InitiatorProposal: proposals[0], ResponderProposal: proposals[1], Check: check, Transcript: p.transcript, LocalKey: localKey, PeerKey: peerKey, Expires: deadline}
	if err = ctx.Err(); err != nil {
		return candidate, err
	}
	if err = callbacks.Validate(ctx, clonePairView(view)); err != nil {
		return candidate, err
	}
	if err = ctx.Err(); err != nil {
		return candidate, err
	}
	if err = callbacks.Show(ctx, clonePairView(view)); err != nil {
		return candidate, err
	}
	if err = ctx.Err(); err != nil {
		return candidate, err
	}
	if err = p.authenticate(5, "displayed", nil); err != nil {
		return candidate, err
	}
	if err = ctx.Err(); err != nil {
		return candidate, err
	}
	accept, err := callbacks.Confirm(ctx, clonePairView(view))
	// A true answer is irreversible even if its caller returns late or also
	// reports an error. Never relabel it No after the peer might receive Yes.
	yes = accept
	if err != nil {
		return candidate, err
	}
	if err = ctx.Err(); err != nil {
		return candidate, err
	}
	decision := byte(0)
	if accept {
		decision = 1
	}
	if err = p.authenticate(6, "decision", []byte{decision}); err != nil {
		return candidate, err
	}
	if !accept {
		return candidate, ErrPairing
	}
	if err = ctx.Err(); err != nil {
		return candidate, err
	}
	return PairCandidate{View: clonePairView(view), Certificate: peerCert}, nil
}

func pairCommit(role byte, keys [64]byte, nonce [32]byte, descriptor [36]byte) [32]byte {
	h := sha256.New()
	h.Write([]byte("OA-Pair/2/commit"))
	h.Write([]byte{role, PairingVersion})
	h.Write(keys[:])
	h.Write(nonce[:])
	h.Write(descriptor[:])
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

func clonePairView(v PairView) PairView {
	v.InitiatorProposal = bytes.Clone(v.InitiatorProposal)
	v.ResponderProposal = bytes.Clone(v.ResponderProposal)
	return v
}

func pairDescriptor(proposal []byte) (d [36]byte) {
	binary.BigEndian.PutUint32(d[:4], uint32(len(proposal)))
	sum := sha256.Sum256(proposal)
	copy(d[4:], sum[:])
	return
}

// proposals transfers a complete I proposal then a complete R proposal. The
// revealed, precommitted lengths bound allocation and exact chunk counts.
func (p *pairStream) proposals(local []byte, otherSize int) ([]byte, error) {
	send := func() error {
		for offset, index := 0, 0; offset < len(local); index++ {
			n := min(pairingChunkSize, len(local)-offset)
			payload := []byte{byte(index), byte((len(local) + pairingChunkSize - 1) / pairingChunkSize)}
			payload = binary.BigEndian.AppendUint16(payload, uint16(n))
			payload = append(payload, local[offset:offset+n]...)
			frame := []byte{3, PairingVersion, p.role}
			frame = append(frame, p.transcript[:]...)
			frame = append(frame, payload...)
			if err := listen.WriteFrameTo(p.conn, frame, pairingFrameLimit); err != nil {
				return err
			}
			offset += n
		}
		return nil
	}
	receive := func() ([]byte, error) {
		out := make([]byte, 0, otherSize)
		for index := 0; len(out) < otherSize; index++ {
			frame, err := listen.ReadFrameFrom(p.conn, pairingFrameLimit)
			if err != nil {
				return nil, err
			}
			n := min(pairingChunkSize, otherSize-len(out))
			if len(frame) != 39+n || frame[0] != 3 || frame[1] != PairingVersion || frame[2] != 3-p.role ||
				!bytes.Equal(frame[3:35], p.transcript[:]) || frame[35] != byte(index) ||
				frame[36] != byte((otherSize+pairingChunkSize-1)/pairingChunkSize) || int(binary.BigEndian.Uint16(frame[37:39])) != n {
				return nil, ErrPairing
			}
			out = append(out, frame[39:]...)
		}
		return out, nil
	}
	if p.role == 1 {
		if err := send(); err != nil {
			return nil, err
		}
		return receive()
	}
	other, err := receive()
	if err != nil {
		return nil, err
	}
	if err = send(); err != nil {
		return nil, err
	}
	return other, nil
}

// exchange always writes I then R, including on an unbuffered TLS stream.
func (p *pairStream) exchange(stage byte, payload []byte, size int) ([]byte, error) {
	write := func() error {
		frame := []byte{stage, PairingVersion, p.role}
		frame = append(frame, p.transcript[:]...)
		frame = append(frame, payload...)
		return listen.WriteFrameTo(p.conn, frame, pairingFrameLimit)
	}
	read := func() ([]byte, error) {
		frame, err := listen.ReadFrameFrom(p.conn, pairingFrameLimit)
		if err != nil {
			return nil, err
		}
		if len(frame) != 35+size || frame[0] != stage || frame[1] != PairingVersion || frame[2] != 3-p.role || !bytes.Equal(frame[3:35], p.transcript[:]) {
			return nil, ErrPairing
		}
		return frame[35:], nil
	}
	if p.role == 1 {
		if err := write(); err != nil {
			return nil, err
		}
		return read()
	}
	other, err := read()
	if err != nil {
		return nil, err
	}
	if err = write(); err != nil {
		return nil, err
	}
	return other, nil
}

func (p *pairStream) mac(domain string, role byte, data []byte) []byte {
	h := hmac.New(sha256.New, p.secret[:])
	h.Write([]byte("OA-Pair/2/" + domain))
	h.Write([]byte{PairingVersion, role})
	h.Write(p.transcript[:])
	h.Write(data)
	return h.Sum(nil)
}

func (p *pairStream) authenticate(stage byte, domain string, decision []byte) error {
	payload := append(append([]byte{}, decision...), p.mac(domain, p.role, decision)...)
	other, err := p.exchange(stage, payload, len(payload))
	if err != nil {
		return err
	}
	var data []byte
	if len(decision) != 0 {
		data = other[:1]
		if data[0] > 1 {
			return ErrPairing
		}
		other = other[1:]
	}
	if !hmac.Equal(other, p.mac(domain, 3-p.role, data)) {
		return ErrPairing
	}
	if len(data) != 0 && data[0] != 1 {
		return ErrPairing
	}
	return nil
}

func pairCheck(transcript [32]byte) (string, error) {
	for counter := uint32(0); counter < 16; counter++ {
		h := sha256.New()
		h.Write([]byte("OA-Pair/2/check"))
		h.Write(transcript[:])
		var b [4]byte
		binary.BigEndian.PutUint32(b[:], counter)
		h.Write(b[:])
		sum := h.Sum(nil)
		for i := 0; i < len(sum); i += 4 {
			n := binary.BigEndian.Uint32(sum[i : i+4])
			if n < 4294000000 {
				return fmt.Sprintf("%06d", n%1000000), nil
			}
		}
	}
	return "", ErrPairing
}
