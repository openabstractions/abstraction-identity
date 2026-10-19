package remote

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/openabstractions/abstraction-identity/listen"
)

type pairResult struct {
	candidate PairCandidate
	err       error
}

func pairSecret(t *testing.T) (secret [32]byte) {
	t.Helper()
	if _, err := rand.Read(secret[:]); err != nil {
		t.Fatal(err)
	}
	return
}
func pairCallbacks() PairingCallbacks {
	return PairingCallbacks{Prepare: func(context.Context, PairKeys) ([]byte, error) { return nil, nil }, Validate: func(context.Context, PairView) error { return nil }, Show: func(context.Context, PairView) error { return nil }, Confirm: func(context.Context, PairView) (bool, error) { return true, nil }}
}
func pairRun(t *testing.T, ctx context.Context, a, b tls.Certificate, secret [32]byte, ca, cb PairingCallbacks) (pairResult, pairResult) {
	t.Helper()
	left, right := net.Pipe()
	out := make(chan pairResult, 1)
	go func() { c, e := PairResponder(ctx, right, b, secret, cb); out <- pairResult{c, e} }()
	c, e := PairInitiator(ctx, left, a, secret, ca)
	other := <-out
	return pairResult{c, e}, other
}

func TestPairingRealTLSDisplayBarrier(t *testing.T) {
	s, c := credentials(t)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	var shown atomic.Int32
	callbacks := func() PairingCallbacks {
		return PairingCallbacks{Prepare: func(context.Context, PairKeys) ([]byte, error) { return nil, nil }, Validate: func(context.Context, PairView) error { return nil }, Show: func(_ context.Context, v PairView) error {
			if len(v.Check) != 6 {
				return errors.New("check width")
			}
			shown.Add(1)
			return nil
		}, Confirm: func(context.Context, PairView) (bool, error) {
			if shown.Load() != 2 {
				return false, errors.New("person asked before both displays")
			}
			return true, nil
		}}
	}
	a, b := pairRun(t, ctx, c.Certificates[0], s.Certificates[0], pairSecret(t), callbacks(), callbacks())
	if a.err != nil || b.err != nil {
		t.Fatalf("%v / %v", a.err, b.err)
	}
	if a.candidate.View.Transcript != b.candidate.View.Transcript || a.candidate.View.Check != b.candidate.View.Check || a.candidate.View.LocalKey != b.candidate.View.PeerKey || a.candidate.Certificate == nil {
		t.Fatal("candidate binding")
	}
}

func TestPairingNoLateAndEqualKey(t *testing.T) {
	for _, mode := range []string{"initiator-no", "responder-no", "late-confirm", "show-failure", "equal-key", "zero-secret"} {
		t.Run(mode, func(t *testing.T) {
			s, c := credentials(t)
			a, b := c.Certificates[0], s.Certificates[0]
			secret := pairSecret(t)
			ca, cb := pairCallbacks(), pairCallbacks()
			budget := 2 * time.Second
			if mode == "late-confirm" {
				budget = 80 * time.Millisecond
				ca.Confirm = func(ctx context.Context, _ PairView) (bool, error) { <-ctx.Done(); return true, nil }
			}
			if mode == "initiator-no" {
				ca.Confirm = func(context.Context, PairView) (bool, error) { return false, nil }
			}
			if mode == "responder-no" {
				cb.Confirm = func(context.Context, PairView) (bool, error) { return false, nil }
			}
			if mode == "show-failure" {
				ca.Show = func(context.Context, PairView) error { return errors.New("presenter refused") }
			}
			if mode == "equal-key" {
				b = a
			}
			if mode == "zero-secret" {
				secret = [32]byte{}
			}
			ctx, cancel := context.WithTimeout(context.Background(), budget)
			defer cancel()
			ra, rb := pairRun(t, ctx, a, b, secret, ca, cb)
			if ra.err == nil || rb.err == nil || ra.candidate.Certificate != nil || rb.candidate.Certificate != nil {
				t.Fatalf("unexpected candidate: %v / %v", ra.err, rb.err)
			}
			if mode == "late-confirm" && !errors.Is(ra.err, ErrPairingUncertain) {
				t.Fatalf("late true lost uncertainty: %v", ra.err)
			}
			if mode == "initiator-no" && errors.Is(ra.err, ErrPairingUncertain) {
				t.Fatal("No treated as local Yes")
			}
		})
	}
}

// maliciousPairResponder uses real TLS and actual exporter/key evidence while
// controlling exactly one wire field. It never calls the production responder.
func maliciousPairResponder(raw net.Conn, local tls.Certificate, secret [32]byte, mode string, captured *[]byte) error {
	defer raw.Close()
	raw.SetDeadline(time.Now().Add(2 * time.Second))
	alpn := pairingProtocol
	if mode == "alpn" {
		alpn = "oa-framed/1"
	}
	if mode == "retired-alpn" {
		alpn = "oa-pair/1"
	}
	conn := tls.Server(raw, &tls.Config{Certificates: []tls.Certificate{local}, ClientAuth: tls.RequireAnyClientCert, MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13, NextProtos: []string{alpn}, SessionTicketsDisabled: true})
	if err := conn.Handshake(); err != nil {
		return err
	}
	state := conn.ConnectionState()
	leaf, _ := x509.ParseCertificate(local.Certificate[0])
	ki := sha256.Sum256(state.PeerCertificates[0].RawSubjectPublicKeyInfo)
	kr := sha256.Sum256(leaf.RawSubjectPublicKeyInfo)
	var keys [64]byte
	copy(keys[:32], ki[:])
	copy(keys[32:], kr[:])
	if mode == "key" {
		keys[0] ^= 1
	}
	var nonce [32]byte
	rand.Read(nonce[:])
	proposal := []byte("receiver-owned proposal")
	descriptor := pairDescriptor(proposal)
	if mode == "proposal-bound" {
		binary.BigEndian.PutUint32(descriptor[:4], PairingProposalLimit+1)
	}
	commit := pairCommit(2, keys, nonce, descriptor)
	read := func() ([]byte, error) { return listen.ReadFrameFrom(conn, pairingFrameLimit) }
	write := func(stage, version, role byte, transcript [32]byte, payload []byte) error {
		f := []byte{stage, version, role}
		f = append(f, transcript[:]...)
		f = append(f, payload...)
		return listen.WriteFrameTo(conn, f, 1024)
	}
	ci, err := read()
	if err != nil {
		return err
	}
	pause := func(stage string) bool {
		if mode != "pause-"+stage {
			return false
		}
		var b [1]byte
		conn.Read(b[:]) // The bounded helper closes raw at its actual deadline.
		return true
	}
	if pause("commit") {
		return nil
	}
	if mode == "silent" {
		time.Sleep(150 * time.Millisecond)
		return nil
	}
	if mode == "oversize" {
		return listen.WriteFrameTo(conn, make([]byte, 513), 1024)
	}
	if mode == "normal-frame" {
		return listen.WriteFrameTo(conn, []byte("endpoint@1 Describe"), 512)
	}
	if mode == "reflection" {
		return listen.WriteFrameTo(conn, ci, 512)
	}
	stage, version, role := byte(1), PairingVersion, byte(2)
	if mode == "stage" {
		stage = 2
	}
	if mode == "version" {
		version = 1
	}
	if mode == "role" {
		role = 1
	}
	payload := append([]byte{}, commit[:]...)
	if mode == "trailing" {
		payload = append(payload, 0)
	}
	if err = write(stage, version, role, [32]byte{}, payload); err != nil {
		return err
	}
	ni, err := read()
	if err != nil {
		return err
	}
	if pause("reveal") {
		return nil
	}
	reveal := nonce
	if mode == "nonce" {
		reveal[0] ^= 1
	}
	if err = write(2, PairingVersion, 2, [32]byte{}, append(append([]byte{}, reveal[:]...), descriptor[:]...)); err != nil {
		return err
	}
	// The initiator proposal may contain several exact bounded chunks.
	var initiatorProposal []byte
	total := int(binary.BigEndian.Uint32(ni[67:71]))
	for len(initiatorProposal) < total {
		chunk, e := read()
		if e != nil {
			return e
		}
		initiatorProposal = append(initiatorProposal, chunk[39:]...)
	}
	if pause("proposal") {
		return nil
	}
	if mode == "adaptive-proposal" || mode == "proposal-digest" {
		proposal[0] ^= 1
	}
	for offset, index := 0, 0; offset < len(proposal); index++ {
		n := min(pairingChunkSize, len(proposal)-offset)
		payload := []byte{byte(index), byte((len(proposal) + pairingChunkSize - 1) / pairingChunkSize)}
		payload = binary.BigEndian.AppendUint16(payload, uint16(n))
		payload = append(payload, proposal[offset:offset+n]...)
		if mode == "chunk-index" {
			payload[0]++
		}
		if mode == "chunk-total" {
			payload[1]++
		}
		if mode == "chunk-length" {
			payload[3]++
		}
		chunkRole := byte(2)
		if mode == "chunk-role" {
			chunkRole = 1
		}
		if err = write(3, PairingVersion, chunkRole, [32]byte{}, payload); err != nil {
			return err
		}
		offset += n
	}
	e, err := state.ExportKeyingMaterial("EXPORTER-Channel-Binding", []byte{}, 32)
	if err != nil {
		return err
	}
	h := sha256.New()
	h.Write([]byte("OA-Pair/2/transcript"))
	h.Write([]byte{PairingVersion})
	h.Write(keys[:])
	h.Write(ci[35:])
	h.Write(commit[:])
	h.Write(ni[35:67])
	h.Write(nonce[:])
	h.Write(e)
	for _, proposal := range [][]byte{initiatorProposal, proposal} {
		var size [4]byte
		binary.BigEndian.PutUint32(size[:], uint32(len(proposal)))
		h.Write(size[:])
		h.Write(proposal)
	}
	p := pairStream{conn: conn, role: 2, secret: secret}
	copy(p.transcript[:], h.Sum(nil))
	if _, err = read(); err != nil {
		return err
	}
	if pause("proof") {
		return nil
	}
	proof := p.mac("proof", 2, nil)
	if mode == "proof" {
		proof[0] ^= 1
	}
	if mode == "proof-stage" {
		proof = p.mac("displayed", 2, nil)
	}
	if mode == "capture" {
		*captured = append([]byte{}, proof...)
	}
	if mode == "replay" {
		proof = *captured
	}
	if err = write(4, PairingVersion, 2, p.transcript, proof); err != nil {
		return err
	}
	if mode != "lost-yes" && !strings.HasPrefix(mode, "pause-") {
		return nil
	}
	if _, err = read(); err != nil {
		return err
	}
	if pause("displayed") {
		return nil
	}
	if err = write(5, PairingVersion, 2, p.transcript, p.mac("displayed", 2, nil)); err != nil {
		return err
	}
	// Consume the initiator's irreversible Yes, then lose the final reply.
	_, err = read()
	if pause("decision") {
		return nil
	}
	return err
}

func TestPairingMalformedAndLostYes(t *testing.T) {
	for _, mode := range []string{"reflection", "role", "version", "stage", "trailing", "key", "nonce", "proof", "proof-stage", "oversize", "normal-frame", "alpn", "retired-alpn", "silent", "lost-yes", "adaptive-proposal", "proposal-digest", "proposal-bound", "chunk-index", "chunk-total", "chunk-length", "chunk-role"} {
		t.Run(mode, func(t *testing.T) {
			s, c := credentials(t)
			secret := pairSecret(t)
			left, right := net.Pipe()
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			if mode == "silent" {
				var done context.CancelFunc
				ctx, done = context.WithTimeout(ctx, 60*time.Millisecond)
				defer done()
			}
			peer := make(chan error, 1)
			go func() { peer <- maliciousPairResponder(right, s.Certificates[0], secret, mode, nil) }()
			callbacks := pairCallbacks()
			var shown, confirmed atomic.Int32
			callbacks.Show = func(context.Context, PairView) error { shown.Add(1); return nil }
			callbacks.Confirm = func(context.Context, PairView) (bool, error) { confirmed.Add(1); return true, nil }
			candidate, err := PairInitiator(ctx, left, c.Certificates[0], secret, callbacks)
			<-peer
			if err == nil || candidate.Certificate != nil {
				t.Fatal("invalid peer produced candidate")
			}
			if mode == "lost-yes" && !errors.Is(err, ErrPairingUncertain) {
				t.Fatalf("lost Yes misreported: %v", err)
			}
			if mode != "lost-yes" && (shown.Load() != 0 || confirmed.Load() != 0) {
				t.Fatal("invalid proposal or proof reached native display/consent")
			}
		})
	}
}

func TestPairingFreshSessionReplay(t *testing.T) {
	s, c := credentials(t)
	secret := pairSecret(t)
	var captured []byte
	for _, mode := range []string{"capture", "replay"} {
		left, right := net.Pipe()
		out := make(chan error, 1)
		go func() { out <- maliciousPairResponder(right, s.Certificates[0], secret, mode, &captured) }()
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		var confirms atomic.Int32
		cb := pairCallbacks()
		cb.Confirm = func(context.Context, PairView) (bool, error) { confirms.Add(1); return true, nil }
		_, err := PairInitiator(ctx, left, c.Certificates[0], secret, cb)
		cancel()
		<-out
		if err == nil {
			t.Fatal("incomplete/replayed ceremony accepted")
		}
		if mode == "replay" && confirms.Load() != 0 {
			t.Fatal("replayed proof reached person")
		}
	}
}

func TestPairingTwoTerminatedTLSLegsRefuse(t *testing.T) {
	for _, substitute := range []bool{false, true} {
		t.Run(fmt.Sprint(substitute), func(t *testing.T) {
			s, c := credentials(t)
			m, _ := credentials(t)
			a, b := c.Certificates[0], s.Certificates[0]
			left, relayLeft := net.Pipe()
			relayRight, right := net.Pipe()
			secret := pairSecret(t)
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			out := make(chan pairResult, 2)
			go func() { v, e := PairInitiator(ctx, left, a, secret, pairCallbacks()); out <- pairResult{v, e} }()
			go func() { v, e := PairResponder(ctx, right, b, secret, pairCallbacks()); out <- pairResult{v, e} }()
			relayDone := make(chan struct{})
			go func() {
				defer close(relayDone)
				defer relayLeft.Close()
				defer relayRight.Close()
				lcert, rcert := b, a
				if substitute {
					lcert = m.Certificates[0]
					rcert = m.Certificates[0]
				}
				l := tls.Server(relayLeft, &tls.Config{Certificates: []tls.Certificate{lcert}, ClientAuth: tls.RequireAnyClientCert, MinVersion: tls.VersionTLS13, NextProtos: []string{pairingProtocol}, SessionTicketsDisabled: true})
				r := tls.Client(relayRight, &tls.Config{Certificates: []tls.Certificate{rcert}, InsecureSkipVerify: true, MinVersion: tls.VersionTLS13, NextProtos: []string{pairingProtocol}, SessionTicketsDisabled: true})
				relayLeft.SetDeadline(time.Now().Add(time.Second))
				relayRight.SetDeadline(time.Now().Add(time.Second))
				handshake := make(chan error, 1)
				go func() { handshake <- l.Handshake() }()
				err := r.Handshake()
				other := <-handshake
				if err != nil || other != nil {
					return
				}
				for stage := 0; stage < 5; stage++ {
					f, e := listen.ReadFrameFrom(l, 512)
					if e != nil {
						return
					}
					if listen.WriteFrameTo(r, f, 512) != nil {
						return
					}
					f, e = listen.ReadFrameFrom(r, 512)
					if e != nil {
						return
					}
					if listen.WriteFrameTo(l, f, 512) != nil {
						return
					}
				}
			}()
			one, two := <-out, <-out
			<-relayDone
			if one.err == nil || two.err == nil {
				t.Fatal("terminated relay authenticated")
			}
			// false uses the original endpoint keys on each attacker leg. Only the
			// actual TLS exporters differ, isolating channel-binding substitution.
		})
	}
}

func TestPairingHandshakeCancellation(t *testing.T) {
	s, _ := credentials(t)
	a, b := net.Pipe()
	defer b.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	_, err := PairInitiator(ctx, a, s.Certificates[0], pairSecret(t), pairCallbacks())
	if err == nil || errors.Is(err, ErrPairingUncertain) {
		t.Fatalf("handshake: %v", err)
	}
}

func TestPairingLocalYesLossIsUncertainOnEitherSide(t *testing.T) {
	for _, dropInitiator := range []bool{false, true} {
		t.Run(fmt.Sprint(dropInitiator), func(t *testing.T) {
			s, c := credentials(t)
			left, right := net.Pipe()
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			ca, cb := pairCallbacks(), pairCallbacks()
			if dropInitiator {
				ca.Confirm = func(context.Context, PairView) (bool, error) { left.Close(); return true, nil }
			} else {
				cb.Confirm = func(context.Context, PairView) (bool, error) { right.Close(); return true, nil }
			}
			secret := pairSecret(t)
			out := make(chan pairResult, 1)
			go func() { v, e := PairResponder(ctx, right, s.Certificates[0], secret, cb); out <- pairResult{v, e} }()
			v, e := PairInitiator(ctx, left, c.Certificates[0], secret, ca)
			a, b := pairResult{v, e}, <-out
			selected := b
			if dropInitiator {
				selected = a
			}
			if !errors.Is(selected.err, ErrPairingUncertain) || a.candidate.Certificate != nil || b.candidate.Certificate != nil {
				t.Fatalf("lost local Yes: %v / %v", a.err, b.err)
			}
		})
	}
}

func TestPairingLateShowNeverConfirms(t *testing.T) {
	s, c := credentials(t)
	ctx, cancel := context.WithTimeout(context.Background(), 70*time.Millisecond)
	defer cancel()
	ca, cb := pairCallbacks(), pairCallbacks()
	var confirmed atomic.Bool
	ca.Show = func(ctx context.Context, _ PairView) error { <-ctx.Done(); return nil }
	ca.Confirm = func(context.Context, PairView) (bool, error) { confirmed.Store(true); return true, nil }
	a, b := pairRun(t, ctx, c.Certificates[0], s.Certificates[0], pairSecret(t), ca, cb)
	if a.err == nil || b.err == nil || confirmed.Load() || errors.Is(a.err, ErrPairingUncertain) {
		t.Fatalf("late display advanced: %v / %v", a.err, b.err)
	}
}

func TestPairingDeadlineAtEachPeerWait(t *testing.T) {
	for _, stage := range []string{"commit", "reveal", "proposal", "proof", "displayed", "decision"} {
		t.Run(stage, func(t *testing.T) {
			s, c := credentials(t)
			secret := pairSecret(t)
			left, right := net.Pipe()
			ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
			defer cancel()
			peer := make(chan error, 1)
			go func() { peer <- maliciousPairResponder(right, s.Certificates[0], secret, "pause-"+stage, nil) }()
			v, e := PairInitiator(ctx, left, c.Certificates[0], secret, pairCallbacks())
			<-peer
			if e == nil || v.Certificate != nil {
				t.Fatal("deadline produced candidate")
			}
			if errors.Is(e, ErrPairingUncertain) != (stage == "decision") {
				t.Fatalf("wrong consent boundary at %s: %v", stage, e)
			}
		})
	}
}

func TestPairingAgreementCopiesAndAsymmetry(t *testing.T) {
	s, c := credentials(t)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	original := bytes.Repeat([]byte{0x37}, PairingProposalLimit)
	callbacks := func(role byte) PairingCallbacks {
		cb := pairCallbacks()
		cb.Prepare = func(_ context.Context, k PairKeys) ([]byte, error) {
			if k.Role != role {
				return nil, errors.New("role")
			}
			if role == 1 {
				return nil, nil
			}
			return original, nil
		}
		check := func(v PairView) error {
			if len(v.InitiatorProposal) != 0 || !bytes.Equal(v.ResponderProposal, bytes.Repeat([]byte{0x37}, PairingProposalLimit)) {
				return errors.New("agreement changed")
			}
			return nil
		}
		cb.Validate = func(_ context.Context, v PairView) error {
			if e := check(v); e != nil {
				return e
			}
			if role == 2 {
				original[0] = 0xff
			}
			v.ResponderProposal[0] = 0xfe
			return nil
		}
		cb.Show = func(_ context.Context, v PairView) error {
			if e := check(v); e != nil {
				return e
			}
			v.ResponderProposal[0] = 0xfd
			return nil
		}
		cb.Confirm = func(_ context.Context, v PairView) (bool, error) {
			if e := check(v); e != nil {
				return false, e
			}
			v.ResponderProposal[0] = 0xfc
			return true, nil
		}
		return cb
	}
	a, b := pairRun(t, ctx, c.Certificates[0], s.Certificates[0], pairSecret(t), callbacks(1), callbacks(2))
	if a.err != nil || b.err != nil {
		t.Fatalf("%v / %v", a.err, b.err)
	}
	if a.candidate.View.ResponderProposal[0] != 0x37 || b.candidate.View.ResponderProposal[0] != 0x37 {
		t.Fatal("callback mutation escaped")
	}
	a.candidate.View.ResponderProposal[0] = 0
	if b.candidate.View.ResponderProposal[0] != 0x37 {
		t.Fatal("candidate aliases peer")
	}
}

func TestPairingAgreementRequiredCallbacksAndBounds(t *testing.T) {
	for _, mode := range []string{"prepare-missing", "validate-missing", "oversize", "prepare-error", "validate-error", "late-prepare", "late-validate"} {
		t.Run(mode, func(t *testing.T) {
			s, c := credentials(t)
			ca, cb := pairCallbacks(), pairCallbacks()
			var confirms atomic.Int32
			ca.Confirm = func(context.Context, PairView) (bool, error) { confirms.Add(1); return true, nil }
			switch mode {
			case "prepare-missing":
				ca.Prepare = nil
			case "validate-missing":
				ca.Validate = nil
			case "oversize":
				ca.Prepare = func(context.Context, PairKeys) ([]byte, error) { return make([]byte, PairingProposalLimit+1), nil }
			case "prepare-error":
				ca.Prepare = func(context.Context, PairKeys) ([]byte, error) { return nil, errors.New("refuse") }
			case "validate-error":
				ca.Validate = func(context.Context, PairView) error { return errors.New("refuse") }
			case "late-prepare":
				ca.Prepare = func(ctx context.Context, _ PairKeys) ([]byte, error) { <-ctx.Done(); return nil, nil }
			case "late-validate":
				ca.Validate = func(ctx context.Context, _ PairView) error { <-ctx.Done(); return nil }
			}
			ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
			defer cancel()
			a, b := pairRun(t, ctx, c.Certificates[0], s.Certificates[0], pairSecret(t), ca, cb)
			if a.err == nil || b.err == nil || confirms.Load() != 0 || errors.Is(a.err, ErrPairingUncertain) {
				t.Fatalf("advanced: %v/%v", a.err, b.err)
			}
		})
	}
}

func TestPairingProposalChunkBoundaries(t *testing.T) {
	for _, size := range []int{1, 448, 449, PairingProposalLimit} {
		t.Run(fmt.Sprint(size), func(t *testing.T) {
			s, c := credentials(t)
			initiator := bytes.Repeat([]byte{0x11}, size)
			responder := bytes.Repeat([]byte{0x22}, PairingProposalLimit)
			callbacks := func(role byte, local tls.Certificate) PairingCallbacks {
				cb := pairCallbacks()
				leaf, err := x509.ParseCertificate(local.Certificate[0])
				if err != nil {
					t.Fatal(err)
				}
				cb.Prepare = func(_ context.Context, keys PairKeys) ([]byte, error) {
					if keys.Role != role || keys.LocalKey != sha256.Sum256(leaf.RawSubjectPublicKeyInfo) || keys.PeerKey == keys.LocalKey {
						return nil, errors.New("prepare lacks actual role/key evidence")
					}
					if role == 1 {
						return initiator, nil
					}
					return responder, nil
				}
				cb.Validate = func(_ context.Context, v PairView) error {
					if !bytes.Equal(v.InitiatorProposal, initiator) || !bytes.Equal(v.ResponderProposal, responder) {
						return errors.New("ordered chunked agreement differs")
					}
					return nil
				}
				return cb
			}
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			a, b := pairRun(t, ctx, c.Certificates[0], s.Certificates[0], pairSecret(t), callbacks(1, c.Certificates[0]), callbacks(2, s.Certificates[0]))
			if a.err != nil || b.err != nil || a.candidate.View.Transcript != b.candidate.View.Transcript {
				t.Fatalf("chunked ceremony: %v / %v", a.err, b.err)
			}
		})
	}
}
