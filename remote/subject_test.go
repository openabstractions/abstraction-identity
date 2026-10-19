package remote

import (
	"crypto/sha256"
	"crypto/x509"
	"errors"
	"strings"
	"testing"
)

func TestRemoteSubjectUsesExactLivePinAndLeafKey(t *testing.T) {
	cert := &x509.Certificate{RawSubjectPublicKeyInfo: []byte("fixture SPKI")}
	peer := Peer{Certificate: cert, Key: sha256.Sum256(cert.RawSubjectPublicKeyInfo)}
	live := true
	calls := 0
	admit := func(p Peer) error {
		calls++
		if !live || p.Key != peer.Key {
			return errors.New("pin absent")
		}
		return nil
	}
	subject, err := SubjectOf(peer, admit)
	if err != nil || !ValidSubjectProgram(subject.Program()) || calls != 1 {
		t.Fatal(subject, err, calls)
	}
	renewed := peer
	renewed.Certificate = &x509.Certificate{RawSubjectPublicKeyInfo: cert.RawSubjectPublicKeyInfo, Raw: []byte("renewed cert")}
	next, err := SubjectOf(renewed, admit)
	if err != nil || next.Program() != subject.Program() {
		t.Fatal(next, err)
	}
	other := Peer{Certificate: &x509.Certificate{RawSubjectPublicKeyInfo: []byte("different SPKI")}}
	other.Key = sha256.Sum256(other.Certificate.RawSubjectPublicKeyInfo)
	if _, err = SubjectOf(other, admit); !errors.Is(err, ErrTrust) {
		t.Fatal(err)
	}
	otherSubject, err := SubjectOf(other, func(Peer) error { return nil })
	if err != nil || otherSubject.Program() == subject.Program() {
		t.Fatal(otherSubject, err)
	}
	live = false
	if _, err = SubjectOf(peer, admit); !errors.Is(err, ErrTrust) {
		t.Fatal(err)
	}
	if (RemotePeer{}).Program() != "" {
		t.Fatal("zero peer acquired identity")
	}
}

func TestRemoteSubjectRejectsMissingAndInconsistentEvidence(t *testing.T) {
	for _, p := range []Peer{{}, {Certificate: &x509.Certificate{}}, {Certificate: &x509.Certificate{RawSubjectPublicKeyInfo: []byte("key")}}} {
		if _, e := SubjectOf(p, func(Peer) error { return nil }); !errors.Is(e, ErrTrust) {
			t.Fatal(p, e)
		}
	}
	p := Peer{Certificate: &x509.Certificate{RawSubjectPublicKeyInfo: []byte("key")}, Key: sha256.Sum256([]byte("key"))}
	if _, e := SubjectOf(p, nil); !errors.Is(e, ErrTrust) {
		t.Fatal(e)
	}
	for _, s := range []string{"remote:", "remote:" + strings.Repeat("A", 64), "remote:" + strings.Repeat("a", 63), "remote:" + strings.Repeat("a", 64) + "/x", "/tmp/remote:" + strings.Repeat("a", 64), "remote:*"} {
		if ValidSubjectProgram(s) {
			t.Fatal("invalid remote token accepted", s)
		}
	}
}
