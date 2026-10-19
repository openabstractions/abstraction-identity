package remote

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
)

const SubjectPrefix = "remote:"

// RemotePeer names an admitted leaf key outside the native identity proof ladder.
// Its zero value names no subject. It conveys no capability permission.
type RemotePeer struct {
	key      [32]byte
	admitted bool
}

func (p RemotePeer) Program() string {
	if !p.admitted {
		return ""
	}
	return SubjectPrefix + hex.EncodeToString(p.key[:])
}

// ParseSubjectProgram validates stored target syntax; it admits no connection.
func ParseSubjectProgram(program string) ([32]byte, error) {
	var key [32]byte
	text, ok := strings.CutPrefix(program, SubjectPrefix)
	if !ok || len(text) != 64 {
		return key, fmt.Errorf("remote: invalid subject")
	}
	raw, err := hex.DecodeString(text)
	if err != nil || hex.EncodeToString(raw) != text {
		return key, fmt.Errorf("remote: invalid subject")
	}
	copy(key[:], raw)
	return key, nil
}

func ValidSubjectProgram(program string) bool {
	_, err := ParseSubjectProgram(program)
	return err == nil
}

// SubjectOf maps receiving TLS evidence after the owner's current exact pin
// policy admits it. Reuse the handshake callback. Display claims grant nothing.
func SubjectOf(peer Peer, admit func(Peer) error) (RemotePeer, error) {
	if admit == nil || peer.Certificate == nil || len(peer.Certificate.RawSubjectPublicKeyInfo) == 0 ||
		sha256.Sum256(peer.Certificate.RawSubjectPublicKeyInfo) != peer.Key {
		return RemotePeer{}, fmt.Errorf("%w: remote subject evidence missing or inconsistent", ErrTrust)
	}
	if err := admit(peer); err != nil {
		return RemotePeer{}, fmt.Errorf("%w: remote subject pin refused: %w", ErrTrust, err)
	}
	return RemotePeer{key: peer.Key, admitted: true}, nil
}
