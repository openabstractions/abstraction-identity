package listen

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"

	identity "github.com/openabstractions/abstraction-identity"
)

// proofRefusalHeader is a terminal response control word. It is outside the
// shared low-30-bit payload length space, including on single exchanges.
const proofRefusalHeader uint32 = 0xFFFFFFFE

// ErrCallerProofUnmet means the receiver refused its caller-proof requirement.
// It says nothing about the client's independently verified server identity.
var ErrCallerProofUnmet = errors.New("listen: receiver refused caller proof")

// ErrProofRefusalProtocol is a malformed fixed refusal control payload.
var ErrProofRefusalProtocol = errors.New("listen: malformed caller-proof refusal")

// ProofRefusal carries only fixed policy vocabulary. The receiver does not
// disclose the proof it observed, platform explanation, or caller values.
type ProofRefusal struct {
	Attribute string
	Required  identity.Proof
}

func (e *ProofRefusal) Error() string {
	if e.Attribute == "" {
		return ErrCallerProofUnmet.Error()
	}
	return fmt.Sprintf("%s: %s requires %s", ErrCallerProofUnmet, e.Attribute, e.Required)
}

func (e *ProofRefusal) Is(target error) bool {
	return target == ErrCallerProofUnmet || target == identity.ErrNotProven
}

var proofAttributes = [...]string{"", "user", "process", "path", "package", "code"}

func proofRefusalBytes(err error) [6]byte {
	var result [6]byte
	binary.BigEndian.PutUint32(result[:4], proofRefusalHeader)
	var proof *identity.ProofError
	if errors.As(err, &proof) {
		for i, name := range proofAttributes {
			if proof.Attribute == name && i != 0 && proof.Want > identity.ProofNone && proof.Want <= identity.ProofSigned {
				result[4], result[5] = byte(i), byte(proof.Want)
				break
			}
		}
	}
	return result
}

func readProofRefusal(r io.Reader) error {
	var tokens [2]byte
	if _, err := io.ReadFull(r, tokens[:]); err != nil {
		return err
	}
	attribute, required := tokens[0], tokens[1]
	if int(attribute) >= len(proofAttributes) || required > byte(identity.ProofSigned) ||
		(attribute == 0) != (required == 0) {
		return ErrProofRefusalProtocol
	}
	return &ProofRefusal{Attribute: proofAttributes[attribute], Required: identity.Proof(required)}
}

func sendProofRefusal(w io.Writer, err error) error {
	word := proofRefusalBytes(err)
	return writeAll(w, word[:])
}
