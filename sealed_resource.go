package identity

import (
	"context"
	"fmt"
	"io"
	"io/fs"
	"net"
	"strings"
	"sync"

	"github.com/openabstractions/abstraction-identity/fileid"
)

// SealedResourceEvidence owns captured resource bytes and the native code
// generations whose trusted signatures seal them. Close releases that state.
// It conveys no identity or rights to other programs inside the bundle.
type SealedResourceEvidence struct {
	state *sealedResourceState
}

type sealedResourceState struct {
	mu     sync.Mutex
	data   []byte
	native sealedResourceNative
}

type sealedResourceNative interface {
	match(*XPCRequest) (Code, Proof, error)
	close()
}

// VerifySealedResource captures a bounded plain resource of an actual native
// app-bundle main program. bundle and program are borrowed open local fileid
// handles; keep them open until return. resourcePath is a clean Resources/ name
// relative to Contents. Policy callers supply their own constant resource name.
// Every supported slice must pass platform-trusted signature and resource checks.
// The returned Code describes the native selected slice; MatchXPCRequest reports
// the particular matched slice. No executable reader or caller requirement is exposed.
// Native Security calls are synchronous; ctx bounds the walks and resource reads.
func VerifySealedResource(ctx context.Context, bundle, program fileid.Handle, resourcePath string, maxBytes int64) (*SealedResourceEvidence, Code, Proof, error) {
	return verifySealedResource(ctx, bundle, program, resourcePath, maxBytes)
}

func sealedResourceName(name string) error {
	if !strings.HasPrefix(name, "Resources/") || strings.ContainsAny(name, "\\\x00") {
		return fmt.Errorf("%w: sealed resource name", fileid.ErrUnsafeName)
	}
	for _, part := range strings.Split(name, "/") {
		if err := fileid.SafeName(part); err != nil {
			return err
		}
	}
	return nil
}

func captureSealedResource(ctx context.Context, bundle, program fileid.Handle, name string, limit int64) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if limit <= 0 || uint64(limit) >= uint64(^uint(0)>>1) {
		return nil, fmt.Errorf("%w: sealed resource bound", fs.ErrInvalid)
	}
	if err := sealedResourceName(name); err != nil {
		return nil, err
	}
	for _, h := range []fileid.Handle{bundle, program} {
		if h.File() == nil || h.FileID().IsZero() {
			return nil, fileid.ErrNoFile
		}
		if _, err := h.File().Stat(); err != nil {
			return nil, err
		}
	}
	programInfo, err := program.File().Stat()
	if err != nil {
		return nil, err
	}
	if !programInfo.Mode().IsRegular() {
		return nil, fmt.Errorf("%w: program is not regular", fs.ErrInvalid)
	}
	if !bundle.FileID().IsDir() || program.FileID().IsDir() {
		return nil, fmt.Errorf("%w: sealed resource handle kinds", fs.ErrInvalid)
	}
	if err := sealedResourceInside(program, bundle); err != nil {
		return nil, err
	}
	h, err := bundle.Beneath("Contents/"+name, fileid.Options{Read: true})
	if err != nil {
		return nil, err
	}
	defer h.Close()
	if err := sealedResourceInside(h, bundle); err != nil {
		return nil, err
	}
	info, err := h.File().Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Size() < 1 || info.Size() > limit {
		return nil, fmt.Errorf("%w: sealed resource size/type", fs.ErrInvalid)
	}
	var data []byte
	buf := make([]byte, 32768)
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		remaining := limit + 1 - int64(len(data))
		if remaining < int64(len(buf)) {
			buf = buf[:remaining]
		}
		n, readErr := h.File().Read(buf)
		data = append(data, buf[:n]...)
		if int64(len(data)) > limit {
			return nil, fmt.Errorf("%w: sealed resource exceeds bound", fs.ErrInvalid)
		}
		if readErr == io.EOF {
			break
		}
		if readErr != nil {
			return nil, readErr
		}
		if n == 0 {
			return nil, io.ErrNoProgress
		}
	}
	if len(data) == 0 {
		return nil, fmt.Errorf("%w: empty sealed resource", fs.ErrInvalid)
	}
	return data, nil
}

func sealedResourceInside(h, bundle fileid.Handle) error {
	rel, err := h.Relate(bundle)
	if err != nil {
		return err
	}
	if rel.Kind != fileid.RelationInside || rel.MultiName {
		return fmt.Errorf("%w: sealed resource containment", ErrNotProven)
	}
	return nil
}

// Bytes returns a defensive copy of the authenticated resource DATA.
func (e *SealedResourceEvidence) Bytes() ([]byte, error) {
	if e == nil || e.state == nil {
		return nil, net.ErrClosed
	}
	s := e.state
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.native == nil {
		return nil, net.ErrClosed
	}
	return append([]byte(nil), s.data...), nil
}

// MatchXPCRequest checks the actual received dictionary's trusted code against
// an authenticated exact generation. It does not change the request's Binding.
func (e *SealedResourceEvidence) MatchXPCRequest(r *XPCRequest) (Code, Proof, error) {
	if e == nil || e.state == nil {
		return Code{}, ProofUnmet, net.ErrClosed
	}
	s := e.state
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.native == nil {
		return Code{}, ProofUnmet, net.ErrClosed
	}
	if r == nil {
		return Code{}, ProofUnmet, ErrNoBinding
	}
	return s.native.match(r)
}

// Close is safe alongside Bytes/Match and through copied evidence values.
func (e *SealedResourceEvidence) Close() error {
	if e == nil || e.state == nil {
		return nil
	}
	s := e.state
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.native != nil {
		s.native.close()
		s.native = nil
		s.data = nil
	}
	return nil
}
