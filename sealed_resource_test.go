package identity

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io/fs"
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/openabstractions/abstraction-identity/fileid"
)

func TestSealedResourceCaptureBoundAndOwnership(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "Contents", "Resources")
	if err := os.MkdirAll(dir, 0700); err != nil {
		t.Fatal(err)
	}
	program := filepath.Join(root, "host")
	resource := filepath.Join(dir, "data")
	if err := os.WriteFile(program, []byte("host"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(resource, []byte("sealed"), 0600); err != nil {
		t.Fatal(err)
	}
	b, err := fileid.Open(context.Background(), fileid.Self, root, fileid.Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	p, err := fileid.Open(context.Background(), fileid.Self, program, fileid.Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	got, err := captureSealedResource(context.Background(), b, p, "Resources/data", 6)
	if err != nil || string(got) != "sealed" {
		t.Fatalf("exact bound: %q %v", got, err)
	}
	for _, n := range []int64{0, -1, 5, int64(^uint64(0) >> 1)} {
		if _, err := captureSealedResource(context.Background(), b, p, "Resources/data", n); !errors.Is(err, fs.ErrInvalid) {
			t.Fatalf("bound %d: %v", n, err)
		}
	}
	for _, name := range []string{"Resources/../data", "Resources//data", "Resources/./data", "../Resources/data", "/Resources/data", "Resources\\data", "Resources/data/", "Resources/a\x00b"} {
		if _, err := captureSealedResource(context.Background(), b, p, name, 6); err == nil {
			t.Fatalf("unsafe name %q", name)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := captureSealedResource(ctx, b, p, "Resources/data", 6); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if _, err = b.File().Stat(); err != nil {
		t.Fatalf("borrowed bundle closed: %v", err)
	}
	if _, err = p.File().Stat(); err != nil {
		t.Fatalf("borrowed program closed: %v", err)
	}
}

type sealedResourceTestNative struct {
	entered, release chan struct{}
	closed           int
}

func TestSealedResourceRefusesOutsideAndMultiname(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "Contents/Resources"), 0700); err != nil {
		t.Fatal(err)
	}
	resource := filepath.Join(root, "Contents/Resources/data")
	if err := os.WriteFile(resource, []byte("data"), 0600); err != nil {
		t.Fatal(err)
	}
	outside := filepath.Join(t.TempDir(), "host")
	if err := os.WriteFile(outside, []byte("host"), 0600); err != nil {
		t.Fatal(err)
	}
	b, err := fileid.Open(context.Background(), fileid.Self, root, fileid.Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	p, err := fileid.Open(context.Background(), fileid.Self, outside, fileid.Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	if _, err := captureSealedResource(context.Background(), b, p, "Resources/data", 4); !errors.Is(err, ErrNotProven) {
		t.Fatalf("outside: %v", err)
	}
	if err := os.Link(resource, filepath.Join(root, "second-name")); err != nil {
		t.Fatal(err)
	}
	inside := filepath.Join(root, "host")
	if err := os.WriteFile(inside, []byte("host"), 0600); err != nil {
		t.Fatal(err)
	}
	q, err := fileid.Open(context.Background(), fileid.Self, inside, fileid.Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer q.Close()
	if _, err := captureSealedResource(context.Background(), b, q, "Resources/data", 4); !errors.Is(err, ErrNotProven) {
		t.Fatalf("multiname: %v", err)
	}
}

func (n *sealedResourceTestNative) match(*XPCRequest) (Code, Proof, error) {
	if n.entered != nil {
		close(n.entered)
		<-n.release
	}
	return Code{Trusted: true}, ProofBound, nil
}
func (n *sealedResourceTestNative) close() { n.closed++ }
func TestSealedResourceEvidenceLifetime(t *testing.T) {
	n := &sealedResourceTestNative{entered: make(chan struct{}), release: make(chan struct{})}
	e := &SealedResourceEvidence{state: &sealedResourceState{data: []byte("sealed"), native: n}}
	copyValue := *e
	b, err := e.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	b[0] = 'X'
	again, _ := e.Bytes()
	if string(again) != "sealed" {
		t.Fatal("mutable evidence bytes")
	}
	if _, _, err = e.MatchXPCRequest(nil); !errors.Is(err, ErrNoBinding) {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		_, _, err := e.MatchXPCRequest(&XPCRequest{})
		if err != nil {
			t.Error(err)
		}
	}()
	<-n.entered
	go func() { defer wg.Done(); copyValue.Close() }()
	close(n.release)
	wg.Wait()
	if n.closed != 1 {
		t.Fatal(n.closed)
	}
	e.Close()
	copyValue.Close()
	if n.closed != 1 {
		t.Fatal("double free")
	}
	if _, err = e.Bytes(); !errors.Is(err, net.ErrClosed) {
		t.Fatal(err)
	}
	if _, _, err = e.MatchXPCRequest(nil); !errors.Is(err, net.ErrClosed) {
		t.Fatal(err)
	}
	var zero SealedResourceEvidence
	if _, err := zero.Bytes(); !errors.Is(err, net.ErrClosed) {
		t.Fatal(err)
	}
	zero.Close()
	var nilValue *SealedResourceEvidence
	nilValue.Close()
}

func sealedResourceHeader(cpu uint32) []byte {
	b := make([]byte, 32)
	binary.LittleEndian.PutUint32(b, 0xfeedfacf)
	binary.LittleEndian.PutUint32(b[4:], cpu)
	binary.LittleEndian.PutUint32(b[12:], 2)
	return b
}
func sealedResourceFat(wide, swapped bool) []byte {
	b := make([]byte, 1056)
	var order binary.ByteOrder = binary.BigEndian
	if swapped {
		order = binary.LittleEndian
	}
	magic, entry := uint32(0xcafebabe), 20
	if wide {
		magic, entry = 0xcafebabf, 32
	}
	order.PutUint32(b, magic)
	order.PutUint32(b[4:], 2)
	for i, cpu := range []uint32{0x0100000c, 0x01000007} {
		a := b[8+i*entry:]
		off := uint64(256 + i*768)
		order.PutUint32(a, cpu)
		if wide {
			order.PutUint64(a[8:], off)
			order.PutUint64(a[16:], 32)
			order.PutUint32(a[24:], 8)
		} else {
			order.PutUint32(a[8:], uint32(off))
			order.PutUint32(a[12:], 32)
			order.PutUint32(a[16:], 8)
		}
		copy(b[off:], sealedResourceHeader(cpu))
	}
	return b
}
func TestSealedResourceArchitectureDirectory(t *testing.T) {
	for _, wide := range []bool{false, true} {
		for _, swapped := range []bool{false, true} {
			b := sealedResourceFat(wide, swapped)
			a, err := sealedResourceArchitectures(bytes.NewReader(b), int64(len(b)))
			if err != nil || len(a) != 2 {
				t.Fatalf("%v %v: %v", wide, swapped, err)
			}
		}
	}
	thin := sealedResourceHeader(0x0100000c)
	if a, err := sealedResourceArchitectures(bytes.NewReader(thin), 32); err != nil || len(a) != 1 {
		t.Fatal(err)
	}
	for i := 0; i < len(thin); i++ {
		if _, err := sealedResourceArchitectures(bytes.NewReader(thin[:i]), int64(i)); err == nil {
			t.Fatalf("truncated %d", i)
		}
	}
	for name, change := range map[string]func([]byte){
		"fat64-overflow-offset":    func(b []byte) { binary.BigEndian.PutUint64(b[16:], ^uint64(0)) },
		"fat64-overflow-length":    func(b []byte) { binary.BigEndian.PutUint64(b[24:], ^uint64(0)) },
		"fat64-reserved":           func(b []byte) { binary.BigEndian.PutUint32(b[36:], 1) },
		"fat64-overlap":            func(b []byte) { binary.BigEndian.PutUint64(b[48:], 256) },
		"fat64-table-overlap":      func(b []byte) { binary.BigEndian.PutUint64(b[16:], 0) },
		"fat64-hostile-count":      func(b []byte) { binary.BigEndian.PutUint32(b[4:], ^uint32(0)) },
		"fat64-slice-disagreement": func(b []byte) { binary.LittleEndian.PutUint32(b[260:], 0x01000007) },
	} {
		t.Run(name, func(t *testing.T) {
			b := sealedResourceFat(true, false)
			change(b)
			if _, err := sealedResourceArchitectures(bytes.NewReader(b), int64(len(b))); err == nil {
				t.Fatal("accepted")
			}
		})
	}
}
