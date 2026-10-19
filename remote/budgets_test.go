package remote

import (
	"github.com/openabstractions/abstraction-identity/internal/personfolders"
	"net"
	"os"
	"testing"
	"time"
)

func TestSourceBudgetCanonicalIPAndRelease(t *testing.T) {
	b := newServerBudgets(Server{MaxSourceConnections: 1})
	release, ok := b.source(&net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 1})
	if !ok {
		t.Fatal("first source refused")
	}
	if _, ok := b.source(&net.TCPAddr{IP: net.ParseIP("::ffff:127.0.0.1"), Port: 2}); ok {
		t.Fatal("port/mapped address bypassed source cap")
	}
	other, ok := b.source(&net.TCPAddr{IP: net.ParseIP("127.0.0.2")})
	if !ok {
		t.Fatal("different source starved")
	}
	other()
	release()
	release()
	if len(b.sources) != 0 {
		t.Fatal("source slots leaked")
	}
	if _, ok := b.source(&net.UnixAddr{Name: "not TCP"}); ok {
		t.Fatal("unknown source accepted")
	}
}

func TestPeerBudgetConcurrencyRateRecoveryAndBoundedIdleState(t *testing.T) {
	now := time.Unix(1000, 0)
	b := newServerBudgets(Server{MaxPeerCalls: 1, PeerRequestsPerSecond: 2, PeerBurst: 2})
	b.now = func() time.Time { return now }
	key := [32]byte{1}
	first, ok := b.peer(key)
	if !ok {
		t.Fatal("first peer refused")
	}
	if _, ok := b.peer(key); ok {
		t.Fatal("concurrency limit bypassed")
	}
	other, ok := b.peer([32]byte{2})
	if !ok {
		t.Fatal("different key starved")
	}
	other()
	first()
	first()
	second, ok := b.peer(key)
	if !ok {
		t.Fatal("concurrency refusal consumed rate token")
	}
	second()
	if _, ok := b.peer(key); ok {
		t.Fatal("burst exceeded")
	}
	now = now.Add(500 * time.Millisecond)
	third, ok := b.peer(key)
	if !ok {
		t.Fatal("rate did not recover")
	}
	// Time spent in a live call must refill tokens too.
	now = now.Add(time.Second)
	third()
	fourth, ok := b.peer(key)
	if !ok {
		t.Fatal("live call discarded refill time")
	}
	fourth()
	for i := len(b.peers); i < maxPeerBudgetEntries; i++ {
		k := [32]byte{byte(i), byte(i >> 8), 1}
		release, ok := b.peer(k)
		if !ok {
			t.Fatal("bounded table filled early")
		}
		release()
	}
	if _, ok := b.peer([32]byte{9, 9, 9}); ok {
		t.Fatal("unbounded key table")
	}
	now = now.Add(peerBudgetIdle)
	release, ok := b.peer([32]byte{9, 9, 9})
	if !ok || len(b.peers) != 1 {
		t.Fatal("idle entries did not expire")
	}
	// An active call survives idle pruning and retains its concurrency slot.
	now = now.Add(2 * peerBudgetIdle)
	next, ok := b.peer([32]byte{8, 8, 8})
	if !ok {
		t.Fatal("new peer refused after expiry")
	}
	if _, ok := b.peer([32]byte{9, 9, 9}); ok {
		t.Fatal("active peer entry evicted")
	}
	next()
	release()
}

func TestPeerBudgetIdlePruningPreservesRateDebt(t *testing.T) {
	now := time.Unix(1000, 0)
	b := newServerBudgets(Server{PeerRequestsPerSecond: 1, PeerBurst: 1000})
	b.now = func() time.Time { return now }
	key := [32]byte{1}
	for i := 0; i < 1000; i++ {
		release, ok := b.peer(key)
		if !ok {
			t.Fatalf("initial burst stopped at %d", i)
		}
		release()
	}
	if _, ok := b.peer(key); ok {
		t.Fatal("initial burst exceeded")
	}
	now = now.Add(61 * time.Second)
	other, ok := b.peer([32]byte{2})
	if !ok {
		t.Fatal("other key refused")
	}
	other()
	// A new key triggers idle pruning. A still owes 939 tokens, and may use
	// only its 61 newly earned tokens when revisited, not a fresh 1000 burst.
	for i := 0; i < 61; i++ {
		release, ok := b.peer(key)
		if !ok {
			t.Fatalf("earned refill stopped at %d", i)
		}
		release()
	}
	if _, ok := b.peer(key); ok {
		t.Fatal("idle pruning discarded rate debt")
	}
}

// TestMain confines per-user folders to the canonical owned test fixture.
func TestMain(m *testing.M) { os.Exit(personfolders.Main(m)) }
