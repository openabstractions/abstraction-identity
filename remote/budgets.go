package remote

import (
	"net"
	"net/netip"
	"sync"
	"time"
)

// Rate state is bounded even when many different admitted keys visit once.
// Source state contains only live handshakes, bounded by MaxConnections.
const maxPeerBudgetEntries = 1024
const peerBudgetIdle = time.Minute

type peerBudget struct {
	active int
	tokens float64
	last   time.Time
}

type serverBudgets struct {
	mu                     sync.Mutex
	sources                map[netip.Addr]int
	peers                  map[[32]byte]*peerBudget
	sourceLimit, peerLimit int
	rate, burst            int
	now                    func() time.Time
}

func newServerBudgets(s Server) *serverBudgets {
	if s.MaxSourceConnections == 0 {
		s.MaxSourceConnections = 4
	}
	if s.MaxPeerCalls == 0 {
		s.MaxPeerCalls = 8
	}
	if s.PeerRequestsPerSecond == 0 {
		s.PeerRequestsPerSecond = 32
	}
	if s.PeerBurst == 0 {
		s.PeerBurst = 64
	}
	return &serverBudgets{sources: make(map[netip.Addr]int), peers: make(map[[32]byte]*peerBudget),
		sourceLimit: s.MaxSourceConnections, peerLimit: s.MaxPeerCalls,
		rate: s.PeerRequestsPerSecond, burst: s.PeerBurst, now: time.Now}
}

func (b *serverBudgets) source(address net.Addr) (func(), bool) {
	tcp, ok := address.(*net.TCPAddr)
	if !ok || tcp == nil || !tcp.AddrPort().Addr().IsValid() {
		return nil, false
	}
	ip := tcp.AddrPort().Addr().Unmap().WithZone("")
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.sources[ip] >= b.sourceLimit {
		return nil, false
	}
	b.sources[ip]++
	var once sync.Once
	return func() {
		once.Do(func() {
			b.mu.Lock()
			defer b.mu.Unlock()
			b.sources[ip]--
			if b.sources[ip] == 0 {
				delete(b.sources, ip)
			}
		})
	}, true
}

func (b *serverBudgets) peer(key [32]byte) (func(), bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	now := b.now()
	entry := b.peers[key]
	if entry == nil {
		for oldKey, old := range b.peers {
			// Discard only a fully refilled idle bucket. Resetting a bucket
			// with remaining rate debt would grant an extra burst on revisit.
			elapsed := now.Sub(old.last)
			if old.active == 0 && elapsed >= peerBudgetIdle &&
				old.tokens+elapsed.Seconds()*float64(b.rate) >= float64(b.burst) {
				delete(b.peers, oldKey)
			}
		}
		if len(b.peers) >= maxPeerBudgetEntries {
			return nil, false
		}
		entry = &peerBudget{tokens: float64(b.burst), last: now}
		b.peers[key] = entry
	}
	if elapsed := now.Sub(entry.last).Seconds(); elapsed > 0 {
		entry.tokens = min(float64(b.burst), entry.tokens+elapsed*float64(b.rate))
		entry.last = now
	}
	if entry.active >= b.peerLimit || entry.tokens < 1 {
		return nil, false
	}
	entry.active++
	entry.tokens--
	var once sync.Once
	return func() {
		once.Do(func() {
			b.mu.Lock()
			defer b.mu.Unlock()
			entry.active--
			now := b.now()
			if elapsed := now.Sub(entry.last).Seconds(); elapsed > 0 {
				entry.tokens = min(float64(b.burst), entry.tokens+elapsed*float64(b.rate))
				entry.last = now
			}
		})
	}, true
}
