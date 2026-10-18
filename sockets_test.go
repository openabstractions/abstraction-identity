package identity

import (
	"encoding/binary"
	"errors"
	"net/netip"
	"slices"
	"testing"
)

// ownerRow lays out one row the way iphlpapi returns it.
func ownerRow(layout ownerTableLayout, addr netip.Addr, port uint16, pid uint32) []byte {
	row := make([]byte, layout.rowSize)
	copy(row[layout.addrAt:], addr.AsSlice())
	row[layout.portAt], row[layout.portAt+1] = byte(port>>8), byte(port)
	binary.LittleEndian.PutUint32(row[layout.pidAt:], pid)
	return row
}

func ownerTableBytes(rows ...[]byte) []byte {
	buf := binary.LittleEndian.AppendUint32(nil, uint32(len(rows)))
	for _, row := range rows {
		buf = append(buf, row...)
	}
	return buf
}

func TestParseOwnerTables(t *testing.T) {
	loop4, any4 := netip.MustParseAddr("127.0.0.1"), netip.MustParseAddr("0.0.0.0")
	loop6, any6 := netip.MustParseAddr("::1"), netip.MustParseAddr("::")
	for _, c := range []struct {
		layout ownerTableLayout
		addr   netip.Addr
	}{{tcp4OwnerLayout, loop4}, {tcp4OwnerLayout, any4}, {tcp6OwnerLayout, loop6}, {tcp6OwnerLayout, any6}, {udp4OwnerLayout, any4}, {udp6OwnerLayout, loop6}} {
		buf := ownerTableBytes(ownerRow(c.layout, c.addr, 41234, 7001), ownerRow(c.layout, c.addr, 9000, 7002))
		got, err := parseOwnerTable(buf, c.layout)
		if err != nil {
			t.Fatal(err)
		}
		want := []Socket{{c.layout.proto, c.addr, 41234, 7001}, {c.layout.proto, c.addr, 9000, 7002}}
		if !slices.Equal(got, want) {
			t.Fatalf("%s %s parsed as %+v", c.layout.proto, c.addr, got)
		}
		if _, err := parseOwnerTable(buf[:len(buf)-1], c.layout); err == nil {
			t.Fatal("truncated owner table accepted")
		}
	}
	if _, err := parseOwnerTable([]byte{1, 0}, tcp4OwnerLayout); err == nil {
		t.Fatal("table without a count accepted")
	}
}

// TestCheckLoopbackOnly asserts ID-T7's rule on fixture tables.
func TestCheckLoopbackOnly(t *testing.T) {
	const port, ours, child, other = 41234, 100, 101, 900
	owned := func(pid int) bool { return pid == ours || pid == child }
	listener := netip.MustParseAddrPort("127.0.0.1:41234")
	loop4 := netip.MustParseAddr("127.0.0.1")
	own := Socket{"tcp", loop4, port, ours}
	for _, c := range []struct {
		name  string
		table []Socket
		ok    bool
	}{
		{"loopback tree", []Socket{own, {"tcp", loop4, 9000, ours}, {"tcp", loop4, 51000, child}, {"tcp", netip.MustParseAddr("::1"), 9001, ours}}, true},
		{"other process beyond loopback", []Socket{own, {"tcp", netip.MustParseAddr("0.0.0.0"), 445, other}}, true},
		{"tree on every interface", []Socket{own, {"tcp", netip.MustParseAddr("0.0.0.0"), 13305, ours}}, false},
		{"child on a LAN address", []Socket{own, {"tcp", netip.MustParseAddr("192.168.1.20"), 51000, child}}, false},
		{"IPv6 wildcard", []Socket{own, {"tcp", netip.MustParseAddr("::"), 9000, ours}}, false},
		{"UDP broadcast beacon", []Socket{own, {"udp", netip.MustParseAddr("0.0.0.0"), 13305, ours}}, false},
		{"IPv4-mapped wildcard", []Socket{own, {"tcp", netip.MustParseAddr("::ffff:0.0.0.0"), 9000, child}}, false},
		{"own listener absent", []Socket{{"tcp", loop4, 9000, ours}}, false},
		{"own listener only on ::1", []Socket{{"tcp", netip.MustParseAddr("::1"), port, ours}}, false},
		{"own port held by another process", []Socket{{"tcp", loop4, port, other}}, false},
		{"empty table", nil, false},
	} {
		err := CheckLoopbackOnly(c.table, owned, listener)
		if c.ok && err != nil {
			t.Fatalf("%s refused: %v", c.name, err)
		}
		if !c.ok && !errors.Is(err, ErrBeyondLoopback) {
			t.Fatalf("%s accepted: %v", c.name, err)
		}
	}
}
