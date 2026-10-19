package identity

import (
	"encoding/binary"
	"fmt"
	"io"
)

type sealedResourceArchitecture struct {
	cpu, sub     uint32
	offset, size uint64
}

// Only the finite architecture directory and each fixed executable header are
// read. No load commands, symbols or untrusted debug allocations are loaded.
func sealedResourceArchitectures(r io.ReaderAt, size int64) ([]sealedResourceArchitecture, error) {
	bad := func() ([]sealedResourceArchitecture, error) {
		return nil, fmt.Errorf("%w: unsupported native executable architecture directory", ErrNotProven)
	}
	read := func(off int64, n int) ([]byte, error) {
		if off < 0 || size < off || int64(n) > size-off {
			return nil, io.ErrUnexpectedEOF
		}
		b := make([]byte, n)
		_, err := r.ReadAt(b, off)
		return b, err
	}
	h, err := read(0, 8)
	if err != nil {
		return bad()
	}
	native := func(b []byte) bool {
		return binary.LittleEndian.Uint32(b) == 0xfeedfacf && (binary.LittleEndian.Uint32(b[4:]) == 0x01000007 || binary.LittleEndian.Uint32(b[4:]) == 0x0100000c) && binary.LittleEndian.Uint32(b[12:]) == 2 && binary.LittleEndian.Uint32(b[28:]) == 0
	}
	magic := binary.BigEndian.Uint32(h)
	if magic == 0xcffaedfe {
		b, e := read(0, 32)
		if e != nil || !native(b) {
			return bad()
		}
		return []sealedResourceArchitecture{{binary.LittleEndian.Uint32(b[4:]), binary.LittleEndian.Uint32(b[8:]), 0, uint64(size)}}, nil
	}
	var order binary.ByteOrder = binary.BigEndian
	wide := magic == 0xcafebabf || magic == 0xbfbafeca
	if magic == 0xbebafeca || magic == 0xbfbafeca {
		order = binary.LittleEndian
	} else if magic != 0xcafebabe && magic != 0xcafebabf {
		return bad()
	}
	count := uint64(order.Uint32(h[4:]))
	entry := uint64(20)
	if wide {
		entry = 32
	}
	if count < 1 || count > 16 {
		return bad()
	}
	table, err := read(8, int(count*entry))
	if err != nil {
		return bad()
	}
	var answer []sealedResourceArchitecture
	seen := map[[2]uint32]bool{}
	for i := uint64(0); i < count; i++ {
		a := table[i*entry : (i+1)*entry]
		cpu, sub := order.Uint32(a), order.Uint32(a[4:])
		off, n, align := uint64(order.Uint32(a[8:])), uint64(order.Uint32(a[12:])), order.Uint32(a[16:])
		if wide {
			off, n, align = order.Uint64(a[8:]), order.Uint64(a[16:]), order.Uint32(a[24:])
			if order.Uint32(a[28:]) != 0 {
				return bad()
			}
		}
		key := [2]uint32{cpu, sub}
		if (cpu != 0x01000007 && cpu != 0x0100000c) || seen[key] || align > 31 || off%(uint64(1)<<align) != 0 || off < 8+count*entry || off > uint64(size) || n < 32 || n > uint64(size)-off {
			return bad()
		}
		for _, old := range answer {
			if off < old.offset+old.size && old.offset < off+n {
				return bad()
			}
		}
		b, e := read(int64(off), 32)
		if e != nil || !native(b) || binary.LittleEndian.Uint32(b[4:]) != cpu || binary.LittleEndian.Uint32(b[8:]) != sub {
			return bad()
		}
		seen[key] = true
		answer = append(answer, sealedResourceArchitecture{cpu, sub, off, n})
	}
	return answer, nil
}
