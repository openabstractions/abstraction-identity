//go:build linux

package identity

import (
	"errors"
	"strconv"
	"strings"
	"testing"
)

func TestEmptyHolderRescanDistinguishesTeardownFromMovedConnection(t *testing.T) {
	// These are second observations after an established captured inode and a
	// descriptor scan with no holder. TIME_WAIT has no live descriptor inode.
	// State and inode columns follow the kernel's documented /proc/net/tcp row.
	tests := []struct {
		name, raw     string
		closed, moved bool
	}{
		{"missing row", "", true, false},
		{"TIME_WAIT zero inode", "0: 0100007F:AD53 0100007F:CCFE 06 00000000:00000000 03:00000019 00000000 1000 0 0", true, false},
		{"FIN_WAIT zero inode", "0: 0100007F:AD53 0100007F:CCFE 05 00000000:00000000 00:00000000 00000000 1000 0 0", true, false},
		{"closing row retains inode", "0: 0100007F:AD53 0100007F:CCFE 08 00000000:00000000 00:00000000 00000000 1000 0 183913", true, false},
		{"established zero inode", "0: 0100007F:AD53 0100007F:CCFE 01 00000000:00000000 00:00000000 00000000 1000 0 0", false, true},
		{"established replacement inode", "0: 0100007F:AD53 0100007F:CCFE 01 00000000:00000000 00:00000000 00000000 1000 0 183914", false, true},
		{"established same inode lacks holder", "0: 0100007F:AD53 0100007F:CCFE 01 00000000:00000000 00:00000000 00000000 1000 0 183913", false, false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var row tcpRow
			found := test.raw != ""
			if found {
				fields := strings.Fields(test.raw)
				state, err := strconv.ParseUint(fields[3], 16, 8)
				if err != nil {
					t.Fatal(err)
				}
				inode, err := strconv.ParseUint(fields[9], 10, 64)
				if err != nil {
					t.Fatal(err)
				}
				row = tcpRow{established: state == 1, inode: inode}
			}
			binding := &loopbackLinuxBinding{inode: 183913}
			closed, err := binding.emptyHolderRescan(row, found)
			if closed != test.closed || errors.Is(err, ErrPeerMoved) != test.moved {
				t.Fatalf("second observation %q: closed=%v, err=%v; want closed=%v moved=%v", test.raw, closed, err, test.closed, test.moved)
			}
		})
	}
}
