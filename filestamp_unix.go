//go:build unix

package identity

import (
	"fmt"
	"os"
	"syscall"
)

// readStampInputs reads f's stamp from the fstat of its descriptor (info is
// f.Stat()): device and inode, size, modification time, and the change and
// birth times changeTimes reads for this platform. Only a change of the
// system clock sets a change time back.
func readStampInputs(f *os.File, info os.FileInfo) (stampInputs, error) {
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return stampInputs{}, fmt.Errorf("identity: %s has no device and inode", f.Name())
	}
	changed, born := changeTimes(f, st)
	return stampInputs{
		identity: fmt.Sprintf("%x-%x", uint64(st.Dev), uint64(st.Ino)),
		size:     info.Size(),
		modified: info.ModTime().UnixNano(),
		changed:  changed,
		born:     born,
	}, nil
}

// nanos is a timespec's seconds and nanoseconds as nanoseconds.
func nanos(sec, nsec int64) int64 { return sec*1e9 + nsec }
