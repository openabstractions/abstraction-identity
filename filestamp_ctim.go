//go:build unix && !linux && !darwin && !freebsd && !netbsd

package identity

import (
	"os"
	"syscall"
)

// changeTimes is the stat change time; this read takes no birth time here.
func changeTimes(_ *os.File, st *syscall.Stat_t) (changed, born int64) {
	return nanos(int64(st.Ctim.Sec), int64(st.Ctim.Nsec)), 0
}
