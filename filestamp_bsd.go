//go:build darwin || freebsd || netbsd

package identity

import (
	"os"
	"syscall"
)

// changeTimes is the stat change time and birth time.
func changeTimes(_ *os.File, st *syscall.Stat_t) (changed, born int64) {
	return nanos(int64(st.Ctimespec.Sec), int64(st.Ctimespec.Nsec)),
		nanos(int64(st.Birthtimespec.Sec), int64(st.Birthtimespec.Nsec))
}
