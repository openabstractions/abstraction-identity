//go:build linux

package identity

import (
	"os"
	"syscall"

	"golang.org/x/sys/unix"
)

// changeTimes is st_ctim and, where the kernel and file system report one,
// the birth time statx reads from f's descriptor (0 elsewhere).
func changeTimes(f *os.File, st *syscall.Stat_t) (changed, born int64) {
	return nanos(int64(st.Ctim.Sec), int64(st.Ctim.Nsec)), birthTime(f)
}

// birthTime is statx's STATX_BTIME for f's descriptor, and 0 when the
// kernel or file system does not report it.
func birthTime(f *os.File) int64 {
	conn, err := f.SyscallConn()
	if err != nil {
		return 0
	}
	var stx unix.Statx_t
	var statErr error = unix.ENOSYS
	if err := conn.Control(func(fd uintptr) {
		statErr = unix.Statx(int(fd), "", unix.AT_EMPTY_PATH|unix.AT_STATX_SYNC_AS_STAT, unix.STATX_BTIME, &stx)
	}); err != nil || statErr != nil || stx.Mask&unix.STATX_BTIME == 0 {
		return 0
	}
	return nanos(stx.Btime.Sec, int64(stx.Btime.Nsec))
}
