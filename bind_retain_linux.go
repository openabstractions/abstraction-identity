package identity

import "golang.org/x/sys/unix"

func retainLinuxProcess(fd, pid int, exe string) (binder, error) {
	duplicate, err := unix.FcntlInt(uintptr(fd), unix.F_DUPFD_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	return &linuxBinding{pidfd: duplicate, pid: pid, exe: exe}, nil
}

func (b *linuxBinding) retainProcess() (binder, error) {
	return retainLinuxProcess(b.pidfd, b.pid, b.exe)
}

func (b *loopbackLinuxBinding) retainProcess() (binder, error) {
	return retainLinuxProcess(b.pidfd, b.pid, b.exe)
}
