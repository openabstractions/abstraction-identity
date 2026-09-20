//go:build linux

package identity

import (
	"encoding/binary"
	"fmt"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/sys/unix"
)

// The Linux loopback binding reads the socket-owner records procfs keeps.
//
// /proc/net/tcp lists each IPv4 TCP socket with its four-tuple, state, owning
// uid and inode. The uid is the credential the kernel attached to the socket
// when it was created, and no later holder changes it. The process is not
// recorded anywhere: a socket is an open file, and the only way to learn which
// process holds it is to read every same-uid process's descriptor table for a
// link to socket:[inode]. Descriptors of other users cannot be read, and a
// socket owned by another uid is refused before that question arises.
//
// That scan answers a question about numbers, so the binding pins the one
// holder it finds with pidfd_open, reads its descriptor table again behind the
// pin and captures its image path. A socket held by more than one process is
// refused, because a descriptor that has been passed or inherited names no
// single program; so is a socket whose holder later changes, or whose holder
// exec's another image.

type loopbackLinuxBinding struct {
	client, server netip.AddrPort
	inode          uint64
	uid            int
	pidfd          int
	pid            int
	exe            string
}

var pidfdOpenSupport = sync.OnceValues(func() (bool, string) {
	fd, err := unix.PidfdOpen(os.Getpid(), 0)
	if err != nil {
		return false, "pidfd_open is unavailable on this kernel (" + err.Error() + "); it needs Linux 5.3, and without it a scanned pid cannot be pinned"
	}
	unix.Close(fd)
	return true, ""
})

func loopbackCeiling() Limits {
	ok, why := pidfdOpenSupport()
	binding := "/proc/net/tcp names the client socket's inode and owning uid; the one same-uid process whose descriptor table holds that inode is pinned with pidfd_open and its image path captured, and a socket held by two processes, or later by another, is refused as moved"
	path := ProofBound
	if !ok {
		binding = why + ", so this machine cannot bind a loopback peer"
		path = ProofNone
	}
	return Limits{
		Platform:  "linux",
		Transport: TransportLoopback,
		Bindable:  ok,
		Binding:   binding,
		Stronger:  "unix: SO_PEERCRED and SO_PEERPIDFD are stamped onto the connection itself, so the process needs no scan",
		Best: Need{
			User:    ProofKernel,
			Process: path,
			Path:    path,
			Package: path,
			Code:    ProofNone,
		},
		Why: map[string]string{
			"user":    "the uid /proc/net/tcp reports is the credential the kernel attached to the socket when it was created",
			"process": "found by scanning same-uid descriptor tables for the socket inode, then pinned with pidfd_open and scanned again behind the pin",
			"path":    "/proc/<pid>/exe read behind the pidfd; a path is a name, not an identity",
			"package": "a sandbox application id read behind the pidfd; " + whyPackageAdvisory,
			"code":    whyNoCode,
		},
	}
}

type tcpRow struct {
	established bool
	uid         int
	inode       uint64
}

// procAddr parses the %08X:%04X form /proc/net/tcp prints: the IPv4 address as
// the host-order integer of its network-order bytes, and the port in host order.
func procAddr(s string) (netip.AddrPort, bool) {
	host, port, ok := strings.Cut(s, ":")
	if !ok || len(host) != 8 {
		return netip.AddrPort{}, false
	}
	a, err := strconv.ParseUint(host, 16, 32)
	if err != nil {
		return netip.AddrPort{}, false
	}
	p, err := strconv.ParseUint(port, 16, 16)
	if err != nil {
		return netip.AddrPort{}, false
	}
	var b [4]byte
	binary.NativeEndian.PutUint32(b[:], uint32(a))
	return netip.AddrPortFrom(netip.AddrFrom4(b), uint16(p)), true
}

// socketRow finds the row whose local end is client and remote end is server.
func socketRow(client, server netip.AddrPort) (tcpRow, bool, error) {
	data, err := os.ReadFile("/proc/self/net/tcp")
	if err != nil {
		return tcpRow{}, false, err
	}
	for _, line := range strings.Split(string(data), "\n")[1:] {
		f := strings.Fields(line)
		if len(f) < 10 {
			continue
		}
		local, ok1 := procAddr(f[1])
		remote, ok2 := procAddr(f[2])
		if !ok1 || !ok2 || local != client || remote != server {
			continue
		}
		state, _ := strconv.ParseUint(f[3], 16, 8)
		uid, err1 := strconv.Atoi(f[7])
		inode, err2 := strconv.ParseUint(f[9], 10, 64)
		if err1 != nil || err2 != nil {
			return tcpRow{}, false, fmt.Errorf("/proc/net/tcp row for %s is not in the expected form", client)
		}
		return tcpRow{established: state == 1, uid: uid, inode: inode}, true, nil
	}
	return tcpRow{}, false, nil
}

// holds reports whether pid's descriptor table has a link to the socket inode.
func holds(pid int, link string) bool {
	dir := "/proc/" + itoa(pid) + "/fd"
	entries, err := os.ReadDir(dir)
	if err != nil {
		return false
	}
	for _, e := range entries {
		if target, err := os.Readlink(dir + "/" + e.Name()); err == nil && target == link {
			return true
		}
	}
	return false
}

// holders lists the processes of uid whose descriptor tables hold the socket.
func holders(inode uint64, uid int) ([]int, error) {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil, err
	}
	link := "socket:[" + strconv.FormatUint(inode, 10) + "]"
	var out []int
	for _, e := range entries {
		pid, err := strconv.Atoi(e.Name())
		if err != nil || pid <= 0 {
			continue
		}
		var st unix.Stat_t
		if unix.Stat("/proc/"+e.Name(), &st) != nil || int(st.Uid) != uid {
			continue
		}
		if holds(pid, link) {
			out = append(out, pid)
		}
	}
	return out, nil
}

func bindLoopback(client, server netip.AddrPort, opts *Options) (binder, *Peer, error) {
	if ok, why := pidfdOpenSupport(); !ok {
		return nil, nil, fmt.Errorf("%w: %s", ErrNoBinding, why)
	}
	row, found, err := socketRow(client, server)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: /proc/net/tcp: %v", ErrNoBinding, err)
	}
	if !found {
		return nil, nil, fmt.Errorf("%w: /proc/net/tcp has no row for %s -> %s", ErrPeerGone, client, server)
	}
	if row.uid != os.Getuid() {
		return nil, nil, fmt.Errorf("%w: the client socket belongs to uid %d; only same-uid descriptor tables can be read", ErrNoBinding, row.uid)
	}
	pids, err := holders(row.inode, row.uid)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: scanning /proc: %v", ErrNoBinding, err)
	}
	switch {
	case len(pids) == 0:
		return nil, nil, fmt.Errorf("%w: no process of uid %d holds the client socket", ErrPeerGone, row.uid)
	case len(pids) > 1:
		return nil, nil, fmt.Errorf("%w: processes %v all hold the client socket; a passed or inherited socket names no single program", ErrPeerMoved, pids)
	}
	pid := pids[0]
	pidfd, err := unix.PidfdOpen(pid, 0)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: pidfd_open(%d): %v", ErrPeerGone, pid, err)
	}
	b := &loopbackLinuxBinding{client: client, server: server, inode: row.inode, uid: row.uid, pidfd: pidfd, pid: pid}
	fail := func(err error) (binder, *Peer, error) { b.release(); return nil, nil, err }
	// Behind the pin, the number names the process the scan found or nothing.
	if live, err := pidfdAlive(pidfd, pid); err != nil || !live {
		return fail(fmt.Errorf("%w: pid %d exited while it was being pinned", ErrPeerGone, pid))
	}
	if !holds(pid, "socket:["+strconv.FormatUint(row.inode, 10)+"]") {
		return fail(fmt.Errorf("%w: pid %d no longer holds the client socket once pinned", ErrPeerMoved, pid))
	}
	exe, deleted, err := processExe(pid)
	if err != nil {
		return fail(fmt.Errorf("%w: /proc/%d/exe: %v", ErrPeerGone, pid, err))
	}
	b.exe = exe
	started, startErr := processStartTime(pid)
	if connectedAt := opts.connectedAt(); startErr == nil && started.After(connectedAt.Add(startTimeSlop)) {
		return fail(fmt.Errorf("%w: pid %d started at %s, after this connection existed at %s", ErrPeerMoved, pid, started.Format(time.RFC3339Nano), connectedAt.Format(time.RFC3339Nano)))
	}
	if err := b.recheck(); err != nil {
		return fail(err)
	}
	p := &Peer{Platform: "linux", Transport: TransportLoopback, ObservedAt: time.Now(), Code: unknown[Code]("code", whyNoCode)}
	user := User{Kind: "posix", UID: row.uid, GID: -1}
	var st unix.Stat_t
	if unix.Stat("/proc/"+itoa(pid), &st) == nil {
		user.GID = int(st.Gid)
	}
	p.User = attr("user", user, ProofKernel, "the uid /proc/net/tcp reports is the credential the kernel attached to the socket when it was created; the gid is the pinned holder's")
	p.Process = attr("process", Process{PID: pid, StartTime: started}, ProofBound,
		"the one same-uid process whose descriptor table holds the client socket, pinned with pidfd_open and scanned again behind the pin")
	if deleted {
		p.Path = attr("path", exe, ProofPID, "the peer's executable has been unlinked since it started, so this path no longer refers to the file it is running")
	} else {
		p.Path = attr("path", exe, ProofBound, "read behind the pidfd; a path is a name, not an identity - see CONTRACT.md")
	}
	if name, why := sandboxPackage(pid); name == "" {
		p.Package = unknown[string]("package", why)
	} else {
		p.Package = attr("package", name, ProofBound, why+"; "+whyPackageAdvisory)
	}
	p.note("transport: a loopback TCP connection carries no credentials; the process came from a descriptor-table scan")
	return b, p, nil
}

func (b *loopbackLinuxBinding) recheck() error {
	row, found, err := socketRow(b.client, b.server)
	if err != nil || !found || !row.established {
		// The connection has closed, which contradicts nothing about who
		// opened it.
		return nil
	}
	if row.inode != b.inode {
		return fmt.Errorf("%w: %s is now socket inode %d; it was %d when the connection was accepted", ErrPeerMoved, b.client, row.inode, b.inode)
	}
	pids, err := holders(b.inode, b.uid)
	if err != nil {
		return nil
	}
	if len(pids) != 1 || pids[0] != b.pid {
		return fmt.Errorf("%w: the client socket is now held by %v; it was held by pid %d alone when the connection was accepted", ErrPeerMoved, pids, b.pid)
	}
	if exe, _, err := processExe(b.pid); err == nil && exe != b.exe {
		return fmt.Errorf("%w: pid %d was %s when this connection was accepted and is %s now", ErrPeerMoved, b.pid, strconvQuote(b.exe), strconvQuote(exe))
	}
	return nil
}

func (b *loopbackLinuxBinding) alive() (bool, error) { return pidfdAlive(b.pidfd, b.pid) }

func (b *loopbackLinuxBinding) release() error {
	if b.pidfd < 0 {
		return nil
	}
	err := unix.Close(b.pidfd)
	b.pidfd = -1
	return err
}
