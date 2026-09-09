//go:build linux

package identity

// Everything this package reads out of /proc, and the reasons each read is
// worth what it is worth.
//
// The rule the rest of the file obeys: /proc is addressed by number. A read
// from /proc/<pid>/... is a question about whoever holds that number at the
// instant of the read, which is only the peer if something is holding the
// number still. On this platform the only thing that does is a pidfd.

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/sys/unix"
)

// pidfdAlive reports whether the pidfd the kernel handed out for this
// connection still names a running process, and that it is the pid SO_PEERCRED
// reported.
//
// /proc/self/fdinfo/<pidfd> carries a Pid line maintained by the kernel: the
// pid the fd refers to, or a non-positive value once the process has been
// reaped. Reading it is how this package observes, rather than assumes, that
// the pin is intact.
//
// A disagreement between that line and SO_PEERCRED is not a weak answer, it is
// an impossible one, and it is returned as an error rather than resolved in
// either direction.
func pidfdAlive(pidfd, want int) (bool, error) {
	name := "/proc/self/fdinfo/" + itoa(pidfd)
	b, err := os.ReadFile(name)
	if err != nil {
		return false, fmt.Errorf("%s: %w", name, err)
	}
	got, ok := fieldInt(string(b), "Pid:")
	if !ok {
		return false, fmt.Errorf("%s: %w", name, errNoPidfdInfo)
	}
	if got <= 0 {
		return false, nil // exited and reaped; the number is being held, nothing else is
	}
	if got != want {
		return false, fmt.Errorf("the pidfd for this connection names pid %d but SO_PEERCRED named pid %d", got, want)
	}
	return true, nil
}

var errNoPidfdInfo = errors.New("no Pid line: this is not a pidfd, or the kernel does not report one")

// processExe reads /proc/<pid>/exe. The second result is true when the kernel
// marked the target as deleted, which means the file the peer is executing is
// no longer reachable at the name being reported.
func processExe(pid int) (string, bool, error) {
	link, err := os.Readlink("/proc/" + itoa(pid) + "/exe")
	if err != nil {
		return "", false, err
	}
	if s, ok := strings.CutSuffix(link, " (deleted)"); ok {
		return s, true, nil
	}
	return link, false, nil
}

// processStartTime converts field 22 of /proc/<pid>/stat - the process start
// time, in clock ticks since boot - into a wall clock instant.
//
// The conversion is approximate and cannot be made otherwise: /proc/uptime is
// read afterwards rather than atomically with the stat file, its resolution is
// 10ms, and the tick rate is an ABI constant taken from the auxiliary vector.
// Callers must use the result only to refuse, never to promote a proof. See
// startTimeSlop.
func processStartTime(pid int) (time.Time, error) {
	stat, err := os.ReadFile("/proc/" + itoa(pid) + "/stat")
	if err != nil {
		return time.Time{}, err
	}
	// The second field is the executable name in parentheses and may
	// contain both spaces and close-parens, so the fields after it can only
	// be found from the last close-paren in the line.
	s := string(stat)
	i := strings.LastIndexByte(s, ')')
	if i < 0 {
		return time.Time{}, errors.New("/proc/<pid>/stat is not in the expected form")
	}
	fields := strings.Fields(s[i+1:])
	// Field 3 (state) is the first one after the parenthesis, so field 22
	// is index 19 here.
	const starttimeIndex = 19
	if len(fields) <= starttimeIndex {
		return time.Time{}, errors.New("/proc/<pid>/stat has too few fields for a start time")
	}
	ticks, err := strconv.ParseInt(fields[starttimeIndex], 10, 64)
	if err != nil {
		return time.Time{}, err
	}
	up, err := uptime()
	if err != nil {
		return time.Time{}, err
	}
	age := up - time.Duration(float64(ticks)/float64(clockTicks())*float64(time.Second))
	return time.Now().Add(-age), nil
}

func uptime() (time.Duration, error) {
	b, err := os.ReadFile("/proc/uptime")
	if err != nil {
		return 0, err
	}
	fields := strings.Fields(string(b))
	if len(fields) == 0 {
		return 0, errors.New("/proc/uptime is empty")
	}
	secs, err := strconv.ParseFloat(fields[0], 64)
	if err != nil {
		return 0, err
	}
	return time.Duration(secs * float64(time.Second)), nil
}

// clockTicks is USER_HZ: the unit /proc/<pid>/stat counts in. It is 100 on
// every architecture this package is likely to run on, but it is an ABI
// constant rather than a law, and the auxiliary vector carries the real one.
var clockTicks = sync.OnceValue(func() int64 {
	const atClkTck = 17 // AT_CLKTCK, linux/auxvec.h
	if av, err := unix.Auxv(); err == nil {
		for _, kv := range av {
			if kv[0] == atClkTck && kv[1] > 0 {
				return int64(kv[1])
			}
		}
	}
	return 100
})

// sandboxPackage names the sandboxed application the peer belongs to, if any,
// and always explains itself.
//
// Read the second result before believing the first. Neither source is a
// statement by the kernel about what the peer *is*:
//
//   - Flatpak: /proc/<pid>/root/.flatpak-info is a file inside the peer's own
//     mount namespace. bubblewrap mounts it read-only and an ordinary sandboxed
//     app cannot rewrite it, which is why the desktop portals use it - but it
//     is still a file in a namespace the peer's own sandbox constructed, not a
//     kernel record, and a process able to build its own namespace can present
//     whatever it likes there.
//   - Snap: the cgroup path carries snap.<instance>.<app>. Under cgroup v2 with
//     systemd user delegation, a process running as that user can create
//     cgroups with names of its choosing and migrate itself into them.
//
// So this answers "what does the peer's sandbox say it is", which is useful
// for a log line and for telling two cooperating apps apart, and is not a
// defence against a hostile process running as the same user.
//
// One more edge, for completeness: a process in no namespace at all has
// /proc/<pid>/root pointing at /, so a file called /.flatpak-info on the host
// would make every peer look like a Flatpak app. Creating it needs root, which
// is a bigger problem than this function - but it is the reason the result is
// prefixed and reported with its provenance rather than as a bare id.
func sandboxPackage(pid int) (string, string) {
	root := "/proc/" + itoa(pid)

	if b, err := os.ReadFile(root + "/root/.flatpak-info"); err == nil {
		if app := iniValue(string(b), "Application", "name"); app != "" {
			return "flatpak:" + app,
				"read from .flatpak-info inside the peer's own mount namespace, which bubblewrap mounts read-only"
		}
		return "flatpak:", "the peer is in a Flatpak sandbox whose .flatpak-info names no application"
	}
	// An unreadable or absent .flatpak-info is not an answer either way. The
	// cgroup below may still be one.

	if b, err := os.ReadFile(root + "/cgroup"); err == nil {
		if id := snapFromCgroup(string(b)); id != "" {
			return "snap:" + id,
				"read from the peer's cgroup path, which snapd sets at launch"
		}
		if strings.Contains(string(b), "firejail") {
			return "firejail:",
				"the peer's cgroup names firejail, which does not carry an application id"
		}
	}

	return "", "the peer is not in a sandbox this package can recognise (Flatpak, Snap or Firejail); Linux has no general answer to what a process is - see CONTRACT.md"
}

// snapFromCgroup finds snap.<instance>.<app> in a cgroup file and returns
// "<instance>.<app>".
func snapFromCgroup(s string) string {
	for _, line := range strings.Split(s, "\n") {
		i := strings.Index(line, "snap.")
		if i < 0 {
			continue
		}
		rest := line[i+len("snap."):]
		// snap.<instance>.<app>.<scope-or-service>.scope
		if j := strings.IndexAny(rest, "/"); j >= 0 {
			rest = rest[:j]
		}
		rest = strings.TrimSuffix(rest, ".scope")
		rest = strings.TrimSuffix(rest, ".service")
		parts := strings.Split(rest, ".")
		if len(parts) >= 2 {
			return parts[0] + "." + parts[1]
		}
	}
	return ""
}

// iniValue reads key from section out of a .desktop/.ini style file. It is
// deliberately small: .flatpak-info is generated by Flatpak, not by a user.
func iniValue(s, section, key string) string {
	in := false
	for _, line := range strings.Split(s, "\n") {
		line = strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(line, "["):
			in = line == "["+section+"]"
		case in:
			if k, v, ok := strings.Cut(line, "="); ok && strings.TrimSpace(k) == key {
				return strings.TrimSpace(v)
			}
		}
	}
	return ""
}

// fieldInt reads "<label>\t<n>" out of a /proc text file.
func fieldInt(s, label string) (int, bool) {
	for _, line := range strings.Split(s, "\n") {
		if !strings.HasPrefix(line, label) {
			continue
		}
		n, err := strconv.Atoi(strings.TrimSpace(line[len(label):]))
		if err != nil {
			return 0, false
		}
		return n, true
	}
	return 0, false
}
