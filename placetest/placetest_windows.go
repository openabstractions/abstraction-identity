package placetest

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"golang.org/x/sys/windows"
)

// ShortName returns the 8.3 spelling of an existing path, or an error when
// the volume keeps no short names for it.
func ShortName(path string) (string, error) {
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return "", err
	}
	buf := make([]uint16, windows.MAX_LONG_PATH)
	n, err := windows.GetShortPathName(p, &buf[0], uint32(len(buf)))
	if err != nil {
		return "", err
	}
	short := windows.UTF16ToString(buf[:n])
	if short == path {
		return "", errors.New("placetest: the volume gives no 8.3 alias (8.3 generation off)")
	}
	return short, nil
}

// LongPath returns the long spelling of an existing path.
func LongPath(path string) (string, error) {
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return "", err
	}
	buf := make([]uint16, windows.MAX_LONG_PATH)
	n, err := windows.GetLongPathName(p, &buf[0], uint32(len(buf)))
	if err != nil {
		return "", err
	}
	return windows.UTF16ToString(buf[:n]), nil
}

// SameSID compares two SIDs, each given as a string SID or an SDDL alias such
// as LA, by their binary form.
func SameSID(a, b string) (bool, error) {
	sa, err := windows.StringToSid(a)
	if err != nil {
		return false, fmt.Errorf("placetest: SID %q: %w", a, err)
	}
	sb, err := windows.StringToSid(b)
	if err != nil {
		return false, fmt.Errorf("placetest: SID %q: %w", b, err)
	}
	return windows.EqualSid(sa, sb), nil
}

// MachineAdministratorSID returns this machine's RID-500 account SID in its
// string form, built from the machine's account-domain SID, which
// LookupAccountName gives for the computer's own name. A domain account's
// prefix names the domain, whose RID 500 is the domain administrator.
func MachineAdministratorSID() (string, error) {
	name, err := windows.ComputerName()
	if err != nil {
		return "", err
	}
	sid, _, kind, err := windows.LookupSID("", name)
	if err != nil {
		return "", fmt.Errorf("placetest: account domain of %s: %w", name, err)
	}
	s := sid.String()
	if kind != windows.SidTypeDomain || !strings.HasPrefix(s, "S-1-5-21-") {
		return "", fmt.Errorf("placetest: %s names %s, which is not a machine account domain", name, s)
	}
	return s + "-500", nil
}

// allowUnprivilegedCreate is SYMBOLIC_LINK_FLAG_ALLOW_UNPRIVILEGED_CREATE,
// which golang.org/x/sys/windows does not name.
const allowUnprivilegedCreate = 0x2

// FolderSymlink makes link a symbolic link to the folder target without
// opening target: os.Symlink stats its target to choose the folder flag, and
// a share target would be opened over SMB before the link exists.
func FolderSymlink(link, target string) error {
	l, err := windows.UTF16PtrFromString(link)
	if err != nil {
		return err
	}
	t, err := windows.UTF16PtrFromString(target)
	if err != nil {
		return err
	}
	if err := windows.CreateSymbolicLink(l, t, windows.SYMBOLIC_LINK_FLAG_DIRECTORY|allowUnprivilegedCreate); err != nil {
		return &os.LinkError{Op: "symlink", Old: target, New: link, Err: err}
	}
	return nil
}

// fsctlSetReparsePoint is FSCTL_SET_REPARSE_POINT, which
// golang.org/x/sys/windows does not name.
const fsctlSetReparsePoint = 0x000900A4

// ShareJunction makes link a new folder carrying a junction (a mount-point
// reparse point) whose target is the share TestNetShare("", false) names.
// mklink /J refuses a share target; the reparse data is written directly,
// which reads nothing at the target, so making the fixture contacts no host.
func ShareJunction(link string) error {
	return MountPoint(link, `\??\UNC\`+TestNetHost+`\share\`, TestNetShare("", false))
}

// MountPoint makes link a new folder carrying a mount-point reparse point
// whose substitute name is substituteName, an NT path such as
// `\??\Volume{GUID}\folder\`, and whose print name is printName. The
// reparse data is written directly, which reads nothing at the target and
// needs no privilege on a folder this account owns.
func MountPoint(link, substituteName, printName string) error {
	if err := os.Mkdir(link, 0o755); err != nil {
		return err
	}
	substitute := utf16Of(substituteName)
	printed := utf16Of(printName)
	var path []uint16
	path = append(path, substitute...)
	path = append(path, 0)
	path = append(path, printed...)
	path = append(path, 0)
	buf := make([]byte, 16+2*len(path))
	le := func(off int, v uint16) { buf[off], buf[off+1] = byte(v), byte(v>>8) }
	tag := uint32(windows.IO_REPARSE_TAG_MOUNT_POINT)
	buf[0], buf[1], buf[2], buf[3] = byte(tag), byte(tag>>8), byte(tag>>16), byte(tag>>24)
	le(4, uint16(8+2*len(path)))
	le(8, 0)
	le(10, uint16(2*len(substitute)))
	le(12, uint16(2*(len(substitute)+1)))
	le(14, uint16(2*len(printed)))
	for i, u := range path {
		le(16+2*i, u)
	}
	p, err := windows.UTF16PtrFromString(link)
	if err != nil {
		return err
	}
	h, err := windows.CreateFile(p, windows.GENERIC_WRITE, 0, nil, windows.OPEN_EXISTING,
		windows.FILE_FLAG_OPEN_REPARSE_POINT|windows.FILE_FLAG_BACKUP_SEMANTICS, 0)
	if err != nil {
		return err
	}
	defer windows.CloseHandle(h)
	var n uint32
	if err := windows.DeviceIoControl(h, fsctlSetReparsePoint, &buf[0], uint32(len(buf)), nil, 0, &n, nil); err != nil {
		return fmt.Errorf("placetest: set the mount point: %w", err)
	}
	return nil
}

// VolumeMountPoint makes link a mount point to target, an existing absolute
// folder, spelled through target's volume named by GUID
// (`\??\Volume{GUID}\folder\`), the reparse data a volume mounted in a folder
// carries (a Dev Drive or a VHD without a letter). It names a volume this
// machine already has, so it needs no administrator rights. It returns the
// volume's GUID root, `\\?\Volume{GUID}\`.
func VolumeMountPoint(link, target string) (string, error) {
	root := filepath.VolumeName(target) + `\`
	p, err := windows.UTF16PtrFromString(root)
	if err != nil {
		return "", err
	}
	buf := make([]uint16, windows.MAX_PATH)
	if err := windows.GetVolumeNameForVolumeMountPoint(p, &buf[0], uint32(len(buf))); err != nil {
		return "", fmt.Errorf("placetest: the volume of %s has no GUID name: %w", target, err)
	}
	guid := windows.UTF16ToString(buf)
	rel := strings.TrimPrefix(target, root)
	return guid, MountPoint(link, `\??\`+strings.TrimPrefix(guid, `\\?\`)+rel+`\`, guid+rel)
}

func utf16Of(s string) []uint16 {
	u, _ := windows.UTF16FromString(s)
	return u[:len(u)-1]
}

// Junction makes link a directory junction to target.
func Junction(link, target string) error {
	out, err := exec.Command("cmd", "/c", "mklink", "/J", link, target).CombinedOutput()
	if err != nil {
		return fmt.Errorf("mklink /J: %v: %s", err, out)
	}
	return nil
}

// CaseSensitive marks an empty folder case-sensitive.
func CaseSensitive(dir string) error {
	out, err := exec.Command("fsutil", "file", "setCaseSensitiveInfo", dir, "enable").CombinedOutput()
	if err != nil {
		return fmt.Errorf("fsutil setCaseSensitiveInfo: %v: %s", err, out)
	}
	return nil
}

// Compact WOF-compresses one file.
func Compact(file string) error {
	out, err := exec.Command("compact", "/c", "/exe:xpress4k", file).CombinedOutput()
	if err != nil {
		return fmt.Errorf("compact /exe: %v: %s", err, out)
	}
	return nil
}

// TestNetShare spells a path on a share of TestNetHost, the reserved
// documentation address no machine answers on (RFC 5737), and extended
// selects the extended UNC form. A fixture spells a share with it so that a
// refusal that comes too late reaches no real host: no test contacts this
// machine's own shares, the NAS or any other one.
func TestNetShare(rest string, extended bool) string {
	rest = strings.TrimLeft(strings.ReplaceAll(rest, "/", `\`), `\`)
	if extended {
		return `\\?\UNC\` + TestNetHost + `\share\` + rest
	}
	return `\\` + TestNetHost + `\share\` + rest
}
