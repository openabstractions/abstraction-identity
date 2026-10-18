//go:build windows

package privatedir

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"unsafe"

	identity "github.com/openabstractions/abstraction-identity"
	"golang.org/x/sys/windows"
)

func extendedPath(p string) string { return `\\?\` + p }
func plainFinal(raw string) string { return strings.TrimPrefix(raw, `\\?\`) }
func (e *heldEntry) close() error  { return windows.CloseHandle(e.h) }

// The descriptors ProtectModelFolder writes: the folder's own, protected,
// and those of a folder and a file below it, which carry the same three
// entries marked inherited from it.
func folderSDDL(sid string) string {
	return fmt.Sprintf("O:%sD:PAI(A;OICI;FA;;;%s)(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)", sid, sid)
}

func childFolderSDDL(sid string) string {
	return fmt.Sprintf("O:%sD:AI(A;OICIID;FA;;;%s)(A;OICIID;FA;;;SY)(A;OICIID;FA;;;BA)", sid, sid)
}

func childFileSDDL(sid string) string {
	return fmt.Sprintf("O:%sD:AI(A;ID;FA;;;%s)(A;ID;FA;;;SY)(A;ID;FA;;;BA)", sid, sid)
}

// heldEntry is one file or folder opened as itself for its descriptor.
type heldEntry struct {
	path string
	h    windows.Handle
	dir  bool
}

// openEntry opens p as itself, a reparse point included, with the rights to
// read and write its descriptor, sharing read and write but not delete.
// The handle also reads data (a folder's listing), because Windows records
// a share mode only for a handle with data access: with it, while the
// handle is open the entry cannot be renamed, deleted or replaced. A
// reparse point is refused on the handle.
func openEntry(p string) (*heldEntry, windows.ByHandleFileInformation, error) {
	var info windows.ByHandleFileInformation
	name, err := windows.UTF16PtrFromString(extendedPath(p))
	if err != nil {
		return nil, info, err
	}
	h, err := windows.CreateFile(name, windows.FILE_READ_DATA|windows.READ_CONTROL|windows.WRITE_DAC|windows.WRITE_OWNER|windows.FILE_READ_ATTRIBUTES,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE, nil, windows.OPEN_EXISTING,
		windows.FILE_FLAG_OPEN_REPARSE_POINT|windows.FILE_FLAG_BACKUP_SEMANTICS, 0)
	if err != nil {
		return nil, info, err
	}
	e := &heldEntry{path: p, h: h}
	if err := windows.GetFileInformationByHandle(h, &info); err != nil {
		//unchecked: the read failure is the error returned; the handle carries no data access
		e.close()
		return nil, info, err
	}
	if info.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		//unchecked: the refusal is the error returned; the handle carries no data access
		e.close()
		return nil, info, fmt.Errorf("%s is a link or junction", p)
	}
	e.dir = info.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY != 0
	return e, info, nil
}

var (
	kernel32               = windows.NewLazySystemDLL("kernel32.dll")
	procFindFirstFileNameW = kernel32.NewProc("FindFirstFileNameW")
	procFindNextFileNameW  = kernel32.NewProc("FindNextFileNameW")
)

// linkNames is every name of the file at p (FindFirstFileNameW and
// FindNextFileNameW), each with p's volume.
func linkNames(p string) ([]string, error) {
	name, err := windows.UTF16PtrFromString(extendedPath(p))
	if err != nil {
		return nil, err
	}
	vol := filepath.VolumeName(p)
	buf := make([]uint16, 1024)
	n := uint32(len(buf))
	r, _, e := procFindFirstFileNameW.Call(uintptr(unsafe.Pointer(name)), 0, uintptr(unsafe.Pointer(&n)), uintptr(unsafe.Pointer(&buf[0])))
	for windows.Handle(r) == windows.InvalidHandle && errors.Is(e, windows.ERROR_MORE_DATA) {
		buf = make([]uint16, n)
		r, _, e = procFindFirstFileNameW.Call(uintptr(unsafe.Pointer(name)), 0, uintptr(unsafe.Pointer(&n)), uintptr(unsafe.Pointer(&buf[0])))
	}
	if windows.Handle(r) == windows.InvalidHandle {
		return nil, e
	}
	find := windows.Handle(r)
	defer windows.FindClose(find)
	names := []string{vol + windows.UTF16ToString(buf[:n])}
	for {
		n = uint32(len(buf))
		ok, _, e := procFindNextFileNameW.Call(uintptr(find), uintptr(unsafe.Pointer(&n)), uintptr(unsafe.Pointer(&buf[0])))
		if ok == 0 {
			if errors.Is(e, windows.ERROR_HANDLE_EOF) {
				return names, nil
			}
			if errors.Is(e, windows.ERROR_MORE_DATA) {
				buf = make([]uint16, n)
				// The name that did not fit is asked for again.
				ok, _, e = procFindNextFileNameW.Call(uintptr(find), uintptr(unsafe.Pointer(&n)), uintptr(unsafe.Pointer(&buf[0])))
				if ok == 0 {
					return nil, e
				}
			} else {
				return nil, e
			}
		}
		names = append(names, vol+windows.UTF16ToString(buf[:n]))
	}
}

// afterScan, set by tests only, runs once every entry is held and judged,
// before the first descriptor is written.
var afterScan func()

func protectModels(dir string, roots []string) error {
	var held []*heldEntry
	defer func() {
		for _, e := range held {
			//unchecked: the handles carry no data access; a failed close changes nothing written
			e.close()
		}
	}()
	top, _, err := openEntry(dir)
	if err != nil {
		return err
	}
	held = append(held, top)
	if !top.dir {
		return errors.New("it is not a directory")
	}
	// Every entry is opened and judged, folders before what they hold,
	// before anything is written. A held folder cannot be renamed or
	// replaced, so each child is opened through folders that stay put.
	for i := 0; i < len(held); i++ {
		if !held[i].dir {
			continue
		}
		children, err := os.ReadDir(held[i].path)
		if err != nil {
			return err
		}
		for _, c := range children {
			p := filepath.Join(held[i].path, c.Name())
			e, info, err := openEntry(p)
			if err != nil {
				return err
			}
			held = append(held, e)
			if !e.dir && info.NumberOfLinks > 1 {
				names, err := linkNames(p)
				if err != nil {
					return fmt.Errorf("%s has %d names, which could not be listed: %v", p, info.NumberOfLinks, err)
				}
				for _, other := range names {
					if !under(other, roots) {
						return fmt.Errorf("%s has another name, %s, outside OA's own folders", p, other)
					}
				}
			}
		}
	}
	if afterScan != nil {
		afterScan()
	}
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return err
	}
	sid := user.User.Sid.String()
	descriptors := map[string]*windows.SECURITY_DESCRIPTOR{}
	for kind, sddl := range map[string]string{"top": folderSDDL(sid), "dir": childFolderSDDL(sid), "file": childFileSDDL(sid)} {
		sd, err := windows.SecurityDescriptorFromString(sddl)
		if err != nil {
			return err
		}
		descriptors[kind] = sd
	}
	// Each descriptor is written through its own handle with
	// SetKernelObjectSecurity, which propagates nothing: no write follows a
	// path, and no inheritance walks the tree.
	info := windows.SECURITY_INFORMATION(windows.OWNER_SECURITY_INFORMATION | windows.DACL_SECURITY_INFORMATION)
	for i, e := range held {
		kind := "file"
		switch {
		case i == 0:
			kind = "top"
		case e.dir:
			kind = "dir"
		}
		if err := windows.SetKernelObjectSecurity(e.h, info, descriptors[kind]); err != nil {
			return fmt.Errorf("%s: %w", e.path, err)
		}
	}
	return nil
}

// checkModels refuses dir unless it is a directory with no reparse point,
// owned by this account, with a protected DACL that allows only this
// account, SYSTEM and Administrators.
func checkModels(dir string) error {
	e, _, err := openEntry(dir)
	if err != nil {
		return err
	}
	//unchecked: the handle carries no data access
	defer e.close()
	if !e.dir {
		return errors.New("it is not a directory")
	}
	sd, err := windows.GetSecurityInfo(e.h, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return err
	}
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return err
	}
	return checkModelsDescriptor(sd, user.User.Sid)
}

// checkModelsDescriptor is checkModels' rule on a security descriptor: the
// owner is user, the DACL is protected, and every allow entry names user,
// SYSTEM or Administrators.
func checkModelsDescriptor(sd *windows.SECURITY_DESCRIPTOR, user *windows.SID) error {
	owner, _, err := sd.Owner()
	if err != nil {
		return err
	}
	if owner == nil || !owner.Equals(user) {
		return fmt.Errorf("it is owned by %v, not this account", owner)
	}
	control, _, err := sd.Control()
	if err != nil {
		return err
	}
	if control&windows.SE_DACL_PROTECTED == 0 {
		return errors.New("its DACL inherits entries from its parent")
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		return err
	}
	if dacl == nil {
		return errors.New("it has no DACL, which admits everyone")
	}
	var allowed []*windows.SID
	for _, kind := range []windows.WELL_KNOWN_SID_TYPE{windows.WinLocalSystemSid, windows.WinBuiltinAdministratorsSid} {
		sid, err := windows.CreateWellKnownSid(kind)
		if err != nil {
			return err
		}
		allowed = append(allowed, sid)
	}
	allowed = append(allowed, user)
	for i := uint32(0); i < uint32(dacl.AceCount); i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, i, &ace); err != nil {
			return err
		}
		if ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE {
			if ace.Header.AceType == windows.ACCESS_DENIED_ACE_TYPE {
				continue
			}
			return fmt.Errorf("its DACL holds an entry of type %d", ace.Header.AceType)
		}
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		ok := false
		for _, a := range allowed {
			ok = ok || sid.Equals(a)
		}
		if !ok {
			return fmt.Errorf("its DACL admits %v", sid)
		}
	}
	return nil
}

// checkRoot refuses this account's home, a folder holding it, its known
// folders, a link or junction at root or above it, and a root that does
// not resolve to itself.
func checkRoot(root string) error {
	var known []string
	for _, id := range []*windows.KNOWNFOLDERID{windows.FOLDERID_Profile, windows.FOLDERID_Documents, windows.FOLDERID_Desktop,
		windows.FOLDERID_Downloads, windows.FOLDERID_RoamingAppData, windows.FOLDERID_LocalAppData} {
		if p, err := windows.KnownFolderPath(id, 0); err == nil && p != "" {
			known = append(known, filepath.Clean(p))
			if id == windows.FOLDERID_RoamingAppData {
				known = append(known, filepath.Dir(filepath.Clean(p)))
			}
		}
	}
	for _, k := range known {
		if same, err := identity.SameFile(root, k); err == nil && same {
			return fmt.Errorf("it is the known folder %s", k)
		}
	}
	if len(known) > 0 && holds(root, known[:1]) {
		return fmt.Errorf("it holds this account's home %s", known[0])
	}
	for p := root; ; p = filepath.Dir(p) {
		name, err := windows.UTF16PtrFromString(extendedPath(p))
		if err != nil {
			return err
		}
		attributes, err := windows.GetFileAttributes(name)
		if err != nil {
			return fmt.Errorf("%s: %w", p, err)
		}
		if attributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
			return fmt.Errorf("%s is a link or junction", p)
		}
		if filepath.Dir(p) == p {
			break
		}
	}
	e, _, err := openEntry(root)
	if err != nil {
		return err
	}
	//unchecked: the handle carries no data access
	defer e.close()
	if !e.dir {
		return errors.New("it is not a directory")
	}
	buf := make([]uint16, 512)
	for {
		n, err := windows.GetFinalPathNameByHandle(e.h, &buf[0], uint32(len(buf)), 0)
		if err != nil {
			return err
		}
		if int(n) < len(buf) {
			// A spelling check on purpose: root and its final path are one
			// folder by construction, and the question is whether root is
			// spelled as its final name (no 8.3 alias, substituted drive or
			// mount point left in it), which only the names answer.
			if final := plainFinal(windows.UTF16ToString(buf[:n])); !identity.SamePathName(final, root) {
				return fmt.Errorf("it resolves to %s", final)
			}
			return nil
		}
		buf = make([]uint16, n+1)
	}
}
