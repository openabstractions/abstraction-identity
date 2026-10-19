//go:build windows

package privatedir

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"unicode/utf16"
	"unsafe"

	"github.com/openabstractions/abstraction-identity/fileid"
	"golang.org/x/sys/windows"
)

func extendedPath(p string) string { return `\\?\` + p }
func (e *heldEntry) close() error {
	if e.file != nil {
		return e.file.Close()
	}
	return windows.CloseHandle(e.h)
}

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
	file *os.File
}

// reopenEntry keeps the admitted file object while acquiring the descriptor
// rights and no-delete sharing already used by this owner. ReOpenFile's
// documented source is a CreateFile handle; native fileid handles instead
// use NtCreateFile. Use the existing fileid same-object empty-name pattern
// with the actual directory/file type and unchanged caller-token access.
// https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-reopenfile
func reopenEntry(admitted fileid.Handle) (*heldEntry, windows.ByHandleFileInformation, error) {
	var options uint32
	if admitted.FileID().IsDir() {
		options |= windows.FILE_DIRECTORY_FILE
	} else {
		options |= windows.FILE_NON_DIRECTORY_FILE
	}
	e, info, err := modelEntryAt(windows.Handle(admitted.File().Fd()), "", admitted.FileID().Path(), options)
	if err != nil {
		return nil, info, err
	}
	key, err := fileid.FileKeyOf(e.file)
	if err != nil || key != admitted.FileID().Key() {
		e.close()
		return nil, info, errors.New("descriptor handle differs from the admitted file")
	}
	return e, info, nil
}

func modelEntryAt(parent windows.Handle, name, display string, options uint32) (*heldEntry, windows.ByHandleFileInformation, error) {
	var info windows.ByHandleFileInformation
	u, err := windows.NewNTUnicodeString(name)
	if err != nil {
		return nil, info, err
	}
	qos := windows.SECURITY_QUALITY_OF_SERVICE{
		Length: uint32(unsafe.Sizeof(windows.SECURITY_QUALITY_OF_SERVICE{})), ImpersonationLevel: windows.SecurityIdentification,
	}
	oa := windows.OBJECT_ATTRIBUTES{Length: uint32(unsafe.Sizeof(windows.OBJECT_ATTRIBUTES{})),
		RootDirectory: parent, ObjectName: u, SecurityQoS: &qos}
	options |= windows.FILE_OPEN_REPARSE_POINT | windows.FILE_SYNCHRONOUS_IO_NONALERT | windows.FILE_OPEN_FOR_BACKUP_INTENT
	var h windows.Handle
	var ios windows.IO_STATUS_BLOCK
	err = windows.NtCreateFile(&h, windows.FILE_READ_DATA|windows.READ_CONTROL|windows.WRITE_DAC|windows.WRITE_OWNER|windows.FILE_READ_ATTRIBUTES|windows.SYNCHRONIZE,
		&oa, &ios, nil, 0, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE, windows.FILE_OPEN, options, 0, 0)
	if err != nil {
		return nil, info, fmt.Errorf("open held model entry %s: %w", display, err)
	}
	e := &heldEntry{path: display, h: h, file: os.NewFile(uintptr(h), display)}
	if err := windows.GetFileInformationByHandle(h, &info); err != nil {
		e.close()
		return nil, info, err
	}
	if info.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		e.close()
		return nil, info, errors.New("admitted entry is a reparse point")
	}
	e.dir = info.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY != 0
	return e, info, nil
}

func modelChildEntry(parent *heldEntry, name string) (*heldEntry, windows.ByHandleFileInformation, error) {
	// This is an existing one-component name returned by held enumeration,
	// not a portable create name. Keep literal trailing dots/spaces and DOS
	// device words; refuse traversal, streams and embedded separators.
	if !literalModelName(name) {
		return nil, windows.ByHandleFileInformation{}, errors.New("not a literal model child name")
	}
	return modelEntryAt(parent.h, name, filepath.Join(parent.path, name), 0)
}

func literalModelName(name string) bool {
	return name != "" && name != "." && name != ".." && !strings.ContainsAny(name, "/\\:\x00")
}

func readHeldDirectory(e *heldEntry) ([]os.DirEntry, error) {
	var duplicate windows.Handle
	if err := windows.DuplicateHandle(windows.CurrentProcess(), e.h, windows.CurrentProcess(), &duplicate, 0, false, windows.DUPLICATE_SAME_ACCESS); err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(duplicate), e.path)
	entries, err := f.ReadDir(-1)
	closeErr := f.Close()
	if err != nil {
		return nil, fmt.Errorf("read held directory %s: %w", e.path, err)
	}
	return entries, closeErr
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
	kernel32         = windows.NewLazySystemDLL("kernel32.dll")
	procOpenFileByID = kernel32.NewProc("OpenFileById")
)

// Tests can supply malformed OS replies without contacting another volume.
var modelLinkQuery = windows.NtQueryInformationFile

// hardlinkParentsWithin queries the admitted file, rather than reopening
// its old path. Native FILE_LINKS_INFORMATION entries are 8-byte aligned;
// their FileNameLength counts UTF-16 characters (ntifs.h).
// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/ns-ntifs-_file_links_information
func hardlinkParentsWithin(e *heldEntry, roots []fileid.Handle, expected uint32) error {
	key, err := fileid.FileKeyOf(e.file)
	if err != nil {
		return err
	}
	buf := hardlinkBuffer(4096)
	for {
		var ios windows.IO_STATUS_BLOCK
		err := modelLinkQuery(e.h, &ios, &buf[0], uint32(len(buf)), 46)
		if err != nil {
			needed := binary.LittleEndian.Uint32(buf[:4])
			if needed > uint32(len(buf)) && needed <= 64<<20 {
				buf = hardlinkBuffer(needed)
				continue
			}
			return fmt.Errorf("held hard-link query: %w", err)
		}
		if ios.Information < 8 || ios.Information > uintptr(len(buf)) {
			return errors.New("held hard-link query returned an invalid byte count")
		}
		buf = buf[:int(ios.Information)]
		if needed := binary.LittleEndian.Uint32(buf[:4]); needed == 0 || uint64(needed) > uint64(len(buf)) {
			return errors.New("held hard-link query returned incomplete bytes")
		}
		count := binary.LittleEndian.Uint32(buf[4:8])
		if count != expected || count == 0 {
			return errors.New("held hard-link query returned an incomplete name set")
		}
		offset := 8
		for i := uint32(0); i < count; i++ {
			if offset > len(buf)-20 {
				return errors.New("malformed held hard-link entry")
			}
			next := binary.LittleEndian.Uint32(buf[offset:])
			parentID := binary.LittleEndian.Uint64(buf[offset+8:])
			characters := binary.LittleEndian.Uint32(buf[offset+16:])
			if parentID == 0 || characters == 0 || uint64(characters)*2 > uint64(len(buf)-offset-20) {
				return errors.New("malformed held hard-link parent/name")
			}
			units := make([]uint16, int(characters))
			for j := range units {
				units[j] = binary.LittleEndian.Uint16(buf[offset+20+j*2:])
			}
			for j := 0; j < len(units); j++ {
				if units[j] >= 0xd800 && units[j] <= 0xdbff {
					if j+1 == len(units) || units[j+1] < 0xdc00 || units[j+1] > 0xdfff {
						return errors.New("held hard-link query returned an invalid UTF-16 name")
					}
					j++
				} else if units[j] >= 0xdc00 && units[j] <= 0xdfff {
					return errors.New("held hard-link query returned an invalid UTF-16 name")
				}
			}
			name := string(utf16.Decode(units))
			if !literalModelName(name) {
				return errors.New("held hard-link query returned a nonliteral name")
			}
			if err := hardlinkParentWithin(e.h, parentID, name, key, roots); err != nil {
				return err
			}
			if i+1 == count {
				if next != 0 {
					return errors.New("held hard-link query has trailing entries")
				}
			} else {
				if uint64(next) < 20+uint64(characters)*2 || next%8 != 0 || uint64(next) > uint64(len(buf)-offset) {
					return errors.New("malformed held hard-link offset")
				}
				offset += int(next)
			}
		}
		return nil
	}
}

func hardlinkBuffer(size uint32) []byte {
	// NtQueryInformationFile requires native 8-byte alignment for this
	// structure; a stack-backed byte array has only byte alignment.
	words := make([]uint64, (int(size)+7)/8)
	return unsafe.Slice((*byte)(unsafe.Pointer(&words[0])), len(words)*8)
}

func hardlinkParentWithin(volumeHint windows.Handle, id uint64, name, expectedKey string, roots []fileid.Handle) error {
	// FILE_ID_DESCRIPTOR has a 16-byte union even for its 64-bit FileId.
	descriptor := struct {
		Size uint32
		Kind uint32
		ID   [2]uint64
	}{Size: 24, ID: [2]uint64{id}}
	raw, _, err := procOpenFileByID.Call(uintptr(volumeHint), uintptr(unsafe.Pointer(&descriptor)),
		uintptr(windows.FILE_READ_ATTRIBUTES|windows.FILE_READ_DATA), uintptr(windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE), 0,
		uintptr(windows.FILE_FLAG_BACKUP_SEMANTICS|windows.FILE_FLAG_OPEN_REPARSE_POINT))
	h := windows.Handle(raw)
	if h == windows.InvalidHandle {
		return err
	}
	f := os.NewFile(uintptr(h), "held hard-link parent")
	defer f.Close()
	key, err := fileid.FileKeyOf(f)
	if err != nil {
		return err
	}
	parentName := make([]uint16, 512)
	for {
		n, err := windows.GetFinalPathNameByHandle(h, &parentName[0], uint32(len(parentName)), 0)
		if err != nil {
			return err
		}
		if int(n) >= len(parentName) {
			parentName = make([]uint16, int(n)+1)
			continue
		}
		parent, err := fileid.Open(context.Background(), fileid.Self, windows.UTF16ToString(parentName[:n]), fileid.Options{Links: fileid.RefuseLinks})
		if err != nil {
			return err
		}
		defer parent.Close()
		if !parent.FileID().IsDir() || parent.FileID().Key() != key {
			return errors.New("hard-link parent changed at its locator")
		}
		for _, root := range roots {
			relation, err := parent.Relate(root)
			if err != nil {
				return err
			}
			if relation.Kind != fileid.RelationOutside {
				entry, _, err := modelEntryAt(h, name, "held hard-link name", windows.FILE_NON_DIRECTORY_FILE)
				if err != nil {
					return err
				}
				actualKey, keyErr := fileid.FileKeyOf(entry.file)
				closeErr := entry.close()
				if keyErr != nil {
					return keyErr
				}
				if actualKey != expectedKey {
					return errors.New("reported hard-link name no longer names the admitted file")
				}
				return closeErr
			}
		}
		return errors.New("held file has a name outside OA's own folders")
	}
}

// afterScan, set by tests only, runs once every entry is held and judged,
// before the first descriptor is written.
var afterScan func()

func protectModelsAt(dir fileid.Handle, roots []fileid.Handle) error {
	var held []*heldEntry
	defer func() {
		for _, e := range held {
			//unchecked: the handles carry no data access; a failed close changes nothing written
			e.close()
		}
	}()
	top, _, err := reopenEntry(dir)
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
		children, err := readHeldDirectory(held[i])
		if err != nil {
			return err
		}
		for _, c := range children {
			p := filepath.Join(held[i].path, c.Name())
			e, info, err := modelChildEntry(held[i], c.Name())
			if err != nil {
				return err
			}
			held = append(held, e)
			if !e.dir && info.NumberOfLinks > 1 {
				if err := hardlinkParentsWithin(e, roots, info.NumberOfLinks); err != nil {
					return fmt.Errorf("%s: %w", p, err)
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
	for _, e := range held[:1] {
		sd, err := windows.GetSecurityInfo(e.h, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
		if err != nil {
			return err
		}
		if err := checkModelsDescriptor(sd, user.User.Sid); err != nil {
			return err
		}
	}
	return nil
}

func modelKnownFolders() []string {
	var known []string
	for _, id := range []*windows.KNOWNFOLDERID{windows.FOLDERID_Profile, windows.FOLDERID_Documents, windows.FOLDERID_Desktop,
		windows.FOLDERID_Downloads, windows.FOLDERID_RoamingAppData, windows.FOLDERID_LocalAppData} {
		p, err := windows.KnownFolderPath(id, 0)
		if err != nil || p == "" {
			if id == windows.FOLDERID_Profile {
				return []string{""}
			}
			continue
		}
		known = append(known, p)
		if id == windows.FOLDERID_RoamingAppData {
			known = append(known, filepath.Dir(p))
		}
	}
	return known
}

// checkModels refuses dir unless it is a directory with no reparse point,
// owned by this account, with a protected DACL that allows only this
// account, SYSTEM and Administrators.
func checkModelsAt(dir fileid.Handle) error {
	e, _, err := reopenEntry(dir)
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
