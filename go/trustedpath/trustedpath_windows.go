//go:build windows

package trustedpath

import (
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

// fileChange is every right that changes a file's bytes, times, owner or
// access, or removes it: write data, append data, write extended
// attributes, write attributes, delete, write DAC, write owner, generic
// all and generic write.
const fileChange = 0x2 | 0x4 | 0x10 | 0x100 | windows.DELETE | windows.WRITE_DAC | windows.WRITE_OWNER |
	windows.GENERIC_ALL | windows.GENERIC_WRITE

// folderChange is every right on a folder that deletes or renames what it
// holds or the folder itself, or grants such a right: delete child,
// delete, write DAC, write owner and generic all. Adding a file or a
// subfolder (BUILTIN\Users' right in %ProgramData%) is not among them: what
// another account adds is owned by that account.
const folderChange = 0x40 | windows.DELETE | windows.WRITE_DAC | windows.WRITE_OWNER | windows.GENERIC_ALL

// executableFolderChange is folderChange plus adding a file or a subfolder
// and generic write: in the folder an elevated program runs from, a file
// another account adds is a library the loader may pick up.
const executableFolderChange = folderChange | 0x2 | 0x4 | windows.GENERIC_WRITE

// CheckFile refuses (ErrUntrusted) the file at path, an absolute local
// path, unless a trusted owner owns it and every folder above it up to the
// volume root, no other principal holds a right on the file that changes or
// removes it or on a folder that deletes, renames or re-permissions what it
// holds, and neither the file nor any of those folders is a reparse point.
// It reads attributes and security descriptors only.
func CheckFile(path string, owners Owners) error { return check(path, owners, false) }

// CheckExecutable is CheckFile for a program that runs elevated (ID-D2's
// executable folder): the folder holding it also refuses another
// principal's right to add a file or a subfolder.
func CheckExecutable(path string, owners Owners) error { return check(path, owners, true) }

func check(path string, owners Owners, executable bool) error {
	trusted, err := owners.sids()
	if err != nil {
		return err
	}
	if !filepath.IsAbs(path) || strings.HasPrefix(path, `\\`) {
		return fmt.Errorf("%w: %q is not an absolute local path", ErrUntrusted, path)
	}
	path = filepath.Clean(path)
	chain := []string{path}
	for dir := filepath.Dir(path); ; dir = filepath.Dir(dir) {
		chain = append(chain, dir)
		if filepath.Dir(dir) == dir {
			break
		}
	}
	// Every object's attributes first, from the volume root down, so a
	// reparse point anywhere on the path is the reason given; then each
	// object's owner and access.
	refuse := func(i int, err error) error {
		if i == 0 {
			return fmt.Errorf("%w: %s: %v", ErrUntrusted, path, err)
		}
		return fmt.Errorf("%w: %s: folder %s: %v", ErrUntrusted, path, chain[i], err)
	}
	for i := len(chain) - 1; i >= 0; i-- {
		if err := kind(chain[i], i > 0); err != nil {
			return refuse(i, err)
		}
	}
	for i, p := range chain {
		mask := windows.ACCESS_MASK(fileChange)
		switch {
		case i == 1 && executable:
			mask = executableFolderChange
		case i > 0:
			mask = folderChange
		}
		if err := access(p, mask, trusted); err != nil {
			return refuse(i, err)
		}
	}
	return nil
}

// kind refuses a reparse point, and a folder where a file belongs or the
// reverse.
func kind(path string, folder bool) error {
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return err
	}
	attributes, err := windows.GetFileAttributes(name)
	if err != nil {
		return err
	}
	if attributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return errors.New("it is a reparse point (a link, junction or mount point)")
	}
	if folder != (attributes&windows.FILE_ATTRIBUTE_DIRECTORY != 0) {
		if folder {
			return errors.New("it is not a folder")
		}
		return errors.New("it is a folder")
	}
	return nil
}

// access judges one object's owner and DACL.
func access(path string, mask windows.ACCESS_MASK, trusted []*windows.SID) error {
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return err
	}
	return checkDescriptor(sd, mask, trusted)
}

// checkDescriptor refuses a descriptor whose owner is not trusted, or whose
// DACL lets an untrusted principal hold a right in mask on the object
// itself. An entry that only passes to children (inherit-only) does not
// apply to it; a deny entry narrows access; any other entry type is refused;
// a missing DACL admits everyone.
func checkDescriptor(sd *windows.SECURITY_DESCRIPTOR, mask windows.ACCESS_MASK, trusted []*windows.SID) error {
	owner, _, err := sd.Owner()
	if err != nil {
		return err
	}
	if owner == nil || !among(owner, trusted) {
		return fmt.Errorf("it is owned by %v", owner)
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		return err
	}
	if dacl == nil {
		return errors.New("it has no DACL, which admits everyone")
	}
	for i := uint32(0); i < uint32(dacl.AceCount); i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, i, &ace); err != nil {
			return err
		}
		if ace.Header.AceFlags&windows.INHERIT_ONLY_ACE != 0 {
			continue
		}
		switch ace.Header.AceType {
		case windows.ACCESS_DENIED_ACE_TYPE:
			continue
		case windows.ACCESS_ALLOWED_ACE_TYPE:
		default:
			return fmt.Errorf("its DACL holds an entry of type %d", ace.Header.AceType)
		}
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		if ace.Mask&mask != 0 && !among(sid, trusted) {
			return fmt.Errorf("%v may change it (access %#x)", sid, uint32(ace.Mask&mask))
		}
	}
	return nil
}

// sids parses the trusted principals, adding the calling account's when
// Account is set.
func (o Owners) sids() ([]*windows.SID, error) {
	var out []*windows.SID
	for _, s := range o.SIDs {
		sid, err := windows.StringToSid(s)
		if err != nil {
			return nil, fmt.Errorf("trustedpath: owner %q: %w", s, err)
		}
		out = append(out, sid)
	}
	if o.Account {
		user, err := windows.GetCurrentProcessToken().GetTokenUser()
		if err != nil {
			return nil, err
		}
		out = append(out, user.User.Sid)
	}
	return out, nil
}

func among(sid *windows.SID, trusted []*windows.SID) bool {
	for _, t := range trusted {
		if sid.Equals(t) {
			return true
		}
	}
	return false
}
