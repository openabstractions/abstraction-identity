//go:build windows

package privatedir

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"unsafe"

	"golang.org/x/sys/windows"
)

// sddl is a private folder's descriptor: owned by the account, with a
// protected DACL of two entries its files and folders inherit, the account
// and SYSTEM with full control.
func sddl(sid string) string {
	return fmt.Sprintf("O:%sD:P(A;OICI;FA;;;%s)(A;OICI;FA;;;SY)", sid, sid)
}

// Make creates dir with the private descriptor applied at creation, so
// there is no moment when it carries the parent's inherited entries.
// CreateDirectory refuses an existing path, a link included (fs.ErrExist).
func Make(dir string) error {
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return err
	}
	sd, err := windows.SecurityDescriptorFromString(sddl(user.User.Sid.String()))
	if err != nil {
		return err
	}
	name, err := windows.UTF16PtrFromString(dir)
	if err != nil {
		return err
	}
	sa := windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: sd}
	if err := windows.CreateDirectory(name, &sa); err != nil {
		if errors.Is(err, windows.ERROR_ALREADY_EXISTS) {
			return fmt.Errorf("%s: %w", dir, fs.ErrExist)
		}
		return err
	}
	return nil
}

// Tighten gives dir, an existing folder, the private descriptor: this
// account becomes its owner and its DACL is replaced by the protected one
// Make sets. It opens dir as itself and refuses a link, a junction or a
// file on that handle, then writes the descriptor through the same handle
// with SetKernelObjectSecurity, which propagates nothing: what the folder
// already holds keeps its own descriptor, a model folder's (ID-D3) and a
// second name of one of its files included. SetNamedSecurityInfo would
// re-propagate inheritance through every name below the folder. Tighten
// judges nothing else; a caller tightens only a folder no other account
// could have written into (storage STO-L9), and CheckDir judges the result.
func Tighten(dir string) error {
	e, _, err := openEntry(dir)
	if err != nil {
		return err
	}
	//unchecked: the handle carries no data written; a failed close changes nothing
	defer e.close()
	if !e.dir {
		return fmt.Errorf("%s is not a directory", dir)
	}
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return err
	}
	sd, err := windows.SecurityDescriptorFromString(sddl(user.User.Sid.String()))
	if err != nil {
		return err
	}
	return windows.SetKernelObjectSecurity(e.h,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, sd)
}

// check refuses dir unless it is a directory with no reparse point, owned
// by this account, with a protected DACL that allows only this account and
// SYSTEM.
func check(dir string) error {
	name, err := windows.UTF16PtrFromString(dir)
	if err != nil {
		return err
	}
	attributes, err := windows.GetFileAttributes(name)
	if err != nil {
		return err
	}
	if attributes&windows.FILE_ATTRIBUTE_DIRECTORY == 0 {
		return errors.New("it is not a directory")
	}
	if attributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return errors.New("it is a link or junction")
	}
	sd, err := windows.GetNamedSecurityInfo(dir, windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return err
	}
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return err
	}
	return checkDescriptor(sd, user.User.Sid)
}

// checkDescriptor is check's rule on a security descriptor: the owner is
// user, the DACL is protected from inheritance, and every entry allows user
// or SYSTEM.
func checkDescriptor(sd *windows.SECURITY_DESCRIPTOR, user *windows.SID) error {
	return checkOwnerDescriptor(sd, user, true)
}

const privateFileRead = true

func checkFileHandle(file *os.File, _ fs.FileInfo) error {
	sd, err := windows.GetSecurityInfo(windows.Handle(file.Fd()), windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return err
	}
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return err
	}
	return checkOwnerDescriptor(sd, user.User.Sid, false)
}

// Files created by CAS inherit the private parent DACL. Check its actual ACEs;
// directories retain the existing protected-DACL requirement unchanged.
func checkOwnerDescriptor(sd *windows.SECURITY_DESCRIPTOR, user *windows.SID, requireProtected bool) error {
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
	if requireProtected && control&windows.SE_DACL_PROTECTED == 0 {
		return errors.New("its DACL inherits entries from its parent")
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		return err
	}
	if dacl == nil {
		return errors.New("it has no DACL, which admits everyone")
	}
	system, err := windows.CreateWellKnownSid(windows.WinLocalSystemSid)
	if err != nil {
		return err
	}
	for i := uint32(0); i < uint32(dacl.AceCount); i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, i, &ace); err != nil {
			return err
		}
		if ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE {
			// A deny entry narrows access; any other type is refused.
			if ace.Header.AceType == windows.ACCESS_DENIED_ACE_TYPE {
				continue
			}
			return fmt.Errorf("its DACL holds an entry of type %d", ace.Header.AceType)
		}
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		if !sid.Equals(user) && !sid.Equals(system) {
			return fmt.Errorf("its DACL admits %v", sid)
		}
	}
	return nil
}
