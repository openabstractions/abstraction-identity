//go:build windows

package trustedpath

import (
	"errors"
	"fmt"
	"path/filepath"
	"strconv"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

// mediumRID is SECURITY_MANDATORY_MEDIUM_RID; an object with no mandatory
// label is Medium.
const mediumRID = 0x2000

// systemMandatoryLabelACEType is SYSTEM_MANDATORY_LABEL_ACE_TYPE.
const systemMandatoryLabelACEType = 0x11

// labelAtLeastMedium refuses a folder whose mandatory integrity label is
// below Medium. Reading the label needs READ_CONTROL only.
func labelAtLeastMedium(path string) error {
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.LABEL_SECURITY_INFORMATION)
	if err != nil {
		return err
	}
	rid, err := integrityRID(sd)
	if err != nil {
		return err
	}
	if rid < mediumRID {
		return fmt.Errorf("its integrity label is %#x, below Medium", rid)
	}
	return nil
}

// integrityRID is the RID of the descriptor's mandatory label, mediumRID
// when it carries none.
func integrityRID(sd *windows.SECURITY_DESCRIPTOR) (uint32, error) {
	sacl, _, err := sd.SACL()
	if err != nil || sacl == nil {
		// No SACL in the answer is no label.
		return mediumRID, nil
	}
	for i := uint32(0); i < uint32(sacl.AceCount); i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(sacl, i, &ace); err != nil {
			return 0, err
		}
		if ace.Header.AceType != systemMandatoryLabelACEType || ace.Header.AceFlags&windows.INHERIT_ONLY_ACE != 0 {
			continue
		}
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		// ConvertSidToStringSid writes to an output parameter. The x/sys
		// subauthority accessors recover interior pointers into the Go-owned
		// descriptor from syscall return values, which checkptr rejects.
		const mandatoryAuthority = "S-1-16"
		label := sid.String()
		if label == mandatoryAuthority {
			return 0, errors.New("a mandatory label without a RID")
		}
		value, ok := strings.CutPrefix(label, mandatoryAuthority+"-")
		if !ok {
			return 0, errors.New("invalid mandatory label SID")
		}
		rid, err := strconv.ParseUint(value, 10, 32)
		if err != nil {
			return 0, errors.New("invalid mandatory label RID")
		}
		return uint32(rid), nil
	}
	return mediumRID, nil
}

// CheckHandle judges an object opened by handle by the rule CheckFile
// applies to the file itself, or to a folder when folder is set: a trusted
// owner, and no other principal with a right that changes or removes it
// (or, for a folder, deletes, renames or re-permissions what it holds). The
// handle needs READ_CONTROL.
func CheckHandle(h windows.Handle, folder bool, owners Owners) error {
	trusted, err := owners.sids()
	if err != nil {
		return err
	}
	sd, err := windows.GetSecurityInfo(h, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return err
	}
	mask := windows.ACCESS_MASK(fileChange)
	if folder {
		mask = folderChange
	}
	if err := checkDescriptor(sd, mask, trusted); err != nil {
		return fmt.Errorf("%w: %v", ErrUntrusted, err)
	}
	return nil
}

// ForeignCapabilities lists, for each folder above root, the AppContainer
// and capability principals (S-1-15-*) its DACL lets change it or what it
// holds, as "folder: SID (access 0x...)". A provider logs them once per
// start: CheckFileWithin trusts a record below such a folder because those
// principals run at Low integrity, which the folder's Medium label stops.
func ForeignCapabilities(root string) []string {
	var out []string
	root = filepath.Clean(root)
	for dir := filepath.Dir(root); ; dir = filepath.Dir(dir) {
		if sd, err := windows.GetNamedSecurityInfo(dir, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION); err == nil {
			if dacl, _, err := sd.DACL(); err == nil && dacl != nil {
				for i := uint32(0); i < uint32(dacl.AceCount); i++ {
					var ace *windows.ACCESS_ALLOWED_ACE
					if windows.GetAce(dacl, i, &ace) != nil || ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE || ace.Header.AceFlags&windows.INHERIT_ONLY_ACE != 0 {
						continue
					}
					sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
					if s := sid.String(); strings.HasPrefix(s, "S-1-15-") && ace.Mask&folderChange != 0 {
						out = append(out, fmt.Sprintf("%s: %s (access %#x)", dir, s, uint32(ace.Mask)))
					}
				}
			}
		}
		if filepath.Dir(dir) == dir {
			break
		}
	}
	return out
}
