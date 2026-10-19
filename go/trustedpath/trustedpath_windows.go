//go:build windows

package trustedpath

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"unsafe"

	"github.com/openabstractions/abstraction-identity/fileid"
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
func CheckFile(path string, owners Owners) error { return check(path, "", owners, false) }

// CheckExecutable is CheckFile for a program that runs elevated (ID-D2's
// executable folder): the folder holding it also refuses another
// principal's right to add a file or a subfolder.
func CheckExecutable(path string, owners Owners) error { return check(path, "", owners, true) }

// CheckFileWithin is CheckFile with the owner and access rule applied from
// root down: to the file and to each folder from root to the file's own.
// Every folder from the volume root down is still refused when it is a
// reparse point, and each folder above root must carry a mandatory
// integrity label of Medium or higher (no label is Medium): a Low or
// untrusted label would let an AppContainer, which runs at Low, rename or
// replace it whatever its DACL says. root must be a folder above path. It
// suits a record in a program's own state folder, whose ACL the program
// sets, below folders other software may have granted rights on
// (research/fast-load/PROPOSAL.md, Decision 2, amendment 1).
func CheckFileWithin(path, root string, owners Owners) error { return check(path, root, owners, false) }

// CheckFolderWithin is CheckFileWithin for the folder root itself: its owner
// and access by the folder rule, every folder above it by the reparse-point
// and integrity-label rules.
func CheckFolderWithin(root string, owners Owners) error { return check(root, root, owners, false) }

func check(path, root string, owners Owners, executable bool) error {
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
	var leafFolder bool
	for i := len(chain) - 1; i >= 0; i-- {
		folder, err := kind(chain[i])
		if err != nil {
			return refuse(i, err)
		}
		if i > 0 && !folder {
			return refuse(i, errors.New("it is not a folder"))
		}
		if i == 0 {
			leafFolder = folder
		}
	}
	limit := len(chain) - 1
	if root != "" {
		root = filepath.Clean(root)
		limit = configuredRootIndex(chain, root)
		if limit < 0 {
			return fmt.Errorf("%w: %s is not below %s", ErrUntrusted, path, root)
		}
	}
	if leafFolder != (root != "" && limit == 0) {
		if leafFolder {
			return refuse(0, errors.New("it is a folder"))
		}
		return refuse(0, errors.New("it is not a folder"))
	}
	for i := limit + 1; i < len(chain); i++ {
		if err := labelAtLeastMedium(chain[i]); err != nil {
			return refuse(i, err)
		}
	}
	for i, p := range chain[:limit+1] {
		mask := windows.ACCESS_MASK(fileChange)
		switch {
		case i == 1 && executable:
			mask = executableFolderChange
		case i > 0 || leafFolder:
			mask = folderChange
		}
		if err := access(p, mask, trusted); err != nil {
			return refuse(i, err)
		}
	}
	return nil
}

// configuredRootIndex locates the real root among the target's ancestors.
// Name-surrogate paths cannot introduce a different route to that root.
func configuredRootIndex(chain []string, root string) int {
	if !filepath.IsAbs(root) || strings.HasPrefix(root, `\\`) {
		return -1
	}
	ctx := context.Background()
	opts := fileid.Options{Links: fileid.RefuseLinks}
	boundary, err := fileid.Resolve(ctx, fileid.Self, root, opts)
	if err != nil || !boundary.IsDir() {
		return -1
	}
	for i, path := range chain {
		id, err := fileid.Resolve(ctx, fileid.Self, path, opts)
		if err == nil && id.Equal(boundary) {
			return i
		}
	}
	return -1
}

// kind reports whether an ordinary path is a folder.
func kind(path string) (bool, error) {
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return false, err
	}
	attributes, err := windows.GetFileAttributes(name)
	if err != nil {
		return false, err
	}
	if attributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return false, errors.New("it is a reparse point (a link, junction or mount point)")
	}
	return attributes&windows.FILE_ATTRIBUTE_DIRECTORY != 0, nil
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
