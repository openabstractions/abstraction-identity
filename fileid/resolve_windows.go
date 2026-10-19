package fileid

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"unicode/utf16"
	"unsafe"

	"golang.org/x/sys/windows"
)

// The walk (paths/DIAGNOSIS.md section 2.3, steps 2 to 7). Each component
// is opened by NtCreateFile relative to the handle of the folder above it,
// with FILE_OPEN_REPARSE_POINT, so the system follows no junction or
// symbolic link on its own. A name-surrogate reparse point (a junction, a
// symbolic link) is read and its target checked with localPath before the
// walk goes on from the target: a link to a share is refused before the
// share is contacted, and a link to a network drive letter likewise. Every
// open carries an identification-level security quality of service and
// FILE_OPEN_NO_RECALL. The walk keeps no answer from RedirectionGuard,
// which a process opts into and whose earliest documented build is Windows
// 11 22H2 (W0-07(s) fact 4, research/release-0.8.0/probes/w0-07s-path-facts.md):
// it reads each link itself on every build.

const (
	// fileOpenNoRecall is FILE_OPEN_NO_RECALL: a file kept in remote storage,
	// such as a cloud files placeholder, is not recalled to answer.
	fileOpenNoRecall = 0x00400000
	// maxLinkHops bounds the links one walk follows, as the system's own
	// limit of 63 reparse points does.
	maxLinkHops = 63
	// symlinkFlagRelative is SYMLINK_FLAG_RELATIVE in a symbolic link's
	// reparse data.
	symlinkFlagRelative = 1
	// fileCaseSensitiveInfo is FILE_INFO_BY_HANDLE_CLASS
	// FileCaseSensitiveInfo; fileCSFlagCaseSensitiveDir its flag.
	fileCaseSensitiveInfo      = 23
	fileCSFlagCaseSensitiveDir = 1
	// accessIdentity reads attributes, the reparse data and the file ID; it
	// is what every component of a walk is opened for.
	accessIdentity = windows.FILE_READ_ATTRIBUTES | windows.SYNCHRONIZE
)

var identificationQoS = windows.SECURITY_QUALITY_OF_SERVICE{
	Length:             uint32(unsafe.Sizeof(windows.SECURITY_QUALITY_OF_SERVICE{})),
	ImpersonationLevel: windows.SecurityIdentification,
}

// openAt opens name relative to the folder parent without following a
// reparse point at name; tests replace it to see every name the walk opens.
var openAt = ntOpenAt

// openRoot opens a volume root such as `C:\`; tests replace it.
var openRoot = openVolumeRoot

// reopenFile opens the file h holds again, for access, through h itself;
// tests replace it. betweenOpens, when set, runs between the walk's open of a
// data-tag file and that reopen; tests change the folder entry there.
var (
	reopenFile   = ntReopen
	betweenOpens func(here string)
)

// ntReopen opens an empty name relative to h, as ReOpenFile does: the file
// object h holds, reached without a name, so nothing in the folder is read.
func ntReopen(h windows.Handle, access uint32) (windows.Handle, error) {
	return ntCreate(h, "", access, windows.FILE_OPEN, windows.FILE_NON_DIRECTORY_FILE|windows.FILE_OPEN_REPARSE_POINT)
}

func ntOpenAt(parent windows.Handle, name string, access, disposition, options uint32) (windows.Handle, error) {
	return ntCreate(parent, name, access, disposition, options|windows.FILE_OPEN_REPARSE_POINT)
}

func ntCreate(parent windows.Handle, name string, access, disposition, options uint32) (windows.Handle, error) {
	u, err := windows.NewNTUnicodeString(name)
	if err != nil {
		return 0, err
	}
	qos := identificationQoS
	oa := windows.OBJECT_ATTRIBUTES{
		Length:        uint32(unsafe.Sizeof(windows.OBJECT_ATTRIBUTES{})),
		RootDirectory: parent,
		ObjectName:    u,
		Attributes:    windows.OBJ_CASE_INSENSITIVE,
		SecurityQoS:   &qos,
	}
	if access&windows.FILE_READ_DATA == 0 {
		// An open that reads no data recalls nothing from remote storage.
		options |= fileOpenNoRecall
	}
	var h windows.Handle
	var iosb windows.IO_STATUS_BLOCK
	err = windows.NtCreateFile(&h, access|windows.SYNCHRONIZE, &oa, &iosb, nil, 0,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, disposition,
		options|windows.FILE_SYNCHRONOUS_IO_NONALERT|windows.FILE_OPEN_FOR_BACKUP_INTENT, 0, 0)
	if err != nil {
		var st windows.NTStatus
		if errors.As(err, &st) {
			return 0, st.Errno()
		}
		return 0, err
	}
	return h, nil
}

// openVolumeRoot opens a drive root such as `C:\`, or a volume GUID root
// `\\?\Volume{GUID}\` as written.
func openVolumeRoot(root string) (windows.Handle, error) {
	observeOpen(root)
	if !strings.HasPrefix(root, `\\?\`) {
		root = `\\?\` + root
	}
	p, err := windows.UTF16PtrFromString(root)
	if err != nil {
		return 0, err
	}
	return windows.CreateFile(p, accessIdentity, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, nil,
		windows.OPEN_EXISTING, windows.FILE_FLAG_OPEN_REPARSE_POINT|windows.FILE_FLAG_BACKUP_SEMANTICS|windows.SECURITY_SQOS_PRESENT|windows.SECURITY_IDENTIFICATION, 0)
}

// checkedRoot refuses a substituted root before opening any child through it.
func checkedRoot(root string) (windows.Handle, error) {
	h, err := openRoot(root)
	if err != nil {
		return 0, err
	}
	tag, err := readAttributeTag(h)
	if err == nil && isLink(tag) {
		err = ErrLink
	}
	if err != nil {
		windows.CloseHandle(h)
		return 0, err
	}
	return h, nil
}

type attributeTag struct {
	attributes uint32
	tag        uint32
}

func readAttributeTag(h windows.Handle) (attributeTag, error) {
	var info struct{ FileAttributes, ReparseTag uint32 }
	if err := windows.GetFileInformationByHandleEx(h, windows.FileAttributeTagInfo, (*byte)(unsafe.Pointer(&info)), uint32(unsafe.Sizeof(info))); err != nil {
		return attributeTag{}, err
	}
	return attributeTag{attributes: info.FileAttributes, tag: info.ReparseTag}, nil
}

// isLink reports whether attributes and a reparse tag make a link the walk
// reads: a name-surrogate tag (IsReparseTagNameSurrogate, bit 29) on a
// reparse point. Every other tag is a data tag, and its file is a regular
// file: a cloud files placeholder, a WOF-compressed file, a deduplicated
// file, an app execution alias. On 10.0.26200 with wof.sys attached a WOF
// file shows no reparse point at all (W0-07(s) fact 3); without the filter
// NTFS shows IO_REPARSE_TAG_WOF, a data tag, and the answer is the same.
func isLink(a attributeTag) bool {
	return a.attributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 && a.tag&0x20000000 != 0
}

// walkState is one walk in progress: the handle of the folder reached and
// its spelling with every link already replaced by its target.
type walkState struct {
	ctx      context.Context
	opt      Options
	dir      windows.Handle
	spelled  string
	hops     int
	finalAcc uint32
}

func (w *walkState) close() {
	if w.dir != 0 {
		//unchecked: a walk handle; closing it reports nothing a caller acts on
		windows.CloseHandle(w.dir)
		w.dir = 0
	}
}

// dataSuffix names a file's own data stream, which is the file itself.
const dataSuffix = "::$DATA"

// withoutStream strips a trailing "::$DATA", spelled so, and refuses a path
// that names any other stream, a colon after its volume name, before
// anything is opened (ID-F4); another letter case of "$DATA" is refused with
// the streams. An alternate stream has data of its own under the file's
// FileID, so a Handle on it would act on data the FileID does not tell apart.
func withoutStream(abs string) (string, error) {
	vol := filepath.VolumeName(abs)
	rest, err := streamFree(abs, abs[len(vol):])
	if err != nil {
		return "", err
	}
	return vol + rest, nil
}

// streamFree is withoutStream's rule for rest, the part of a path below its
// volume; spelled names the path in the refusal. A typed path and every link
// target pass it.
func streamFree(spelled, rest string) (string, error) {
	if trimmed, ok := strings.CutSuffix(rest, dataSuffix); ok {
		rest = trimmed
	}
	if strings.ContainsRune(rest, ':') {
		return "", fmt.Errorf("%w: %q names a data stream", ErrUnsafeName, spelled)
	}
	return rest, nil
}

func components(rest string) []string {
	return strings.FieldsFunc(rest, func(r rune) bool { return r == '\\' || r == '/' })
}

func open(ctx context.Context, path string, opt Options) (Handle, error) {
	if err := localPath(path); err != nil {
		return Handle{}, err
	}
	abs, err := absolute(path)
	if err != nil {
		return Handle{}, err
	}
	abs = strings.TrimPrefix(strings.ReplaceAll(abs, "/", `\`), `\\?\`)
	if !driveAbsolute(abs) {
		return Handle{}, &NotLocalPathError{Path: path, Reason: "it names no drive letter"}
	}
	w := &walkState{ctx: ctx, opt: opt}
	defer w.close()
	if err := w.restart(abs[:3]); err != nil {
		return Handle{}, err
	}
	h, err := w.walk(components(abs[3:]))
	if err != nil {
		return Handle{}, err
	}
	return describe(h, w.spelled)
}

func (w *walkState) restart(root string) error {
	w.close()
	h, err := checkedRoot(root)
	if err != nil {
		return &pathError{op: "open", path: root, err: err}
	}
	w.dir, w.spelled = h, root
	return nil
}

func (w *walkState) access(last bool) uint32 {
	if last && w.opt.Read {
		return accessIdentity | windows.FILE_GENERIC_READ
	}
	return accessIdentity
}

// walk opens each of names below w.dir and returns the handle of the last,
// which the caller owns; w.dir stays the folder above it. With no names it
// returns a handle of w.dir itself.
func (w *walkState) walk(names []string) (windows.Handle, error) {
	if len(names) == 0 {
		var dup windows.Handle
		self := windows.CurrentProcess()
		if err := windows.DuplicateHandle(self, w.dir, self, &dup, 0, false, windows.DUPLICATE_SAME_ACCESS); err != nil {
			return 0, err
		}
		return dup, nil
	}
	for len(names) > 0 {
		if err := w.ctx.Err(); err != nil {
			return 0, err
		}
		name := names[0]
		names = names[1:]
		last := len(names) == 0
		here := filepath.Join(w.spelled, name)
		if strings.ContainsRune(name, ':') {
			// Every input has passed streamFree or SafeName; no name holding
			// a stream reaches NtCreateFile whatever its source.
			return 0, fmt.Errorf("%w: %q names a data stream", ErrUnsafeName, here)
		}
		observeOpen(here)
		h, err := openAt(w.dir, name, w.access(last), windows.FILE_OPEN, 0)
		if err != nil {
			return 0, &pathError{op: "open", path: here, err: err}
		}
		tag, err := readAttributeTag(h)
		if err != nil {
			windows.CloseHandle(h)
			return 0, &pathError{op: "read the attributes of", path: here, err: err}
		}
		if isLink(tag) {
			target, err := readLinkTarget(h, here, w.spelled)
			windows.CloseHandle(h)
			if err != nil {
				return 0, err
			}
			if w.opt.Links == RefuseLinks {
				return 0, fmt.Errorf("%w: %s is a link to %s", ErrLink, here, target)
			}
			root, rest, err := localTarget(here, target)
			if err != nil {
				return 0, err
			}
			if w.hops++; w.hops > maxLinkHops {
				return 0, &pathError{op: "follow", path: here, err: windows.ERROR_CANT_RESOLVE_FILENAME}
			}
			if err := w.restart(root); err != nil {
				return 0, err
			}
			names = append(components(rest), names...)
			if len(names) == 0 {
				return w.walk(nil)
			}
			continue
		}
		if last {
			if w.opt.Read && tag.attributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
				// A data tag read for its data: reopen the same file through
				// the handle just opened, so the filter that owns the tag
				// (WOF, cloud files) serves the data, and require its key.
				// No name is looked up again: an entry swapped for a link
				// between the two opens is never followed.
				want, _, err := fileIDKey(h)
				if err != nil {
					windows.CloseHandle(h)
					return 0, &pathError{op: "identify", path: here, err: err}
				}
				if betweenOpens != nil {
					betweenOpens(here)
				}
				again, err := reopenFile(h, w.access(true))
				windows.CloseHandle(h)
				if err != nil {
					return 0, &pathError{op: "open", path: here, err: err}
				}
				tag, err := readAttributeTag(again)
				if err == nil && isLink(tag) {
					err = ErrLink
				}
				if err != nil {
					windows.CloseHandle(again)
					return 0, &pathError{op: "open", path: here, err: err}
				}
				if got, _, err := fileIDKey(again); err != nil || got != want {
					windows.CloseHandle(again)
					return 0, &pathError{op: "open", path: here, err: errors.New("the file changed while it was opened")}
				}
				h = again
			}
			w.spelled = here
			return h, nil
		}
		w.close()
		w.dir, w.spelled = h, here
	}
	return 0, errors.New("fileid: empty walk")
}

// readLinkTarget reads the reparse data of the link h holds, at here in the
// folder dir, and returns its target as a drive path.
func readLinkTarget(h windows.Handle, here, dir string) (string, error) {
	buf := make([]byte, windows.MAXIMUM_REPARSE_DATA_BUFFER_SIZE)
	var n uint32
	if err := windows.DeviceIoControl(h, windows.FSCTL_GET_REPARSE_POINT, nil, 0, &buf[0], uint32(len(buf)), &n, nil); err != nil {
		return "", &pathError{op: "read the link", path: here, err: err}
	}
	return linkTarget(buf[:n], here, dir)
}

// volumeGUIDLen is the length of `Volume{xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx}`.
const volumeGUIDLen = 44

// volumeGUIDPath reports whether s, without its `\\?\` or `\??\` prefix,
// begins with a volume's GUID name, spelled `Volume{` as the mount manager
// writes it, and then ends or goes on with a separator.
func volumeGUIDPath(s string) bool {
	return len(s) >= volumeGUIDLen && strings.HasPrefix(s, "Volume{") && s[volumeGUIDLen-1] == '}' &&
		(len(s) == volumeGUIDLen || s[volumeGUIDLen] == '\\')
}

// localTarget splits a link's target, a drive path or a `\\?\Volume{GUID}\`
// path from linkTarget, into the root the walk restarts at and the rest. The
// rest passes the stream refusal a typed path passes (streamFree) before the
// volume is read. A drive path must pass localPath. A volume GUID names a
// volume of this machine, mounted in a folder or with no mount at all, such
// as a Dev Drive or a VHD without a letter; it is followed when GetDriveType
// reads its root as a local disk, removable, optical or RAM disk, and refused
// as remote or unknown. Nothing is opened.
func localTarget(here, target string) (root, rest string, err error) {
	refuseStream := func(rest string) (string, error) {
		free, err := streamFree(target, rest)
		if err != nil {
			return "", fmt.Errorf("%s is a link: %w", here, err)
		}
		return free, nil
	}
	if driveAbsolute(target) {
		if rest, err = refuseStream(target[3:]); err != nil {
			return "", "", err
		}
		if err := localPath(target[:3] + rest); err != nil {
			return "", "", err
		}
		return target[:3], rest, nil
	}
	if s, ok := strings.CutPrefix(target, `\\?\`); ok && volumeGUIDPath(s) {
		if rest, err = refuseStream(strings.TrimPrefix(s[volumeGUIDLen:], `\`)); err != nil {
			return "", "", err
		}
		root = `\\?\` + s[:volumeGUIDLen] + `\`
		switch pathDriveType(root) {
		case windows.DRIVE_FIXED, windows.DRIVE_REMOVABLE, windows.DRIVE_CDROM, windows.DRIVE_RAMDISK:
			return root, rest, nil
		}
		return "", "", &NotLocalPathError{Path: here, Reason: "a link to " + target + ", which names no local volume"}
	}
	return "", "", &NotLocalPathError{Path: here, Reason: "a link to " + target + ", which names no local volume"}
}

// linkTarget reads a junction's or symbolic link's reparse data and returns
// its target, cleaned as Win32 cleans one: an absolute drive path, or a
// `\\?\Volume{GUID}\` path for a mount point of a volume named by GUID, which
// localTarget checks. A target on a share (\??\UNC\...), the device
// namespace and every other form is refused with a *NotLocalPathError; a link
// of a kind fileid does not read is refused with ErrLink. It reads only the
// bytes; nothing is opened.
func linkTarget(buf []byte, here, dir string) (string, error) {
	if len(buf) < 16 {
		return "", fmt.Errorf("%w: %s has short reparse data", ErrLink, here)
	}
	le16 := func(off int) int { return int(binary.LittleEndian.Uint16(buf[off:])) }
	tag := binary.LittleEndian.Uint32(buf)
	var body, flags int
	switch tag {
	case windows.IO_REPARSE_TAG_MOUNT_POINT:
		body = 16
	case windows.IO_REPARSE_TAG_SYMLINK:
		if len(buf) < 20 {
			return "", fmt.Errorf("%w: %s has short reparse data", ErrLink, here)
		}
		body, flags = 20, int(binary.LittleEndian.Uint32(buf[16:]))
	default:
		return "", fmt.Errorf("%w: %s is a link of kind %#x", ErrLink, here, tag)
	}
	off, length := le16(8), le16(10)
	if off%2 != 0 || length%2 != 0 || body+off+length > len(buf) {
		return "", fmt.Errorf("%w: %s has malformed reparse data", ErrLink, here)
	}
	units := make([]uint16, length/2)
	for i := range units {
		units[i] = binary.LittleEndian.Uint16(buf[body+off+2*i:])
	}
	sub := string(utf16.Decode(units))
	relative := tag == windows.IO_REPARSE_TAG_SYMLINK && flags&symlinkFlagRelative != 0
	absolute := driveAbsolute(sub) || strings.HasPrefix(sub, `\??\`) && (driveAbsolute(sub[4:]) || volumeGUIDPath(sub[4:]))
	if !relative && absolute {
		for _, name := range components(sub) {
			if name == "." || name == ".." {
				return "", fmt.Errorf("%w: %s has an absolute link target with dot components", ErrLink, here)
			}
		}
	}
	refuse := func(reason string) error { return &NotLocalPathError{Path: here, Reason: reason} }
	switch {
	case tag == windows.IO_REPARSE_TAG_SYMLINK && flags&symlinkFlagRelative != 0:
		if strings.HasPrefix(sub, `\`) {
			// Relative to the root of the link's own volume.
			return filepath.Clean(filepath.VolumeName(dir) + sub), nil
		}
		return filepath.Clean(filepath.Join(dir, sub)), nil
	case strings.HasPrefix(sub, `\??\`) && volumeGUIDPath(sub[4:]):
		vol := `\\?\` + sub[4:4+volumeGUIDLen]
		return filepath.Clean(vol + `\` + strings.TrimPrefix(sub[4+volumeGUIDLen:], `\`)), nil
	case strings.HasPrefix(sub, `\??\`) && driveAbsolute(sub[4:]):
		return filepath.Clean(sub[4:]), nil
	case strings.HasPrefix(sub, `\??\`) && len(sub) == 6 && sub[5] == ':':
		return sub[4:] + `\`, nil
	case driveAbsolute(sub):
		return filepath.Clean(sub), nil
	}
	return "", refuse("a link to " + sub + ", which names no local volume")
}

// finalPathOf reads a handle's final path; tests name a folder through a
// mount point, as the system names a volume mounted in a folder.
var finalPathOf = handleFinalPath

// describe reads the FileID of the open handle h, whose spelling after
// links is spelled, and returns the Handle owning it.
func describe(h windows.Handle, spelled string) (Handle, error) {
	fail := func(err error) (Handle, error) {
		windows.CloseHandle(h)
		return Handle{}, err
	}
	key, wide, err := fileIDKey(h)
	if err != nil {
		return fail(err)
	}
	final, err := finalPathOf(h)
	if err != nil {
		return fail(&pathError{op: "name", path: spelled, err: err})
	}
	if rest, ok := strings.CutPrefix(final, `UNC\`); ok {
		final = `\\` + rest
	}
	if err := localPath(final); err != nil {
		return fail(err)
	}
	var by windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(h, &by); err != nil {
		return fail(&pathError{op: "read", path: final, err: err})
	}
	durability := Volatile
	if wide && persistentFileSystem(h) {
		durability = Persistent
	}
	id := FileID{key: key, path: final, durability: durability, links: int(by.NumberOfLinks),
		dir: by.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY != 0}
	return Handle{f: os.NewFile(uintptr(h), final), id: id}, nil
}

// fileIDKey is fileKeyHandle's key, and wide reports whether it came from
// the 128-bit FILE_ID_INFO; the 64-bit fallback is a volatile key (F4).
func fileIDKey(h windows.Handle) (key string, wide bool, err error) {
	var info fileIDInfo
	if err := windows.GetFileInformationByHandleEx(h, fileIdInfoClass, (*byte)(unsafe.Pointer(&info)), uint32(unsafe.Sizeof(info))); err == nil {
		return fmt.Sprintf("%016x-%x", info.VolumeSerialNumber, info.FileID), true, nil
	}
	key, err = fileKeyHandle(h)
	return key, false, err
}

// persistentFileSystem reports whether the volume h is on keeps file IDs
// across a reboot and a rename: NTFS and ReFS. FAT and exFAT give a file a
// new ID when its name is rewritten.
func persistentFileSystem(h windows.Handle) bool {
	name := make([]uint16, windows.MAX_PATH+1)
	if err := windows.GetVolumeInformationByHandle(h, nil, 0, nil, nil, nil, &name[0], uint32(len(name))); err != nil {
		return false
	}
	// GetVolumeInformation spells each file system's name one way.
	switch windows.UTF16ToString(name) {
	case "NTFS", "ReFS":
		return true
	}
	return false
}

func handleOf(h Handle) windows.Handle { return windows.Handle(h.f.Fd()) }

// stillAt reads h's final path from its handle again and reports whether it
// is the path describe read.
func stillAt(h Handle) (bool, error) {
	final, err := finalPathOf(handleOf(h))
	if err != nil {
		return false, &pathError{op: "name", path: h.id.path, err: err}
	}
	if rest, ok := strings.CutPrefix(final, `UNC\`); ok {
		final = `\\` + rest
	}
	return final == h.id.path, nil
}

func beneath(start Handle, names []string, opt Options) (Handle, error) {
	w := &walkState{ctx: context.Background(), opt: opt, spelled: start.id.path}
	self := windows.CurrentProcess()
	if err := windows.DuplicateHandle(self, handleOf(start), self, &w.dir, 0, false, windows.DUPLICATE_SAME_ACCESS); err != nil {
		return Handle{}, err
	}
	defer w.close()
	h, err := w.walk(names)
	if err != nil {
		return Handle{}, err
	}
	return describe(h, w.spelled)
}

func createExclusive(dir Handle, name string) (Handle, error) {
	here := filepath.Join(dir.id.path, name)
	observeOpen(here)
	h, err := ntCreate(handleOf(dir), name, accessIdentity|windows.GENERIC_READ|windows.GENERIC_WRITE, windows.FILE_CREATE,
		windows.FILE_NON_DIRECTORY_FILE|windows.FILE_OPEN_REPARSE_POINT)
	if err != nil {
		return Handle{}, &pathError{op: "create", path: here, err: err}
	}
	return describe(h, here)
}

// leafName reads the folder's entry for name: a name a file has reads as the
// folder holds it, an 8.3 alias in its long form and with the case it was
// created with. The entry is read through the held folder, and no handle
// is opened on the file: a store's
// readers resolve its leaf outside the lock, and a handle on the data file
// would refuse a writer's rename over it. A name with a wildcard character,
// which no Windows file has, is taken as written. It also reads whether the
// folder compares names with case.
func leafName(folder Handle, name string) (string, bool, error) {
	var cs struct{ Flags uint32 }
	caseSensitive := windows.GetFileInformationByHandleEx(handleOf(folder), fileCaseSensitiveInfo,
		(*byte)(unsafe.Pointer(&cs)), uint32(unsafe.Sizeof(cs))) == nil && cs.Flags&fileCSFlagCaseSensitiveDir != 0
	if strings.ContainsAny(name, "*?<>\"") {
		return name, caseSensitive, nil
	}
	here := filepath.Join(folder.id.path, name)
	observeOpen(here)
	h, err := ntCreate(handleOf(folder), "", accessIdentity|windows.FILE_LIST_DIRECTORY, windows.FILE_OPEN,
		windows.FILE_DIRECTORY_FILE|windows.FILE_OPEN_REPARSE_POINT)
	if err != nil {
		return "", false, &pathError{op: "read the folder entry", path: here, err: err}
	}
	defer windows.CloseHandle(h)
	entry, err := directoryEntryName(h, name)
	if errors.Is(err, windows.STATUS_NO_SUCH_FILE) || errors.Is(err, windows.STATUS_NO_MORE_FILES) {
		return name, caseSensitive, nil
	}
	if err != nil {
		return "", false, &pathError{op: "read the folder entry", path: here, err: err}
	}
	return entry, caseSensitive, nil
}

var queryDirectoryFile = windows.NewLazySystemDLL("ntdll.dll").NewProc("NtQueryDirectoryFile")

// directoryEntryName uses FileNamesInformation (12): three ULONGs followed
// by FileNameLength bytes of UTF-16. The private reopen is synchronous and
// owns its enumeration cursor; no event, APC or caller-shared scan is used.
// ABI: learn.microsoft.com/windows-hardware/drivers/ddi/ntifs/nf-ntifs-ntquerydirectoryfile
func directoryEntryName(folder windows.Handle, name string) (string, error) {
	filter, err := windows.NewNTUnicodeString(name)
	if err != nil {
		return "", err
	}
	var entry struct {
		NextEntryOffset, FileIndex, FileNameLength uint32
		FileName                                   [windows.MAX_LONG_PATH]uint16
	}
	var iosb windows.IO_STATUS_BLOCK
	status, _, _ := queryDirectoryFile.Call(uintptr(folder), 0, 0, 0,
		uintptr(unsafe.Pointer(&iosb)), uintptr(unsafe.Pointer(&entry)), unsafe.Sizeof(entry),
		12, 1, uintptr(unsafe.Pointer(filter)), 1)
	runtime.KeepAlive(filter)
	if windows.NTStatus(status) != windows.STATUS_SUCCESS {
		return "", windows.NTStatus(status)
	}
	const header = 12
	if entry.NextEntryOffset != 0 || entry.FileNameLength == 0 || entry.FileNameLength%2 != 0 ||
		entry.FileNameLength > uint32(len(entry.FileName)*2) || iosb.Information < header+uintptr(entry.FileNameLength) ||
		iosb.Information > unsafe.Sizeof(entry) {
		return "", errors.New("fileid: malformed directory entry")
	}
	return string(utf16.Decode(entry.FileName[:entry.FileNameLength/2])), nil
}

// openByID finds a stored file by its ID on the volume of its stored path:
// NTFS file references are the low 64 bits of the 128-bit ID, and
// NtCreateFile opens one with FILE_OPEN_BY_FILE_ID relative to any handle on
// the volume. A ReFS ID, which needs all 128 bits, is not looked up.
func openByID(ctx context.Context, s StoredFileID) (FileID, bool) {
	serial, id, ok := strings.Cut(s.key, "-")
	if !ok || len(id) != 32 || !driveAbsolute(s.path) {
		return FileID{}, false
	}
	raw, err := hex.DecodeString(id)
	if err != nil || len(raw) != 16 {
		return FileID{}, false
	}
	for _, b := range raw[8:] {
		if b != 0 {
			return FileID{}, false
		}
	}
	if ctx.Err() != nil || localPath(s.path) != nil {
		return FileID{}, false
	}
	root, err := checkedRoot(s.path[:3])
	if err != nil {
		return FileID{}, false
	}
	defer windows.CloseHandle(root)
	h, err := ntCreateByID(root, raw[:8])
	if err != nil {
		return FileID{}, false
	}
	got, err := describe(h, s.path)
	if err != nil {
		return FileID{}, false
	}
	got.Close()
	if !strings.HasPrefix(got.id.key, serial+"-") {
		return FileID{}, false
	}
	return got.id, true
}

// ntCreateByID opens the file whose 64-bit NTFS reference ref holds, on the
// volume of the handle volume, without following a reparse point.
func ntCreateByID(volume windows.Handle, ref []byte) (windows.Handle, error) {
	u := windows.NTUnicodeString{Length: uint16(len(ref)), MaximumLength: uint16(len(ref)), Buffer: (*uint16)(unsafe.Pointer(&ref[0]))}
	qos := identificationQoS
	oa := windows.OBJECT_ATTRIBUTES{
		Length:        uint32(unsafe.Sizeof(windows.OBJECT_ATTRIBUTES{})),
		RootDirectory: volume,
		ObjectName:    &u,
		SecurityQoS:   &qos,
	}
	var h windows.Handle
	var iosb windows.IO_STATUS_BLOCK
	err := windows.NtCreateFile(&h, accessIdentity, &oa, &iosb, nil, 0,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, windows.FILE_OPEN,
		windows.FILE_OPEN_BY_FILE_ID|windows.FILE_OPEN_REPARSE_POINT|windows.FILE_SYNCHRONOUS_IO_NONALERT|windows.FILE_OPEN_FOR_BACKUP_INTENT|fileOpenNoRecall, 0, 0)
	if err != nil {
		return 0, err
	}
	return h, nil
}
