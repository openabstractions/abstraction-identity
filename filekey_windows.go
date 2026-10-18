package identity

import (
	"fmt"
	"os"
	"strings"
	"sync/atomic"
	"unsafe"

	"golang.org/x/sys/windows"
)

// fileIdInfoClass is FILE_INFO_BY_HANDLE_CLASS FileIdInfo: the volume serial
// number and the 128-bit file ID ReFS needs; NTFS fills the low 64 bits.
const fileIdInfoClass = 18

type fileIDInfo struct {
	VolumeSerialNumber uint64
	FileID             [16]byte
}

// openObserver, when set, is told every path identity is about to open or
// read by name (observeOpen); tests count opens with it.
var openObserver atomic.Pointer[func(path string)]

// ObserveOpens is for tests, in this module and in its consumers: until stop
// is called, observe is told every path identity's path functions are about
// to open or read by name, so a test can show that a refused path was never
// opened. One observer at a time; ok is false while another is set.
func ObserveOpens(observe func(path string)) (stop func(), ok bool) {
	if !openObserver.CompareAndSwap(nil, &observe) {
		return func() {}, false
	}
	return func() { openObserver.CompareAndSwap(&observe, nil) }, true
}

func observeOpen(path string) {
	if observe := openObserver.Load(); observe != nil {
		(*observe)(path)
	}
}

// openHandle opens path for its identity alone: no data access, sharing
// everything, a folder too (FILE_FLAG_BACKUP_SEMANTICS), with flags added.
// A path LocalPath refuses is never opened. The open carries a security
// quality of service at identification level (SECURITY_SQOS_PRESENT |
// SECURITY_IDENTIFICATION), so whatever answers the open cannot act as this
// process. CreateFile reads the same SECURITY_SQOS_PRESENT bit on a file as
// FILE_FLAG_OPEN_NO_RECALL: a file kept in remote storage is not recalled to
// read its identity.
func openHandle(path string, flags uint32) (windows.Handle, error) {
	if err := localPath(path); err != nil {
		return 0, err
	}
	observeOpen(path)
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return 0, err
	}
	h, err := windows.CreateFile(p, 0, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, nil,
		windows.OPEN_EXISTING, windows.FILE_FLAG_BACKUP_SEMANTICS|windows.SECURITY_SQOS_PRESENT|windows.SECURITY_IDENTIFICATION|flags, 0)
	if err != nil {
		return 0, &pathError{op: "open", path: path, err: err}
	}
	return h, nil
}

// pathExists reports whether path names an existing file, folder or link,
// without following a link in its last component, as os.Lstat finds one.
func pathExists(path string) bool {
	h, err := openHandle(path, windows.FILE_FLAG_OPEN_REPARSE_POINT)
	if err != nil {
		return false
	}
	//unchecked: an identity query handle; closing it reports nothing a caller acts on
	windows.CloseHandle(h)
	return true
}

// fileKey opens path (links are followed, as os.Stat follows them) and reads
// its volume serial number and file ID.
func fileKey(path string) (string, error) {
	h, err := openHandle(path, 0)
	if err != nil {
		return "", err
	}
	defer windows.CloseHandle(h)
	return fileKeyHandle(h)
}

// FileKeyOf reads the filesystem identity from an already open handle.
// A caller changing an access list can compare this exact handle with the
// recorded path identity before the effect, without reopening a name.
func FileKeyOf(f *os.File) (string, error) {
	if f == nil {
		return "", fmt.Errorf("identity: no file handle")
	}
	return fileKeyHandle(windows.Handle(f.Fd()))
}

func fileKeyHandle(h windows.Handle) (string, error) {
	var info fileIDInfo
	if err := windows.GetFileInformationByHandleEx(h, fileIdInfoClass, (*byte)(unsafe.Pointer(&info)), uint32(unsafe.Sizeof(info))); err == nil {
		return fmt.Sprintf("%016x-%x", info.VolumeSerialNumber, info.FileID), nil
	}
	var by windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(h, &by); err != nil {
		return "", fmt.Errorf("identity: identify an open file: %w", err)
	}
	return fmt.Sprintf("%08x-%08x%08x", by.VolumeSerialNumber, by.FileIndexHigh, by.FileIndexLow), nil
}

// resolveLinks is the final path of an existing file or folder, the kernel's
// name for the handle after junctions and symbolic links
// (GetFinalPathNameByHandle, as handleFinalPath reads it). A final path that
// is not on a local drive, as a symbolic link to a share gives, is refused
// for every later open.
func resolveLinks(path string) (string, error) {
	h, err := openHandle(path, 0)
	if err != nil {
		return "", err
	}
	defer windows.CloseHandle(h)
	final, err := handleFinalPath(h)
	if err != nil {
		return "", err
	}
	if rest, ok := strings.CutPrefix(final, `UNC\`); ok {
		final = `\\` + rest
	}
	if err := localPath(final); err != nil {
		return "", err
	}
	return final, nil
}
