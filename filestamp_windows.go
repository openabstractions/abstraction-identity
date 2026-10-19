//go:build windows

package identity

import (
	"fmt"
	"os"
	"unsafe"

	"golang.org/x/sys/windows"
)

// fileBasicInfo is FILE_BASIC_INFO, which GetFileInformationByHandleEx
// fills for FileBasicInfo. Times count 100-nanosecond intervals since 1601.
type fileBasicInfo struct {
	CreationTime   int64
	LastAccessTime int64
	LastWriteTime  int64
	ChangeTime     int64
	FileAttributes uint32
	_              uint32
}

// readStampInputs reads f's stamp from its handle: the volume serial number
// and file ID (FileKeyOf), the size from info, and the LastWriteTime and
// ChangeTime of FILE_BASIC_INFO.
//
// On NTFS the file ID is the file reference number: a 48-bit MFT record
// index and a 16-bit sequence number NTFS increments each time it reuses
// the record (MFT_SEGMENT_REFERENCE, ntifs.h, learn.microsoft.com), and
// FILE_ID_INFO carries it in its low 64 bits. A file created on a deleted
// file's record therefore has another file ID until the sequence number
// wraps after 65,535 reuses of that record. ChangeTime catches a file
// rewritten in place whose LastWriteTime was set back.
func readStampInputs(f *os.File, info os.FileInfo) (stampInputs, error) {
	identity, err := FileKeyOf(f)
	if err != nil {
		return stampInputs{}, err
	}
	var basic fileBasicInfo
	if err := windows.GetFileInformationByHandleEx(windows.Handle(f.Fd()), windows.FileBasicInfo,
		(*byte)(unsafe.Pointer(&basic)), uint32(unsafe.Sizeof(basic))); err != nil {
		return stampInputs{}, fmt.Errorf("identity: read the times of an open file: %w", err)
	}
	return stampInputs{identity: identity, size: info.Size(), modified: basic.LastWriteTime, changed: basic.ChangeTime}, nil
}
