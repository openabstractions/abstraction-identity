//go:build windows

package identity

// Win32 entry points this package needs that golang.org/x/sys/windows does not
// already wrap. Everything else comes from there.

import (
	"path/filepath"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	modadvapi32 = windows.NewLazySystemDLL("advapi32.dll")
	modkernel32 = windows.NewLazySystemDLL("kernel32.dll")
	modcrypt32  = windows.NewLazySystemDLL("crypt32.dll")
	modwintrust = windows.NewLazySystemDLL("wintrust.dll")

	procImpersonateNamedPipeClient     = modadvapi32.NewProc("ImpersonateNamedPipeClient")
	procGetNamedPipeClientComputerName = modkernel32.NewProc("GetNamedPipeClientComputerNameW")
	procGetPackageFullName             = modkernel32.NewProc("GetPackageFullName")
	procCryptMsgGetParam               = modcrypt32.NewProc("CryptMsgGetParam")
	procCryptMsgClose                  = modcrypt32.NewProc("CryptMsgClose")

	procCryptCATAdminAcquireContext2         = modwintrust.NewProc("CryptCATAdminAcquireContext2")
	procCryptCATAdminReleaseContext          = modwintrust.NewProc("CryptCATAdminReleaseContext")
	procCryptCATAdminCalcHashFromFileHandle2 = modwintrust.NewProc("CryptCATAdminCalcHashFromFileHandle2")
	procCryptCATAdminEnumCatalogFromHash     = modwintrust.NewProc("CryptCATAdminEnumCatalogFromHash")
	procCryptCATAdminReleaseCatalogContext   = modwintrust.NewProc("CryptCATAdminReleaseCatalogContext")
	procCryptCATCatalogInfoFromContext       = modwintrust.NewProc("CryptCATCatalogInfoFromContext")
)

// wintrustCatalogInfo is WINTRUST_CATALOG_INFO, the WTD_CHOICE_CATALOG
// argument of WinVerifyTrust, including the Windows 8 hCatAdmin field a
// SHA-256 member hash requires.
type wintrustCatalogInfo struct {
	Size               uint32
	CatalogVersion     uint32
	CatalogFilePath    *uint16
	MemberTag          *uint16
	MemberFilePath     *uint16
	MemberFile         windows.Handle
	CalculatedHash     *byte
	CalculatedHashSize uint32
	CatalogContext     uintptr
	CatAdmin           windows.Handle
}

// catalogInfo is CATALOG_INFO: the path of the catalog file a catalog
// context names.
type catalogInfo struct {
	Size        uint32
	CatalogFile [windows.MAX_PATH]uint16
}

// cryptCATAdminAcquireContext2 opens a catalog administrator context that
// hashes members with alg ("SHA256" or "SHA1"). Release it with
// cryptCATAdminReleaseContext.
func cryptCATAdminAcquireContext2(alg string) (windows.Handle, error) {
	algW, err := windows.UTF16PtrFromString(alg)
	if err != nil {
		return 0, err
	}
	var admin windows.Handle
	r1, _, e1 := syscall.SyscallN(procCryptCATAdminAcquireContext2.Addr(),
		uintptr(unsafe.Pointer(&admin)), 0, uintptr(unsafe.Pointer(algW)), 0, 0)
	if r1 == 0 {
		return 0, errnoOrEINVAL(e1)
	}
	return admin, nil
}

func cryptCATAdminReleaseContext(admin windows.Handle) {
	//unchecked: releasing a context on every return path; a failed release has no caller left to act on it
	syscall.SyscallN(procCryptCATAdminReleaseContext.Addr(), uintptr(admin), 0)
}

// cryptCATAdminCalcHashFromFileHandle2 is the member hash of the open file
// under admin's algorithm, the value a catalog lists the file by.
func cryptCATAdminCalcHashFromFileHandle2(admin, file windows.Handle) ([]byte, error) {
	hash := make([]byte, 64)
	n := uint32(len(hash))
	r1, _, e1 := syscall.SyscallN(procCryptCATAdminCalcHashFromFileHandle2.Addr(),
		uintptr(admin), uintptr(file), uintptr(unsafe.Pointer(&n)), uintptr(unsafe.Pointer(&hash[0])), 0)
	if r1 == 0 {
		return nil, errnoOrEINVAL(e1)
	}
	if n == 0 || n > uint32(len(hash)) {
		return nil, syscall.EINVAL
	}
	return hash[:n], nil
}

// cryptCATAdminEnumCatalogFromHash returns the next catalog context listing
// hash after *prev, or 0 when no further catalog lists it. The call releases
// the context *prev named; a loop that stops before 0 releases the last one
// with cryptCATAdminReleaseCatalogContext (mscat.h).
func cryptCATAdminEnumCatalogFromHash(admin windows.Handle, hash []byte, prev *windows.Handle) windows.Handle {
	//unchecked: a zero return ends the enumeration; GetLastError adds nothing a caller acts on
	r1, _, _ := syscall.SyscallN(procCryptCATAdminEnumCatalogFromHash.Addr(), uintptr(admin),
		uintptr(unsafe.Pointer(&hash[0])), uintptr(len(hash)), 0, uintptr(unsafe.Pointer(prev)))
	return windows.Handle(r1)
}

func cryptCATAdminReleaseCatalogContext(admin, info windows.Handle) {
	//unchecked: releasing a catalog context the caller is done with; a failed release has no caller left to act on it
	syscall.SyscallN(procCryptCATAdminReleaseCatalogContext.Addr(), uintptr(admin), uintptr(info), 0)
}

// cryptCATCatalogInfoFromContext fills out with the path of the catalog file
// info names.
func cryptCATCatalogInfoFromContext(info windows.Handle, out *catalogInfo) error {
	out.Size = uint32(unsafe.Sizeof(*out))
	r1, _, e1 := syscall.SyscallN(procCryptCATCatalogInfoFromContext.Addr(), uintptr(info), uintptr(unsafe.Pointer(out)), 0)
	if r1 == 0 {
		return errnoOrEINVAL(e1)
	}
	return nil
}

const (
	// APPMODEL_ERROR_NO_PACKAGE: the process has no MSIX package identity.
	// It is the answer for every ordinary executable, so it is not an error.
	appmodelErrorNoPackage syscall.Errno = 15700

	// CMSG_SIGNER_CERT_INFO_PARAM: the CERT_INFO of the signer, used to find
	// the signing certificate in the store the message came with.
	cmsgSignerCertInfoParam = 7

	// Authenticode verdicts worth naming rather than printing as hex.
	trustENoSignature        = 0x800B0100
	trustESubjectFormUnknown = 0x800B0003
	trustEProviderUnknown    = 0x800B0001
	trustEBadDigest          = 0x80096010
	certEUntrustedRoot       = 0x800B0109
	certEExpired             = 0x800B0101
	certERevoked             = 0x800B010C
	certEChaining            = 0x800B010A
	certEUntrustedTestRoot   = 0x800B010D
	cryptERevocationOffline  = 0x80092013
	cryptENotFound           = 0x80092004

	// GetFinalPathNameByHandle flags: the normalized DOS-drive form, which
	// is what QueryFullProcessImageName also returns, so the two are
	// comparable.
	fileNameNormalized = 0x0
	volumeNameDOS      = 0x0
)

// impersonateNamedPipeClient makes the calling thread run as the pipe's client.
// It is per-thread, and it lasts until RevertToSelf. Callers must go through
// withPeerToken, never call this directly.
func impersonateNamedPipeClient(pipe windows.Handle) error {
	r1, _, e1 := syscall.SyscallN(procImpersonateNamedPipeClient.Addr(), uintptr(pipe))
	if r1 == 0 {
		return errnoOrEINVAL(e1)
	}
	return nil
}

// namedPipeClientComputerName returns the computer the client is running on.
// For a local client it is this machine's NetBIOS name.
func namedPipeClientComputerName(pipe windows.Handle) (string, error) {
	buf := make([]uint16, 256)
	r1, _, e1 := syscall.SyscallN(procGetNamedPipeClientComputerName.Addr(),
		uintptr(pipe), uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)*2))
	if r1 == 0 {
		return "", errnoOrEINVAL(e1)
	}
	return windows.UTF16ToString(buf), nil
}

// packageFullName returns the MSIX package full name of a process, or
// ("", nil) when the process is not packaged.
func packageFullName(proc windows.Handle) (string, error) {
	var n uint32
	r1, _, _ := syscall.SyscallN(procGetPackageFullName.Addr(), uintptr(proc), uintptr(unsafe.Pointer(&n)), 0)
	switch syscall.Errno(r1) {
	case appmodelErrorNoPackage:
		return "", nil
	case syscall.ERROR_INSUFFICIENT_BUFFER:
		// Expected: n now holds the required length.
	case 0:
		return "", nil // no package identity, zero-length name
	default:
		return "", syscall.Errno(r1)
	}
	buf := make([]uint16, n)
	r1, _, _ = syscall.SyscallN(procGetPackageFullName.Addr(), uintptr(proc),
		uintptr(unsafe.Pointer(&n)), uintptr(unsafe.Pointer(&buf[0])))
	if syscall.Errno(r1) == appmodelErrorNoPackage {
		return "", nil
	}
	if r1 != 0 {
		return "", syscall.Errno(r1)
	}
	return windows.UTF16ToString(buf), nil
}

func cryptMsgGetParam(msg windows.Handle, param, index uint32, data unsafe.Pointer, size *uint32) error {
	r1, _, e1 := syscall.SyscallN(procCryptMsgGetParam.Addr(), uintptr(msg), uintptr(param),
		uintptr(index), uintptr(data), uintptr(unsafe.Pointer(size)))
	if r1 == 0 {
		return errnoOrEINVAL(e1)
	}
	return nil
}

func cryptMsgClose(msg windows.Handle) {
	syscall.SyscallN(procCryptMsgClose.Addr(), uintptr(msg))
}

func errnoOrEINVAL(e syscall.Errno) error {
	if e != 0 {
		return e
	}
	return syscall.EINVAL
}

func init() {
	// A short DOS 8.3 name component and its long-form spelling name the
	// same file. This concept exists only on Windows; this is the one
	// platform where canonicalProgramPath does more than return its argument.
	canonicalProgramPath = func(path string) string {
		if !HasShortNameComponent(path) || localPath(path) != nil {
			// A path with no component shaped like a short alias has none
			// to expand, and a program on a share or a device name is never
			// read here.
			return path
		}
		observeOpen(path)
		if long, err := longImagePath(path); err == nil {
			return long
		}
		// A file that does not exist yet keeps its own spelling, below the
		// deepest folder that exists, which reads in its long form: a short
		// alias in an existing part of the path never survives into a stored
		// spelling (UnresolvedShortName covers the part that does not exist).
		dir, rest := filepath.Dir(path), filepath.Base(path)
		for dir != filepath.Dir(dir) {
			if long, err := longImagePath(dir); err == nil {
				return filepath.Join(long, rest)
			}
			rest = filepath.Join(filepath.Base(dir), rest)
			dir = filepath.Dir(dir)
		}
		return path
	}
}

var procGetPackagePathByFullName = modkernel32.NewProc("GetPackagePathByFullName")

// packagePathByFullName returns the folder an installed MSIX package's files
// live in, such as C:\Program Files\WindowsApps\<full name>.
func packagePathByFullName(fullName string) (string, error) {
	name, err := windows.UTF16PtrFromString(fullName)
	if err != nil {
		return "", err
	}
	var n uint32
	//unchecked: SyscallN's error is the raw GetLastError, not meaningful without a failed primary return, which is checked below
	r1, _, _ := syscall.SyscallN(procGetPackagePathByFullName.Addr(), uintptr(unsafe.Pointer(name)), uintptr(unsafe.Pointer(&n)), 0)
	if syscall.Errno(r1) != syscall.ERROR_INSUFFICIENT_BUFFER || n == 0 {
		if r1 == 0 {
			return "", syscall.ERROR_NOT_FOUND
		}
		return "", syscall.Errno(r1)
	}
	buf := make([]uint16, n)
	//unchecked: SyscallN's error is the raw GetLastError, not meaningful without a failed primary return, which is checked below
	r1, _, _ = syscall.SyscallN(procGetPackagePathByFullName.Addr(), uintptr(unsafe.Pointer(name)), uintptr(unsafe.Pointer(&n)), uintptr(unsafe.Pointer(&buf[0])))
	if r1 != 0 {
		return "", syscall.Errno(r1)
	}
	return windows.UTF16ToString(buf), nil
}
