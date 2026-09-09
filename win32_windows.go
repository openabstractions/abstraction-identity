//go:build windows

package identity

// Win32 entry points this package needs that golang.org/x/sys/windows does not
// already wrap. Everything else comes from there.

import (
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	modadvapi32 = windows.NewLazySystemDLL("advapi32.dll")
	modkernel32 = windows.NewLazySystemDLL("kernel32.dll")
	modcrypt32  = windows.NewLazySystemDLL("crypt32.dll")

	procImpersonateNamedPipeClient     = modadvapi32.NewProc("ImpersonateNamedPipeClient")
	procGetNamedPipeClientComputerName = modkernel32.NewProc("GetNamedPipeClientComputerNameW")
	procGetPackageFullName             = modkernel32.NewProc("GetPackageFullName")
	procCryptMsgGetParam               = modcrypt32.NewProc("CryptMsgGetParam")
	procCryptMsgClose                  = modcrypt32.NewProc("CryptMsgClose")
)

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
