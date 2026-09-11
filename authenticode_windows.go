//go:build windows

package identity

import (
	"fmt"
	"strings"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

// verifyImage asks Windows whether the file a process is running carries a
// signature Windows itself trusts, and who signed it.
//
// The awkward part is that Windows has no way to verify the image a process is
// actually executing. WinVerifyTrust verifies a file. The running process is a
// section object mapped from a file that may since have been renamed, deleted,
// or replaced. So this does the most that is available:
//
//   - it holds the peer's process handle open throughout, so the pid cannot be
//     recycled underneath it;
//   - it opens the image file and keeps that handle open for the whole
//     verification, and passes the handle - not the path - to WinVerifyTrust,
//     so the bytes that were verified are bytes it is holding;
//   - it asks the kernel again, afterwards, what path that process is running
//     from and what path its own open handle resolves to, and refuses the
//     answer if they have stopped agreeing.
//
// What remains is one race this package cannot close: between the process
// starting and this function opening the file, the file could have been
// renamed away and a different file put at the name the kernel now reports. It
// requires write access to the directory and precise timing. It is the reason
// Code never reports better than ProofBound. See CONTRACT.md.
func verifyImage(proc windows.Handle, imagePath string, opts *Options) (Code, Proof, error) {
	// Expand DOS 8.3 aliases before verification, preserving this initial name
	// for the later rename/swap checks rather than recanonicalizing it afterwards.
	imagePath, err := longImagePath(imagePath)
	if err != nil {
		return Code{}, ProofNone, err
	}
	pathW, err := windows.UTF16PtrFromString(imagePath)
	if err != nil {
		return Code{}, ProofNone, err
	}

	// FILE_SHARE_DELETE is deliberate: without it this open would block a
	// legitimate updater from replacing the binary, and a service that
	// identifies its callers must not become a reason software cannot be
	// patched.
	file, err := windows.CreateFile(pathW, windows.GENERIC_READ,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil, windows.OPEN_EXISTING, windows.FILE_ATTRIBUTE_NORMAL, 0)
	if err != nil {
		return Code{}, ProofNone, fmt.Errorf("the image file could not be opened: %w", err)
	}
	defer windows.CloseHandle(file)

	code, verdict := verifyTrust(file, pathW, opts.checkRevocation())
	if code.Trusted {
		if subject, issuer, err := signerName(pathW); err == nil {
			code.Subject, code.Issuer = subject, issuer
		} else {
			// The file verified but the signature is not embedded in
			// it - Windows found it in a system catalog. That is a
			// real and common answer for OS binaries.
			code.Catalog = true
			code.Status = "valid, signed via a system catalog rather than an embedded signature"
		}
	}

	// Everything above happened over a span. Check that the span did not
	// contain a swap.
	if err := stillSameImage(proc, file, imagePath); err != nil {
		return Code{}, ProofNone, fmt.Errorf("verification abandoned: %w", err)
	}
	return code, verdict, nil
}

// stillSameImage re-asks the kernel where the process is running from, and
// where our own open file handle now lives, and requires all three names to
// agree with the path the verification was performed against.
func stillSameImage(proc, file windows.Handle, want string) error {
	now, err := processImagePath(proc)
	if err != nil {
		return fmt.Errorf("the process image path could no longer be read: %w", err)
	}
	now, err = longImagePath(now)
	if err != nil {
		return fmt.Errorf("the process image path could not be normalized: %w", err)
	}
	if !samePath(now, want) {
		return fmt.Errorf("the process image path changed from %q to %q during verification", want, now)
	}
	buf := make([]uint16, windows.MAX_LONG_PATH)
	n, err := windows.GetFinalPathNameByHandle(file, &buf[0], uint32(len(buf)), fileNameNormalized|volumeNameDOS)
	if err != nil {
		return fmt.Errorf("the verified file could no longer be named: %w", err)
	}
	if n == 0 || n >= uint32(len(buf)) {
		return fmt.Errorf("the verified file path exceeds the buffer")
	}
	got := strings.TrimPrefix(windows.UTF16ToString(buf[:n]), `\\?\`)
	if !samePath(got, want) {
		return fmt.Errorf("the file that was verified is now at %q, not %q", got, want)
	}
	return nil
}

// longImagePath expands short DOS components without resolving the final file
// afresh after verification. Failure refuses identity rather than guessing.
func longImagePath(path string) (string, error) {
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return "", err
	}
	buf := make([]uint16, windows.MAX_LONG_PATH)
	n, err := windows.GetLongPathName(p, &buf[0], uint32(len(buf)))
	if err != nil {
		return "", err
	}
	if n == 0 || n >= uint32(len(buf)) {
		return "", fmt.Errorf("image path exceeds the buffer")
	}
	return strings.TrimPrefix(windows.UTF16ToString(buf[:n]), `\\?\`), nil
}

// verifyTrust runs the Authenticode policy over an already-open file handle.
// The Proof is the verdict: ProofBound for a file Windows accepted, one of the
// verdict rungs for one it did not.
func verifyTrust(file windows.Handle, pathW *uint16, revocation bool) (Code, Proof) {
	fi := windows.WinTrustFileInfo{
		Size:     uint32(unsafe.Sizeof(windows.WinTrustFileInfo{})),
		FilePath: pathW,
		File:     file,
	}
	data := windows.WinTrustData{
		Size:                            uint32(unsafe.Sizeof(windows.WinTrustData{})),
		UIChoice:                        windows.WTD_UI_NONE,
		RevocationChecks:                windows.WTD_REVOKE_NONE,
		UnionChoice:                     windows.WTD_CHOICE_FILE,
		FileOrCatalogOrBlobOrSgnrOrCert: unsafe.Pointer(&fi),
		StateAction:                     windows.WTD_STATEACTION_VERIFY,
		// Cache-only URL retrieval keeps identification off the network.
		// A permission prompt that hangs waiting for a CRL is a permission
		// prompt that gets clicked through.
		//
		// WTD_SAFER_FLAG is deliberately absent. Under it Windows reports
		// a signature it refused as TRUST_E_NOSIGNATURE, in the return
		// value and in GetLastError alike - measured on Windows 11 with a
		// signed node.exe one byte changed - so a tampered file and an
		// unsigned one would land on the same rung.
		ProvFlags: windows.WTD_CACHE_ONLY_URL_RETRIEVAL,
		UIContext: windows.WTD_UICONTEXT_EXECUTE,
	}
	if revocation {
		data.RevocationChecks = windows.WTD_REVOKE_WHOLECHAIN
		data.ProvFlags = windows.WTD_REVOCATION_CHECK_CHAIN
	}

	action := windows.WINTRUST_ACTION_GENERIC_VERIFY_V2
	err := windows.WinVerifyTrustEx(windows.InvalidHWND, &action, &data)

	// Always close the trust state, whatever the verdict, or the provider
	// leaks per call.
	data.StateAction = windows.WTD_STATEACTION_CLOSE
	windows.WinVerifyTrustEx(windows.InvalidHWND, &action, &data)

	if err == nil {
		return Code{Trusted: true, Status: "valid"}, ProofBound
	}
	status, verdict := trustVerdict(err)
	return Code{Status: status}, verdict
}

// trustVerdict words a WinVerifyTrust refusal and places it on the ladder. A
// file that carries no signature, or is of a kind that cannot carry one, is
// unsigned; every signature Windows found and refused is invalid, whether the
// bytes changed or the chain failed. Windows has no requirement language, so
// ProofUnmet is never produced here.
func trustVerdict(err error) (string, Proof) {
	var code uintptr
	if e, ok := err.(syscall.Errno); ok {
		code = uintptr(e)
	}
	switch code {
	case trustENoSignature, cryptENotFound:
		return "no signature", ProofUnsigned
	case trustESubjectFormUnknown:
		return "the file is not of a form Authenticode can sign", ProofUnsigned
	case trustEProviderUnknown:
		return "no trust provider for this file type", ProofUnsigned
	case trustEBadDigest:
		return "signed, but the file has been modified since it was signed", ProofInvalid
	case certEUntrustedRoot, certEUntrustedTestRoot:
		return "signed by a certificate chaining to a root this machine does not trust", ProofInvalid
	case certEExpired:
		return "signed by an expired certificate", ProofInvalid
	case certERevoked:
		return "signed by a revoked certificate", ProofInvalid
	case certEChaining:
		return "signed, but the certificate chain could not be built", ProofInvalid
	case cryptERevocationOffline:
		return "revocation status could not be checked", ProofInvalid
	}
	return "not trusted: " + err.Error(), ProofInvalid
}

// signerName pulls the subject and issuer of the signing certificate out of
// the file's embedded PKCS#7 message.
//
// The subject is what a person would read in a consent prompt. It is not on
// its own an identity: certificates are issued to whatever name a CA will
// accept, and two publishers can share a display name. The issuer is reported
// beside it so a policy can pin both, which is the least that makes the pair
// meaningful.
func signerName(pathW *uint16) (subject, issuer string, err error) {
	var (
		encoding, contentType, formatType uint32
		store, msg                        windows.Handle
	)
	err = windows.CryptQueryObject(windows.CERT_QUERY_OBJECT_FILE, unsafe.Pointer(pathW),
		windows.CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED, windows.CERT_QUERY_FORMAT_FLAG_BINARY,
		0, &encoding, &contentType, &formatType, &store, &msg, nil)
	if err != nil {
		return "", "", err
	}
	defer windows.CertCloseStore(store, 0)
	defer cryptMsgClose(msg)

	var n uint32
	if err := cryptMsgGetParam(msg, cmsgSignerCertInfoParam, 0, nil, &n); err != nil {
		return "", "", err
	}
	buf := make([]byte, n)
	if err := cryptMsgGetParam(msg, cmsgSignerCertInfoParam, 0, unsafe.Pointer(&buf[0]), &n); err != nil {
		return "", "", err
	}
	info := (*windows.CertInfo)(unsafe.Pointer(&buf[0]))

	cert, err := windows.CertFindCertificateInStore(store, encoding, 0,
		windows.CERT_FIND_SUBJECT_CERT, unsafe.Pointer(info), nil)
	if err != nil {
		return "", "", err
	}
	defer windows.CertFreeCertificateContext(cert)

	return certName(cert, 0), certName(cert, windows.CERT_NAME_ISSUER_FLAG), nil
}

func certName(cert *windows.CertContext, flags uint32) string {
	n := windows.CertGetNameString(cert, windows.CERT_NAME_SIMPLE_DISPLAY_TYPE, flags, nil, nil, 0)
	if n <= 1 {
		return ""
	}
	buf := make([]uint16, n)
	windows.CertGetNameString(cert, windows.CERT_NAME_SIMPLE_DISPLAY_TYPE, flags, nil, &buf[0], n)
	return windows.UTF16ToString(buf)
}
