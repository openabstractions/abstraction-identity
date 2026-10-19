//go:build windows

package identity

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"sync"
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

	code, verdict, err := verifyHeld(file, pathW, opts.checkRevocation())
	if err != nil {
		return Code{}, ProofNone, fmt.Errorf("verification abandoned: %w", err)
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
	return stillSameFile(file, want)
}

// stillSameFile requires the file an open handle names to be at want: the
// kernel's final path for the handle, with its \\?\ prefix removed, and want
// must name one file by file identity (samePath, which is SameFile: the
// volume serial number and file ID). A want in another case, an 8.3 alias or
// a path through a junction or symbolic link to that file passes; a want that
// names another file or no file fails, as after a rename or delete.
func stillSameFile(file windows.Handle, want string) error {
	got, err := handleFinalPath(file)
	if err != nil {
		return err
	}
	return sameFinalPath(got, want)
}

// sameFinalPath is stillSameFile's comparison.
func sameFinalPath(got, want string) error {
	if !samePath(got, want) {
		return fmt.Errorf("the file that was verified is now at %q, not %q", got, want)
	}
	return nil
}

// handleFinalPath is the normalized DOS path the kernel reports for an open
// handle, after junctions and symbolic links, without its \\?\ prefix. A file
// on a network share reads UNC\server\share\... in this form.
func handleFinalPath(file windows.Handle) (string, error) {
	buf := make([]uint16, windows.MAX_LONG_PATH)
	n, err := windows.GetFinalPathNameByHandle(file, &buf[0], uint32(len(buf)), fileNameNormalized|volumeNameDOS)
	if err != nil {
		return "", fmt.Errorf("the verified file could no longer be named: %w", err)
	}
	if n == 0 || n >= uint32(len(buf)) {
		return "", fmt.Errorf("the verified file path exceeds the buffer")
	}
	return strings.TrimPrefix(windows.UTF16ToString(buf[:n]), `\\?\`), nil
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
//
// WinVerifyTrust over a file reads only the signature embedded in it. A file
// with none that lies under the Windows directory is looked up in the system
// catalogs by its hash (verifyCatalog); many Windows binaries, powershell.exe
// among them, are signed only there. The system catalogs list the operating
// system's files, and a file with no embedded signature anywhere else is
// unsigned without a lookup, which would hash the whole file again: about
// 4.4 ms per MB, paid on a peer's first connection and every five minutes
// after (ID-W2).
func verifyTrust(file windows.Handle, pathW *uint16, revocation bool) (Code, Proof) {
	return verifyTrustCaptured(file, pathW, revocation, nil)
}

func verifyTrustCaptured(file windows.Handle, pathW *uint16, revocation bool, publisherKey *string) (Code, Proof) {
	if publisherKey != nil {
		*publisherKey = ""
	}
	fi := windows.WinTrustFileInfo{
		Size:     uint32(unsafe.Sizeof(windows.WinTrustFileInfo{})),
		FilePath: pathW,
		File:     file,
	}
	signer, err := winTrustCall(windows.WTD_CHOICE_FILE, unsafe.Pointer(&fi), revocation)
	if err == nil {
		if publisherKey != nil {
			*publisherKey = signer.publisherKey
		}
		return Code{Trusted: true, Status: "valid", Subject: signer.subject, Issuer: signer.issuer}, ProofBound
	}
	status, verdict := trustVerdict(err)
	if verdict == ProofUnsigned && inWindowsDirectory(file) {
		if code, verdict, listed := verifyCatalog(file, pathW, revocation); listed {
			return code, verdict
		}
	}
	return Code{Status: status}, verdict
}

// windowsDirectory is the final path of the system Windows directory
// (GetSystemWindowsDirectory), in handleFinalPath's form.
var windowsDirectory = sync.OnceValues(func() (string, error) {
	dir, err := windows.GetSystemWindowsDirectory()
	if err != nil {
		return "", err
	}
	dirW, err := windows.UTF16PtrFromString(dir)
	if err != nil {
		return "", err
	}
	h, err := windows.CreateFile(dirW, 0,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil, windows.OPEN_EXISTING, windows.FILE_FLAG_BACKUP_SEMANTICS, 0)
	if err != nil {
		return "", err
	}
	defer windows.CloseHandle(h)
	return handleFinalPath(h)
})

// inWindowsDirectory reports whether the open file's final path lies under the
// Windows directory's final path. A path that cannot be read is outside it.
func inWindowsDirectory(file windows.Handle) bool {
	dir, err := windowsDirectory()
	if err != nil {
		return false
	}
	final, err := handleFinalPath(file)
	if err != nil {
		return false
	}
	return underDirectory(final, dir)
}

// underDirectory reports whether path lies strictly inside dir, by file
// identity (Within), so C:\WindowsApps is outside C:\Windows.
func underDirectory(path, dir string) bool {
	ok, _ := Within(path, dir)
	return ok
}

// catalogHash is the member-hash algorithm the lookup uses. Measured
// 2026-10-01 on Windows 11 (26200): every one of 3394 files without an
// embedded signature under System32 (executables and libraries), SysWOW64,
// the Windows directory itself and Windows PowerShell's folder matched a
// catalog under SHA-256; none needed SHA-1.
const catalogHash = "SHA256"

// maxCatalogs bounds the catalogs examined for one hash. An inbox file is
// listed by a few.
const maxCatalogs = 64

// verifyCatalog finds the system catalogs that list the open file's hash and
// verifies the file as a member of each in turn, under winTrust's policy. The
// first catalog Windows accepts gives a trusted Code with Catalog set and that
// catalog's signer copied from that accepted native trust state.
//
// A refusal on the unsigned rung (TRUST_E_NOSIGNATURE, CRYPT_E_NOT_FOUND)
// means that catalog does not list the file, a stale index entry, and the
// search goes on. listed is false when no catalog verifies the file and none
// refused it on another rung: the file is then unsigned. A file a catalog
// refused on another rung (a bad digest, an untrusted chain) is invalid with
// the first such refusal's wording. Every catalog context and the
// administrator context are released before it returns.
func verifyCatalog(file windows.Handle, pathW *uint16, revocation bool) (code Code, verdict Proof, listed bool) {
	admin, err := cryptCATAdminAcquireContext2(catalogHash)
	if err != nil {
		return Code{}, ProofUnsigned, false
	}
	defer cryptCATAdminReleaseContext(admin)
	hash, err := cryptCATAdminCalcHashFromFileHandle2(admin, file)
	if err != nil {
		return Code{}, ProofUnsigned, false
	}
	tag, err := windows.UTF16PtrFromString(strings.ToUpper(hex.EncodeToString(hash)))
	if err != nil {
		return Code{}, ProofUnsigned, false
	}
	var refusal error
	var prev windows.Handle
	for range maxCatalogs {
		info := cryptCATAdminEnumCatalogFromHash(admin, hash, &prev)
		if info == 0 {
			// The enumeration released the last context it returned.
			prev = 0
			break
		}
		prev = info
		code, refused, err := catalogMember(admin, info, tag, hash, file, pathW, revocation)
		if err == nil && refused == nil {
			cryptCATAdminReleaseCatalogContext(admin, info)
			return code, ProofBound, true
		}
		if refused != nil && refusal == nil {
			if _, rung := trustVerdict(refused); rung != ProofUnsigned {
				refusal = refused
			}
		}
	}
	if prev != 0 {
		cryptCATAdminReleaseCatalogContext(admin, prev)
	}
	if refusal == nil {
		return Code{}, ProofUnsigned, false
	}
	status, verdict := trustVerdict(refusal)
	return Code{Status: "listed by a system catalog Windows refused: " + status, Catalog: true}, verdict, true
}

// catalogMember verifies the open file as the member tag of the catalog info
// names and, when Windows accepts it, reads that catalog's signer. The catalog
// file is held open across the verification and the signer read, and its
// handle must still name the catalog's path afterwards, as stillSameFile
// requires of the member file itself. refusal is WinVerifyTrust's verdict on a
// catalog it refused; err is a catalog that could not be read.
func catalogMember(admin, info windows.Handle, tag *uint16, hash []byte, file windows.Handle, pathW *uint16, revocation bool) (code Code, refusal, err error) {
	var ci catalogInfo
	if err := cryptCATCatalogInfoFromContext(info, &ci); err != nil {
		return Code{}, nil, err
	}
	catalogW := &ci.CatalogFile[0]
	catalogPath := windows.UTF16ToString(ci.CatalogFile[:])
	catalog, err := windows.CreateFile(catalogW, windows.GENERIC_READ,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil, windows.OPEN_EXISTING, windows.FILE_ATTRIBUTE_NORMAL, 0)
	if err != nil {
		return Code{}, nil, err
	}
	defer windows.CloseHandle(catalog)

	member := wintrustCatalogInfo{
		Size:               uint32(unsafe.Sizeof(wintrustCatalogInfo{})),
		CatalogFilePath:    catalogW,
		MemberTag:          tag,
		MemberFilePath:     pathW,
		MemberFile:         file,
		CalculatedHash:     &hash[0],
		CalculatedHashSize: uint32(len(hash)),
		CatAdmin:           admin,
	}
	signer, refusal := winTrustCall(windows.WTD_CHOICE_CATALOG, unsafe.Pointer(&member), revocation)
	if refusal != nil {
		return Code{}, refusal, nil
	}
	code = Code{Trusted: true, Catalog: true, Status: "valid, signed through a system catalog", Subject: signer.subject, Issuer: signer.issuer}
	if err := stillSameFile(catalog, catalogPath); err != nil {
		return Code{}, nil, err
	}
	return code, nil, nil
}

// winTrustCall is winTrust; tests observe and answer the verifications
// through it.
var winTrustCall = winTrust

// winTrust is the one Authenticode policy this package applies: a
// WinVerifyTrust call over the subject choice names (a file, or a catalog
// member), with the trust state closed afterwards whatever the verdict.
func winTrust(choice uint32, subject unsafe.Pointer, revocation bool) (trustSigner, error) {
	data := windows.WinTrustData{
		Size:                            uint32(unsafe.Sizeof(windows.WinTrustData{})),
		UIChoice:                        windows.WTD_UI_NONE,
		RevocationChecks:                windows.WTD_REVOKE_NONE,
		UnionChoice:                     choice,
		FileOrCatalogOrBlobOrSgnrOrCert: subject,
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
	var signer trustSigner
	if err == nil {
		// Copy strings while the accepted provider state owns the certificate.
		// A missing helper/state/certificate supplies no publisher evidence.
		signer = acceptedTrustSigner(data.StateData)
	}

	// Always close the trust state, whatever the verdict, or the provider
	// leaks per call.
	data.StateAction = windows.WTD_STATEACTION_CLOSE
	windows.WinVerifyTrustEx(windows.InvalidHWND, &action, &data)
	return signer, err
}

type trustSigner struct{ subject, issuer, publisherKey string }

// acceptedTrustSigner reads the primary signer (index zero, not its timestamp
// countersigner) from this verification's provider state. The helpers return
// borrowed pointers. All names are copied before WTD_STATEACTION_CLOSE; no
// certificate context or provider pointer escapes that lifetime. A catalog
// member's provider state names the catalog signer Windows accepted.
func acceptedTrustSigner(state windows.Handle) trustSigner {
	if state == 0 || procWTHelperProvDataFromStateData.Find() != nil ||
		procWTHelperGetProvSignerFromChain.Find() != nil || procWTHelperGetProvCertFromChain.Find() != nil {
		return trustSigner{}
	}
	provider, _, _ := procWTHelperProvDataFromStateData.Call(uintptr(state))
	if provider == 0 {
		return trustSigner{}
	}
	signer, _, _ := procWTHelperGetProvSignerFromChain.Call(provider, 0, 0, 0)
	if signer == 0 {
		return trustSigner{}
	}
	certificate, _, _ := procWTHelperGetProvCertFromChain.Call(signer, 0)
	if certificate == 0 {
		return trustSigner{}
	}
	// Only this documented prefix of CRYPT_PROVIDER_CERT is read. The SDK
	// places pCert after cbStruct with native pointer alignment.
	cert := trustProviderCertificate(certificate, windows.ReadProcessMemory)
	if cert == nil {
		return trustSigner{}
	}
	return trustSigner{subject: certName(cert, 0), issuer: certName(cert, windows.CERT_NAME_ISSUER_FLAG), publisherKey: acceptedPublisherKey(cert, windows.ReadProcessMemory)}
}

// P-06 uses the full DER subject Windows accepted, rather than the display CN
// or a renewal-fragile leaf thumbprint. Copy all borrowed bytes while WinTrust
// still owns its provider state. A failed or unbounded read supplies no key.
func acceptedPublisherKey(cert *windows.CertContext, read func(windows.Handle, uintptr, *byte, uintptr, *uintptr) error) string {
	copyNative := func(address uintptr, destination unsafe.Pointer, size uintptr) bool {
		var copied uintptr
		return address != 0 && read(windows.CurrentProcess(), address, (*byte)(destination), size, &copied) == nil && copied == size
	}
	var context windows.CertContext
	if cert == nil || !copyNative(uintptr(unsafe.Pointer(cert)), unsafe.Pointer(&context), unsafe.Sizeof(context)) {
		return ""
	}
	var info windows.CertInfo
	if !copyNative(uintptr(unsafe.Pointer(context.CertInfo)), unsafe.Pointer(&info), unsafe.Sizeof(info)) || info.Subject.Size == 0 || info.Subject.Size > 65536 {
		return ""
	}
	der := make([]byte, info.Subject.Size)
	if !copyNative(uintptr(unsafe.Pointer(info.Subject.Data)), unsafe.Pointer(&der[0]), uintptr(len(der))) {
		return ""
	}
	hash := sha256.Sum256(der)
	return "authenticode-dn-sha256:" + hex.EncodeToString(hash[:])
}

type trustProviderCert struct {
	size uint32
	cert *windows.CertContext
}

// trustProviderCertificate copies the fixed native prefix into Go-owned
// storage. The returned certificate is still borrowed from the open WinTrust
// state; acceptedTrustSigner copies its names before that state closes.
func trustProviderCertificate(address uintptr, read func(windows.Handle, uintptr, *byte, uintptr, *uintptr) error) *windows.CertContext {
	if address == 0 {
		return nil
	}
	var prefix trustProviderCert
	var copied uintptr
	size := unsafe.Sizeof(prefix)
	// CurrentProcess is a pseudo-handle and creates no handle to close.
	if err := read(windows.CurrentProcess(), address, (*byte)(unsafe.Pointer(&prefix)), size, &copied); err != nil || copied != size {
		return nil
	}
	if prefix.size < uint32(size) || prefix.cert == nil {
		return nil
	}
	return prefix.cert
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

func certName(cert *windows.CertContext, flags uint32) string {
	n := windows.CertGetNameString(cert, windows.CERT_NAME_SIMPLE_DISPLAY_TYPE, flags, nil, nil, 0)
	if n <= 1 {
		return ""
	}
	buf := make([]uint16, n)
	windows.CertGetNameString(cert, windows.CERT_NAME_SIMPLE_DISPLAY_TYPE, flags, nil, &buf[0], n)
	return windows.UTF16ToString(buf)
}
