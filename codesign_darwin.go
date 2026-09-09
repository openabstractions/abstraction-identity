//go:build darwin && cgo

package identity

// Code signature verification through the Security framework.
//
// This is the call that makes macOS different from Windows: it asks the
// operating system's own code signing machinery about *running code*, selected
// by audit token, rather than about a file on disk. Windows has no equivalent -
// WinVerifyTrust takes a file, and a running process is a mapping of a file
// that may since have been replaced.
//
// Two things this file is careful about, because getting either wrong turns the
// check into decoration:
//
//  1. SecCodeCheckValidity is the call that verifies. SecCodeCopySigningInformation
//     alone reports what the code *claims* - a team identifier read out of it
//     without a validity check is a team identifier anybody can write into their
//     own binary. So nothing here reads signing information until CheckValidity
//     has returned errSecSuccess, and if the caller supplied a requirement it is
//     passed to CheckValidity so the OS enforces it rather than this package
//     comparing strings afterwards.
//
//  2. The audit token is passed through to the Security framework as a token.
//     Taking the pid out of it and calling SecCodeCreateWithPID would put back
//     exactly the race the token exists to remove. kSecGuestAttributeAudit is
//     the public, long-standing route for this and is what is used here.
//     SecCodeCreateWithAuditToken is the newer spelling of the same idea; it is
//     not used because it is not present on every macOS this package supports.
//
// What this file cannot do is make the *token* mean more than the transport it
// came from. Over a unix socket the token names whichever process the socket
// currently points at, so a perfectly valid signature here still only proves
// something about that process. See identity_darwin.go and CONTRACT.md.

/*
#cgo LDFLAGS: -framework CoreFoundation -framework Security
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <CoreFoundation/CoreFoundation.h>
#include <Security/Security.h>

// ai_cfstring copies a CFStringRef into a C buffer, or leaves it empty.
static void ai_cfstring(CFStringRef s, char *out, int outlen) {
	if (s == NULL || outlen <= 0) {
		return;
	}
	if (!CFStringGetCString(s, out, outlen, kCFStringEncodingUTF8)) {
		out[0] = '\0';
	}
}

// ai_status renders an OSStatus the way the operating system words it.
static void ai_status(OSStatus st, char *out, int outlen) {
	CFStringRef s = SecCopyErrorMessageString(st, NULL);
	if (s == NULL) {
		snprintf(out, outlen, "OSStatus %d", (int)st);
		return;
	}
	ai_cfstring(s, out, outlen);
	CFRelease(s);
}

// ai_verify validates the code identified by an audit token and, only if that
// succeeds, reports what the validated signature says.
//
// Returns the OSStatus of the validity check. Every out buffer is left empty on
// any failing path.
static OSStatus ai_verify(const void *token, int tokenlen, const char *requirement,
                          char *ident, int identlen,
                          char *team, int teamlen,
                          char *subject, int subjectlen,
                          char *issuer, int issuerlen,
                          char *path, int pathlen,
                          char *status, int statuslen) {
	ident[0] = team[0] = subject[0] = issuer[0] = path[0] = status[0] = '\0';

	CFDataRef data = CFDataCreate(NULL, (const UInt8 *)token, (CFIndex)tokenlen);
	if (data == NULL) {
		ai_status(errSecAllocate, status, statuslen);
		return errSecAllocate;
	}
	const void *keys[] = { kSecGuestAttributeAudit };
	const void *vals[] = { data };
	CFDictionaryRef attrs = CFDictionaryCreate(NULL, keys, vals, 1,
		&kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
	CFRelease(data);
	if (attrs == NULL) {
		ai_status(errSecAllocate, status, statuslen);
		return errSecAllocate;
	}

	SecCodeRef code = NULL;
	OSStatus st = SecCodeCopyGuestWithAttributes(NULL, attrs, kSecCSDefaultFlags, &code);
	CFRelease(attrs);
	if (st != errSecSuccess || code == NULL) {
		ai_status(st, status, statuslen);
		return st;
	}

	SecRequirementRef req = NULL;
	if (requirement != NULL && requirement[0] != '\0') {
		CFStringRef rs = CFStringCreateWithCString(NULL, requirement, kCFStringEncodingUTF8);
		if (rs == NULL) {
			CFRelease(code);
			ai_status(errSecAllocate, status, statuslen);
			return errSecAllocate;
		}
		st = SecRequirementCreateWithString(rs, kSecCSDefaultFlags, &req);
		CFRelease(rs);
		if (st != errSecSuccess) {
			CFRelease(code);
			ai_status(st, status, statuslen);
			return st;
		}
	}

	// The verification. Nothing below runs unless this succeeds.
	st = SecCodeCheckValidity(code, kSecCSDefaultFlags, req);
	if (req != NULL) {
		CFRelease(req);
	}
	ai_status(st, status, statuslen);
	if (st != errSecSuccess) {
		CFRelease(code);
		return st;
	}
	snprintf(status, statuslen, "valid");

	CFDictionaryRef info = NULL;
	if (SecCodeCopySigningInformation(code,
			kSecCSSigningInformation | kSecCSRequirementInformation,
			&info) == errSecSuccess && info != NULL) {
		ai_cfstring((CFStringRef)CFDictionaryGetValue(info, kSecCodeInfoIdentifier), ident, identlen);
		ai_cfstring((CFStringRef)CFDictionaryGetValue(info, kSecCodeInfoTeamIdentifier), team, teamlen);

		CFArrayRef certs = (CFArrayRef)CFDictionaryGetValue(info, kSecCodeInfoCertificates);
		if (certs != NULL && CFArrayGetCount(certs) > 0) {
			SecCertificateRef leaf = (SecCertificateRef)CFArrayGetValueAtIndex(certs, 0);
			CFStringRef s = SecCertificateCopySubjectSummary(leaf);
			ai_cfstring(s, subject, subjectlen);
			if (s != NULL) {
				CFRelease(s);
			}
			if (CFArrayGetCount(certs) > 1) {
				SecCertificateRef ca = (SecCertificateRef)CFArrayGetValueAtIndex(certs, 1);
				CFStringRef is = SecCertificateCopySubjectSummary(ca);
				ai_cfstring(is, issuer, issuerlen);
				if (is != NULL) {
					CFRelease(is);
				}
			}
		}
		CFRelease(info);
	}

	CFURLRef url = NULL;
	if (SecCodeCopyPath(code, kSecCSDefaultFlags, &url) == errSecSuccess && url != NULL) {
		CFStringRef p = CFURLCopyFileSystemPath(url, kCFURLPOSIXPathStyle);
		ai_cfstring(p, path, pathlen);
		if (p != NULL) {
			CFRelease(p);
		}
		CFRelease(url);
	}

	CFRelease(code);
	return errSecSuccess;
}
*/
import "C"

import "unsafe"

func codeCeiling() (Proof, string) {
	return ProofBound, "the Security framework validates the signature of running code selected by audit token, which is more than Windows can do for an unpackaged program - but over a unix socket the token only names the process the socket currently points at, so the answer is worth what that binding is worth; " + whyNoXPC
}

// verifyAuditToken validates the code the token names and reports what the
// validated signature says. The second result is the signing identifier (the
// bundle id for an application), the third the path of the verified code.
func verifyAuditToken(token auditToken, opts *Options) (Code, string, string, error) {
	var (
		ident   [256]C.char
		team    [64]C.char
		subject [512]C.char
		issuer  [512]C.char
		path    [1024]C.char
		status  [512]C.char
	)

	var req *C.char
	if r := opts.codeRequirement(); r != "" {
		req = C.CString(r)
		defer C.free(unsafe.Pointer(req))
	}

	tok := token // addressable copy; the token is 32 bytes of plain data
	st := C.ai_verify(
		unsafe.Pointer(&tok[0]), C.int(unsafe.Sizeof(tok)), req,
		&ident[0], C.int(len(ident)),
		&team[0], C.int(len(team)),
		&subject[0], C.int(len(subject)),
		&issuer[0], C.int(len(issuer)),
		&path[0], C.int(len(path)),
		&status[0], C.int(len(status)),
	)

	code := Code{
		Subject: C.GoString(&subject[0]),
		Issuer:  C.GoString(&issuer[0]),
		TeamID:  C.GoString(&team[0]),
		Status:  C.GoString(&status[0]),
		Trusted: st == 0, // errSecSuccess
	}
	if code.Status == "" {
		code.Status = "no verdict"
	}
	if !code.Trusted {
		// A failed check is an answer, not an error: unsigned, expired
		// and tampered-with are all things a service needs to be told,
		// and none of them may carry an identifier or a path out of this
		// function.
		return code, "", "", nil
	}
	if code.Subject == "" && code.TeamID != "" {
		// Platform binaries validate against the system's own anchor and
		// carry no leaf certificate to name.
		code.Subject = "team " + code.TeamID
	}
	return code, C.GoString(&ident[0]), C.GoString(&path[0]), nil
}
