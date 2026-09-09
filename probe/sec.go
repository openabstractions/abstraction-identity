//go:build darwin && cgo

package main

/*
#cgo LDFLAGS: -framework CoreFoundation -framework Security
#include <stdio.h>
#include <string.h>
#include <CoreFoundation/CoreFoundation.h>
#include <Security/Security.h>

static void s_cfstring(CFStringRef s, char *out, int outlen) {
	if (s == NULL || outlen <= 0) { return; }
	if (!CFStringGetCString(s, out, outlen, kCFStringEncodingUTF8)) { out[0] = '\0'; }
}

static void s_status(OSStatus st, char *out, int outlen) {
	CFStringRef s = SecCopyErrorMessageString(st, NULL);
	if (s == NULL) { snprintf(out, outlen, "OSStatus %d", (int)st); return; }
	s_cfstring(s, out, outlen);
	CFRelease(s);
}

// s_verify mirrors the package's ai_verify but also reports, separately, whether
// SecCodeCopyGuestWithAttributes accepted the token at all -- so we can tell
// "the token named nothing" from "the token named code that failed to verify".
static int s_verify(const void *token, int tokenlen, char *ident, int identlen,
                    char *team, int teamlen, char *subject, int subjectlen,
                    char *path, int pathlen, char *status, int statuslen,
                    char *gueststatus, int gueststatuslen, int *flags) {
	ident[0] = team[0] = subject[0] = path[0] = status[0] = gueststatus[0] = '\0';
	*flags = -1;

	CFDataRef data = CFDataCreate(NULL, (const UInt8 *)token, (CFIndex)tokenlen);
	const void *keys[] = { kSecGuestAttributeAudit };
	const void *vals[] = { data };
	CFDictionaryRef attrs = CFDictionaryCreate(NULL, keys, vals, 1,
		&kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
	CFRelease(data);

	SecCodeRef code = NULL;
	OSStatus gst = SecCodeCopyGuestWithAttributes(NULL, attrs, kSecCSDefaultFlags, &code);
	CFRelease(attrs);
	s_status(gst, gueststatus, gueststatuslen);
	if (gst != errSecSuccess || code == NULL) {
		snprintf(status, statuslen, "guest lookup failed");
		return (int)gst;
	}

	OSStatus st = SecCodeCheckValidity(code, kSecCSDefaultFlags, NULL);
	s_status(st, status, statuslen);

	// Report signing information regardless, so we can show what an
	// unvalidated read would have handed out.
	CFDictionaryRef info = NULL;
	if (SecCodeCopySigningInformation(code,
			kSecCSSigningInformation | kSecCSRequirementInformation, &info) == errSecSuccess
			&& info != NULL) {
		s_cfstring((CFStringRef)CFDictionaryGetValue(info, kSecCodeInfoIdentifier), ident, identlen);
		s_cfstring((CFStringRef)CFDictionaryGetValue(info, kSecCodeInfoTeamIdentifier), team, teamlen);
		CFNumberRef fl = (CFNumberRef)CFDictionaryGetValue(info, kSecCodeInfoFlags);
		if (fl != NULL) { CFNumberGetValue(fl, kCFNumberIntType, flags); }
		CFArrayRef certs = (CFArrayRef)CFDictionaryGetValue(info, kSecCodeInfoCertificates);
		if (certs != NULL && CFArrayGetCount(certs) > 0) {
			CFStringRef s = SecCertificateCopySubjectSummary(
				(SecCertificateRef)CFArrayGetValueAtIndex(certs, 0));
			s_cfstring(s, subject, subjectlen);
			if (s != NULL) { CFRelease(s); }
		}
		CFRelease(info);
	}
	CFURLRef url = NULL;
	if (SecCodeCopyPath(code, kSecCSDefaultFlags, &url) == errSecSuccess && url != NULL) {
		CFStringRef p = CFURLCopyFileSystemPath(url, kCFURLPOSIXPathStyle);
		s_cfstring(p, path, pathlen);
		if (p != NULL) { CFRelease(p); }
		CFRelease(url);
	}
	CFRelease(code);
	return (int)st;
}
*/
import "C"

import (
	"fmt"
	"unsafe"
)

type verdict struct {
	guestStatus string // did SecCodeCopyGuestWithAttributes accept the token
	checkStatus string // did SecCodeCheckValidity pass
	ok          bool
	ident       string
	team        string
	subject     string
	path        string
	flags       int
}

func (v verdict) String() string {
	return fmt.Sprintf("guest=%q check=%q ok=%v ident=%q team=%q subject=%q path=%q cdflags=0x%x",
		v.guestStatus, v.checkStatus, v.ok, v.ident, v.team, v.subject, v.path, uint32(v.flags))
}

func verifyToken(tk token) verdict {
	var ident, team, subject, path, status, guest [512]C.char
	var flags C.int
	t := tk // addressable copy
	st := C.s_verify(
		unsafe.Pointer(&t[0]), C.int(unsafe.Sizeof(t)),
		&ident[0], C.int(len(ident)),
		&team[0], C.int(len(team)),
		&subject[0], C.int(len(subject)),
		&path[0], C.int(len(path)),
		&status[0], C.int(len(status)),
		&guest[0], C.int(len(guest)),
		&flags,
	)
	return verdict{
		guestStatus: C.GoString(&guest[0]),
		checkStatus: C.GoString(&status[0]),
		ok:          st == 0,
		ident:       C.GoString(&ident[0]),
		team:        C.GoString(&team[0]),
		subject:     C.GoString(&subject[0]),
		path:        C.GoString(&path[0]),
		flags:       int(flags),
	}
}
