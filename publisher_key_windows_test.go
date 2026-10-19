//go:build windows

package identity

import (
	"crypto/sha256"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"syscall"
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"
)

func TestAcceptedPublisherKeySharesHeldVerificationAndClearsOnRefusal(t *testing.T) {
	path := filepath.Join(t.TempDir(), "inert.exe")
	if err := os.WriteFile(path, make([]byte, 512), 0600); err != nil {
		t.Fatal(err)
	}
	previous := winTrustCall
	t.Cleanup(func() { winTrustCall = previous })
	key := "authenticode-dn-sha256:" + strings.Repeat("a", 64)
	var refused bool
	winTrustCall = func(choice uint32, subject unsafe.Pointer, revocation bool) (trustSigner, error) {
		if choice != windows.WTD_CHOICE_FILE || !revocation || (*windows.WinTrustFileInfo)(subject).File == 0 {
			t.Fatal("publisher evidence used another verification boundary")
		}
		if writable, err := os.OpenFile(path, os.O_WRONLY, 0); err == nil {
			writable.Close()
			t.Fatal("signature custody admitted writer")
		}
		if refused {
			return trustSigner{publisherKey: key}, syscall.Errno(certERevoked)
		}
		return trustSigner{subject: "Display publisher", issuer: "Accepted issuer", publisherKey: key}, nil
	}
	opts := &Options{CheckRevocation: true}
	code, proof, publisher, err := VerifyFilePublisher(path, opts)
	if err != nil || !code.Trusted || proof != ProofBound || publisher != key {
		t.Fatal(code, proof, publisher, err)
	}
	legacy, legacyProof, err := VerifyFile(path, opts)
	if err != nil || !reflect.DeepEqual(legacy, code) || legacyProof != proof {
		t.Fatal("additive capture changed existing API", legacy, legacyProof, err)
	}
	refused = true
	code, proof, publisher, err = VerifyFilePublisher(path, opts)
	if err != nil || code.Trusted || proof != ProofInvalid || publisher != "" {
		t.Fatal("revoked verification retained publisher authority", code, proof, publisher, err)
	}
}

func TestAcceptedPublisherKeyUsesFullNativeSubjectDER(t *testing.T) {
	key := func(organization string) string {
		der, err := asn1.Marshal(pkix.Name{CommonName: "Same display name", Organization: []string{organization}}.ToRDNSequence())
		if err != nil {
			t.Fatal(err)
		}
		info := windows.CertInfo{Subject: windows.CertNameBlob{Size: uint32(len(der)), Data: &der[0]}}
		certificate := windows.CertContext{CertInfo: &info}
		got := acceptedPublisherKey(&certificate, windows.ReadProcessMemory)
		hash := sha256.Sum256(der)
		if want := "authenticode-dn-sha256:" + hex.EncodeToString(hash[:]); got != want {
			t.Fatal(got, want)
		}
		runtime.KeepAlive(der)
		runtime.KeepAlive(info)
		runtime.KeepAlive(certificate)
		return got
	}
	if key("publisher one") == key("publisher two") {
		t.Fatal("same CN joined different full publisher names")
	}
}

func TestAcceptedPublisherKeyMissingOrUnboundedEvidenceIsEmpty(t *testing.T) {
	broken := func(windows.Handle, uintptr, *byte, uintptr, *uintptr) error { return errors.New("inert read failure") }
	if acceptedPublisherKey(nil, broken) != "" {
		t.Fatal("missing evidence acquired a key")
	}
	info := windows.CertInfo{Subject: windows.CertNameBlob{Size: 65537}}
	certificate := windows.CertContext{CertInfo: &info}
	if acceptedPublisherKey(&certificate, windows.ReadProcessMemory) != "" || acceptedPublisherKey(&certificate, broken) != "" {
		t.Fatal("unbounded or failed native read acquired a key")
	}
	short := func(_ windows.Handle, _ uintptr, destination *byte, size uintptr, copied *uintptr) error {
		*copied = size - 1
		return nil
	}
	if acceptedPublisherKey(&certificate, short) != "" {
		t.Fatal("short native read acquired a key")
	}
	runtime.KeepAlive(info)
	runtime.KeepAlive(certificate)
}
