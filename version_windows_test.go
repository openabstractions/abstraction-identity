//go:build windows

package identity

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"unicode/utf16"
	"unsafe"

	"golang.org/x/sys/windows"
)

// TestVerifyFileNamesTheProgramByItsVersionResource: a trusted file carries
// FileDescription and OriginalFilename of its own (neutral) version resource,
// the values GetFileVersionInfoEx returns with FILE_VER_GET_NEUTRAL; the
// localized .mui's OriginalFilename (PowerShell.EXE.MUI) is never reported.
// An unmodified copy of powershell.exe outside the Windows directory reads
// unsigned and names nothing, although it carries the same resource (VISION
// 2026-10-01, ID-W4).
func TestVerifyFileNamesTheProgramByItsVersionResource(t *testing.T) {
	code, proof, err := VerifyFile(systemPowerShell, nil)
	if err != nil || proof != ProofBound || !code.Catalog ||
		code.Description != "Windows PowerShell" || code.OriginalName != "PowerShell.EXE" {
		t.Fatalf("VerifyFile(%q) = %s %v %v", systemPowerShell, named(code), proof, err)
	}

	git := signedGit(t)
	code, proof, err = VerifyFile(git, nil)
	if err != nil || proof != ProofBound || code.Catalog || code.Description != "Git for Windows" || code.OriginalName != "git.exe" {
		t.Fatalf("VerifyFile(%q) = %s %v %v", git, named(code), proof, err)
	}

	data, err := os.ReadFile(systemPowerShell)
	if err != nil {
		t.Fatal(err)
	}
	renamed := filepath.Join(t.TempDir(), "OllamaHelper.exe")
	if err := os.WriteFile(renamed, data, 0o600); err != nil {
		t.Fatal(err)
	}
	if v, err := readVersionResource(bytes.NewReader(data)); err != nil || v.description != "Windows PowerShell" {
		t.Fatalf("the copy must carry the resource for this test to mean anything: %+v %v", v, err)
	}
	exe := mustExe(t)
	for _, path := range []string{renamed, exe} {
		code, proof, err := VerifyFile(path, nil)
		if err != nil || proof != ProofUnsigned || code.Description != "" || code.OriginalName != "" {
			t.Fatalf("an unsigned file must name no program: VerifyFile(%q) = %s %v %v", path, named(code), proof, err)
		}
	}
}

// TestVerifyFileNamesNoProgramForAModifiedFile: a signed file whose bytes
// changed is invalid, and its version resource is not reported.
func TestVerifyFileNamesNoProgramForAModifiedFile(t *testing.T) {
	data, err := os.ReadFile(signedGit(t))
	if err != nil {
		t.Fatal(err)
	}
	at := descriptionOffset(t, data, "Git for Windows")
	copy(data[at:], utf16le("Gut"))
	modified := filepath.Join(t.TempDir(), "git.exe")
	if err := os.WriteFile(modified, data, 0o600); err != nil {
		t.Fatal(err)
	}
	code, proof, err := VerifyFile(modified, nil)
	if err != nil || proof != ProofInvalid || code.Description != "" || code.OriginalName != "" {
		t.Fatalf("modified signed file: %s %v %v", named(code), proof, err)
	}
}

// gitCopy copies git.exe into a temporary directory and returns the copy and
// the offset of its FileDescription.
func gitCopy(t *testing.T) (string, int) {
	t.Helper()
	data, err := os.ReadFile(signedGit(t))
	if err != nil {
		t.Fatal(err)
	}
	at := descriptionOffset(t, data, "Git for Windows")
	copied := filepath.Join(t.TempDir(), "git.exe")
	if err := os.WriteFile(copied, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return copied, at
}

// duringVerification runs during every WinVerifyTrust call, after Windows
// answered, until the test ends.
func duringVerification(t *testing.T, during func()) {
	t.Helper()
	previous := winTrustCall
	t.Cleanup(func() { winTrustCall = previous })
	winTrustCall = func(choice uint32, subject unsafe.Pointer, revocation bool) error {
		verdict := previous(choice, subject, revocation)
		during()
		return verdict
	}
}

// TestVerifyFileHoldsTheFileAgainstWriters: while VerifyFile holds a file,
// an open for writing fails with a sharing violation, and the answer names
// the bytes Windows verified (ID-W4). A file another handle already holds
// open for writing is refused at the open.
func TestVerifyFileHoldsTheFileAgainstWriters(t *testing.T) {
	copied, _ := gitCopy(t)
	var opened error
	calls := 0
	duringVerification(t, func() {
		calls++
		f, err := os.OpenFile(copied, os.O_WRONLY, 0)
		if err == nil {
			f.Close()
		}
		opened = err
	})
	code, proof, err := VerifyFile(copied, nil)
	if calls == 0 || !errors.Is(opened, windows.ERROR_SHARING_VIOLATION) {
		t.Fatalf("an open for writing during verification must be a sharing violation, got %v (%d verifications)", opened, calls)
	}
	if err != nil || proof != ProofBound || code.Description != "Git for Windows" {
		t.Fatalf("VerifyFile(%q) = %s %v %v", copied, named(code), proof, err)
	}

	winTrustCall = winTrust
	writer, err := os.OpenFile(copied, os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer writer.Close()
	if _, proof, err := VerifyFile(copied, nil); !errors.Is(err, windows.ERROR_SHARING_VIOLATION) || proof != ProofNone {
		t.Fatalf("a file open for writing must be refused at the open: %v %v", proof, err)
	}
}

// TestVersionResourceIsTheVerifiedBytes: through a handle that shares write
// access, a version resource rewritten after Windows verified the file is not
// reported; the verification is abandoned, as for a file that moved (ID-W4).
func TestVersionResourceIsTheVerifiedBytes(t *testing.T) {
	copied, at := gitCopy(t)
	duringVerification(t, func() {
		f, err := os.OpenFile(copied, os.O_WRONLY, 0)
		if err != nil {
			t.Errorf("rewrite: %v", err)
			return
		}
		defer f.Close()
		if _, err := f.WriteAt(utf16le("Bad"), int64(at)); err != nil {
			t.Errorf("rewrite: %v", err)
		}
	})
	file, pathW := openSharingWrite(t, copied)
	code, proof, err := verifyHeld(file, pathW, false)
	if err == nil || proof != ProofNone || code.Description != "" {
		t.Fatalf("a resource rewritten after verification must abandon it: description %q, %v %v", code.Description, proof, err)
	}
}

// TestVersionResourceReadFailureAbandonsVerification: a trusted file whose
// version resource read fails in the operating system is abandoned, whether
// the read before or after the verification fails. A truncated or empty image
// is a missing resource, never a read failure.
func TestVersionResourceReadFailureAbandonsVerification(t *testing.T) {
	copied, _ := gitCopy(t)
	// failing names the read that fails; 0 fails both.
	for _, failing := range []int{0, 1, 2} {
		reads := 0
		previous := versionSource
		versionSource = func(file windows.Handle) io.ReaderAt {
			reads++
			if failing == 0 || reads == failing {
				return failingReader{}
			}
			return heldFile(file)
		}
		code, proof, err := VerifyFile(copied, nil)
		versionSource = previous
		if !errors.Is(err, errUnreadable) || proof != ProofNone || code.Description != "" {
			t.Fatalf("read %d failing: %s %v %v", failing, named(code), proof, err)
		}
	}
	if _, err := readVersionResource(failingReader{}); !errors.Is(err, errUnreadable) {
		t.Fatalf("a failed read must be reported as one: %v", err)
	}
	if _, err := readVersionResource(bytes.NewReader([]byte("MZ"))); err == nil || errors.Is(err, errUnreadable) {
		t.Fatalf("a truncated image is no read failure: %v", err)
	}
	if v, err := readVersionResource(bytes.NewReader(nil)); err == nil || errors.Is(err, errUnreadable) {
		t.Fatalf("an empty file has no resource and no read failure: %+v %v", v, err)
	}
}

type failingReader struct{}

func (failingReader) ReadAt([]byte, int64) (int, error) {
	return 0, fmt.Errorf("%w: %w", errUnreadable, windows.ERROR_IO_DEVICE)
}

// openSharingWrite opens path the way verifyImage opens a running image, with
// write sharing, and returns the handle and the path verifyHeld takes.
func openSharingWrite(t *testing.T, path string) (windows.Handle, *uint16) {
	t.Helper()
	pathW, err := windows.UTF16PtrFromString(path)
	if err != nil {
		t.Fatal(err)
	}
	file, err := windows.CreateFile(pathW, windows.GENERIC_READ,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil, windows.OPEN_EXISTING, windows.FILE_ATTRIBUTE_NORMAL, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { windows.CloseHandle(file) })
	return file, pathW
}

// TestPeerImageNamesTheProgramByItsVersionResource: a peer's image is read
// the same way through verifyImage. The peer is cmd.exe, catalog-signed,
// waiting on its input.
func TestPeerImageNamesTheProgramByItsVersionResource(t *testing.T) {
	cmdPath := filepath.Join(os.Getenv("SystemRoot"), "System32", "cmd.exe")
	child := exec.Command(cmdPath, "/q", "/k")
	stdin, err := child.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := child.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		stdin.Close()
		child.Wait()
	})
	proc, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, uint32(child.Process.Pid))
	if err != nil {
		t.Fatal(err)
	}
	defer windows.CloseHandle(proc)
	path, err := processImagePath(proc)
	if err != nil {
		t.Fatal(err)
	}
	code, proof, err := verifyImage(proc, path, nil)
	if err != nil || proof != ProofBound || code.Description != "Windows Command Processor" || code.OriginalName != "Cmd.Exe" {
		t.Fatalf("verifyImage(%q) = %s %v %v", path, named(code), proof, err)
	}
}

// TestParseVersionInfoChoosesTheTranslatedTable: both strings come from the
// table VarFileInfo\Translation names, the first table otherwise.
func TestParseVersionInfoChoosesTheTranslatedTable(t *testing.T) {
	tables := []versionNode{
		node("040704b0", nil, node("FileDescription", text("Erste")), node("OriginalFilename", text("erste.exe"))),
		node("040904b0", nil, node("FileDescription", text(" Second ")), node("OriginalFilename", text("second.exe"))),
	}
	translated := node("VS_VERSION_INFO", make([]byte, 52),
		node("StringFileInfo", nil, tables...),
		node("VarFileInfo", nil, node("Translation", []byte{0x09, 0x04, 0xb0, 0x04})))
	v, err := parseVersionInfo(translated.encode())
	if err != nil || v != (imageVersion{"Second", "second.exe"}) {
		t.Fatalf("translated table: %+v %v", v, err)
	}
	untranslated := node("VS_VERSION_INFO", make([]byte, 52), node("StringFileInfo", nil, tables...))
	v, err = parseVersionInfo(untranslated.encode())
	if err != nil || v != (imageVersion{"Erste", "erste.exe"}) {
		t.Fatalf("first table: %+v %v", v, err)
	}
	if _, err := parseVersionInfo(node("SOMETHING_ELSE", nil).encode()); err == nil {
		t.Fatal("a block that is not VS_VERSION_INFO must be refused")
	}
}

// TestVersionResourceReaderToleratesDamagedImages: every truncation of a real
// image and of its version resource, and every single-byte change of the
// resource, returns without a panic.
func TestVersionResourceReaderToleratesDamagedImages(t *testing.T) {
	data, err := os.ReadFile(systemPowerShell)
	if err != nil {
		t.Skip(err)
	}
	for n := 0; n < len(data); n += 1 + n/64 {
		readVersionResource(bytes.NewReader(data[:n]))
	}
	resource := bytes.Index(data, utf16le("VS_VERSION_INFO"))
	if resource < 6 {
		t.Fatal("powershell.exe carries no VS_VERSION_INFO")
	}
	block := data[resource-6:]
	length := int(binary.LittleEndian.Uint16(block))
	block = append([]byte(nil), block[:length]...)
	for n := range block {
		parseVersionInfo(block[:n])
	}
	for i := range block {
		for _, b := range []byte{0x00, 0xff} {
			damaged := append([]byte(nil), block...)
			damaged[i] = b
			parseVersionInfo(damaged)
		}
	}
}

// named prints a Code with the version strings its String method leaves out.
func named(c Code) string {
	return fmt.Sprintf("%s description=%q original=%q", c, c.Description, c.OriginalName)
}

// descriptionOffset is the offset of description inside the file's
// VS_VERSIONINFO resource.
func descriptionOffset(t *testing.T, data []byte, description string) int {
	t.Helper()
	resource := bytes.Index(data, utf16le("VS_VERSION_INFO"))
	if resource < 0 {
		t.Fatal("the file carries no VS_VERSION_INFO")
	}
	at := bytes.Index(data[resource:], utf16le(description))
	if at < 0 {
		t.Fatalf("the file's version resource carries no %q", description)
	}
	return resource + at
}

func utf16le(s string) []byte {
	var out []byte
	for _, u := range utf16.Encode([]rune(s)) {
		out = binary.LittleEndian.AppendUint16(out, u)
	}
	return out
}

// versionNode builds a VS_VERSIONINFO block for the parser tests.
type versionNode struct {
	key      string
	value    []byte
	children []versionNode
}

func node(key string, value []byte, children ...versionNode) versionNode {
	return versionNode{key: key, value: value, children: children}
}

// text makes a String block's value: UTF-16 with its terminator.
func text(s string) []byte { return append(utf16le(s), 0, 0) }

func (n versionNode) encode() []byte {
	out := make([]byte, 6)
	out = append(out, utf16le(n.key)...)
	out = append(out, 0, 0)
	for len(out)%4 != 0 {
		out = append(out, 0)
	}
	valueLength := len(n.value)
	isText := strings.HasPrefix(n.key, "File") || strings.HasPrefix(n.key, "Original")
	if isText {
		valueLength /= 2
	}
	out = append(out, n.value...)
	for _, c := range n.children {
		for len(out)%4 != 0 {
			out = append(out, 0)
		}
		out = append(out, c.encode()...)
	}
	binary.LittleEndian.PutUint16(out, uint16(len(out)))
	binary.LittleEndian.PutUint16(out[2:], uint16(valueLength))
	if isText {
		binary.LittleEndian.PutUint16(out[4:], 1)
	}
	return out
}
