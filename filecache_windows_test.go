//go:build windows

package identity

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"unsafe"

	"github.com/openabstractions/abstraction-identity/fileid"
	"golang.org/x/sys/windows"
)

// The path is only a native policy hint: signature/resource facts must still
// come from the held x. (or x-space) file, even when Win32 names a decoy x.
func TestHeldSignatureIgnoresTrailingFolderDecoy(t *testing.T) {
	system := os.Getenv("SystemRoot")
	ownPath := filepath.Join(system, "System32", "cmd.exe")
	decoyPath := filepath.Join(system, "System32", "WindowsPowerShell", "v1.0", "powershell.exe")
	want, proof, err := VerifyFile(ownPath, nil)
	if err != nil || proof != ProofBound || !want.Trusted || !SharedInterpreterName(want.OriginalName) {
		t.Fatalf("owned-copy source signature unavailable: %+v %v %v", want, proof, err)
	}
	other, proof, err := VerifyFile(decoyPath, nil)
	if err != nil || proof != ProofBound || !other.Trusted || other.OriginalName == want.OriginalName {
		t.Fatalf("distinct OS signed decoy unavailable: %+v %v %v", other, proof, err)
	}
	ownBytes, err := os.ReadFile(ownPath)
	if err != nil {
		t.Fatal(err)
	}
	decoyBytes, err := os.ReadFile(decoyPath)
	if err != nil {
		t.Fatal(err)
	}
	for _, suffix := range []string{".", " "} {
		t.Run(fmt.Sprintf("suffix-%x", suffix), func(t *testing.T) {
			dir := t.TempDir()
			for _, name := range []string{"x", "x" + suffix} {
				if err := os.Mkdir(`\\?\`+filepath.Join(dir, name), 0o755); err != nil {
					t.Fatal(err)
				}
			}
			own := `\\?\` + filepath.Join(dir, "x"+suffix, "renamed.exe")
			decoy := filepath.Join(dir, "x", "renamed.exe")
			if err := os.WriteFile(own, ownBytes, 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(decoy, decoyBytes, 0o600); err != nil {
				t.Fatal(err)
			}
			if same, err := SameFile(own, decoy); err != nil || same {
				t.Fatalf("SameFile collapsed exact folder: %v, %v", same, err)
			}
			ka, ea := FileKey(own)
			kb, eb := FileKey(decoy)
			if ea != nil || eb != nil || ka == kb || ka == "" {
				t.Fatalf("distinct legacy keys: %q %q %v %v", ka, kb, ea, eb)
			}
			if ProgramKey(own) != ka || ProgramKey(decoy) != kb {
				t.Fatal("legacy program keys do not use fileid")
			}
			oldKey, oldErr := FileKey(strings.TrimPrefix(own, `\\?\`))
			if oldErr != nil || oldKey != ka && oldKey != kb || suffix == "." && oldKey != kb {
				t.Fatalf("unprefixed spelling: own=%q decoy=%q got=%q error=%v", ka, kb, oldKey, oldErr)
			}
			t.Logf("unprefixed folder suffix %q reads own=%t decoy=%t", suffix, oldKey == ka, oldKey == kb)
			sharedA, err := fileid.FileKey(own)
			if err != nil || sharedA != ka {
				t.Fatalf("fileid key mismatch: %q %q %v", sharedA, ka, err)
			}
			saved := verifyProgramFile
			var observed Code
			calls := 0
			var nativeErr error
			verifyProgramFile = func(f *os.File, hint string, opts *Options) (Code, Proof, error) {
				calls++
				// Record the path-only result separately. Catalog policy may
				// refuse a copied OS image; that is no wrong-verdict RED.
				old, _, oldErr := VerifyFile(hint, nil)
				if old.Trusted && old.OriginalName != other.OriginalName {
					t.Fatalf("path-only result described neither the copied decoy nor refusal: %+v %v", old, oldErr)
				}
				info, err := f.Stat()
				ownInfo, ownErr := os.Stat(own)
				if err != nil || ownErr != nil || !os.SameFile(info, ownInfo) {
					t.Fatalf("signature reader lost held own file: %v %v", err, ownErr)
				}
				code, proof, err := saved(f, hint, opts)
				observed = code
				nativeErr = err
				return code, proof, err
			}
			defer func() { verifyProgramFile = saved }()
			name := signedInterpreterName(own)
			if calls != 1 {
				t.Fatalf("held verifier calls %d, want one", calls)
			}
			if name != "" && !strings.EqualFold(name, want.OriginalName) {
				t.Fatalf("decoy interpreter evidence %q; own=%q decoy=%q", name, want.OriginalName, other.OriginalName)
			}
			if observed.Trusted && observed.OriginalName != want.OriginalName {
				t.Fatalf("held signature described decoy: %+v", observed)
			}
			t.Logf("held OS signed file own=%q, path-only decoy=%q, interpreter result=%q, native error=%v", want.OriginalName, other.OriginalName, name, nativeErr)
		})
	}
}

// TestHeldSignatureSurvivesRename reaches signedInterpreterName's private
// held-file seam and real WinVerifyTrust. Neither copied program is executed.
func TestHeldSignatureSurvivesRename(t *testing.T) {
	a := `C:\Program Files\nodejs\node.exe`
	b := signedGit(t)
	want, proof, err := VerifyFile(a, nil)
	if err != nil || proof != ProofBound || !want.Trusted || want.Catalog ||
		want.Subject == "" || want.Issuer == "" || !SharedInterpreterName(want.OriginalName) {
		t.Fatalf("signed interpreter fixture unavailable: %+v %v %v", want, proof, err)
	}
	other, proof, err := VerifyFile(b, nil)
	if err != nil || proof != ProofBound || !other.Trusted || other.Subject == "" || other.Subject == want.Subject {
		t.Fatalf("distinct signed replacement unavailable: %+v %v %v", other, proof, err)
	}
	first, err := os.ReadFile(a)
	if err != nil {
		t.Fatal(err)
	}
	replacement, err := os.ReadFile(b)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	path, moved := filepath.Join(dir, "interpreter.exe"), filepath.Join(dir, "held.exe")
	if err := os.WriteFile(path, first, 0o600); err != nil {
		t.Fatal(err)
	}
	previousTrust, previousVerify := winTrustCall, verifyProgramFile
	t.Cleanup(func() { winTrustCall, verifyProgramFile = previousTrust, previousVerify })
	// Retain the old source's exact handle/reopen shape as a real native
	// counterexample: its os.Open caller blocks the updater's rename.
	oldPath := filepath.Join(dir, "old-shape.exe")
	if err := os.WriteFile(oldPath, first, 0o600); err != nil {
		t.Fatal(err)
	}
	oldHeld, err := os.Open(oldPath)
	if err != nil {
		t.Fatal(err)
	}
	defer oldHeld.Close()
	oldRename := error(nil)
	winTrustCall = func(choice uint32, subject unsafe.Pointer, revocation bool) (trustSigner, error) {
		if choice == windows.WTD_CHOICE_FILE {
			oldRename = os.Rename(oldPath, filepath.Join(dir, "old-moved.exe"))
		}
		return previousTrust(choice, subject, revocation)
	}
	oldCode, oldProof, oldErr := VerifyFile(oldPath, nil)
	if err := oldHeld.Close(); err != nil {
		t.Fatal(err)
	}
	if oldErr != nil || oldProof != ProofBound || oldCode.Subject != want.Subject ||
		!errors.Is(oldRename, windows.ERROR_SHARING_VIOLATION) {
		t.Fatalf("old source shape: code=%+v proof=%v error=%v rename=%v", oldCode, oldProof, oldErr, oldRename)
	}
	t.Logf("old source native counterexample: held os.Open + VerifyFile rename = %v", oldRename)
	renamed := false
	winTrustCall = func(choice uint32, subject unsafe.Pointer, revocation bool) (trustSigner, error) {
		if choice == windows.WTD_CHOICE_FILE && !renamed {
			if err := os.Rename(path, moved); err != nil {
				t.Fatalf("rename held signed fixture: %v", err)
			}
			if err := os.WriteFile(path, replacement, 0o600); err != nil {
				t.Fatal(err)
			}
			renamed = true
		}
		return previousTrust(choice, subject, revocation)
	}
	var got Code
	verifyProgramFile = func(f *os.File, name string, opts *Options) (Code, Proof, error) {
		code, proof, err := previousVerify(f, name, opts)
		got = code
		if err != nil || proof != ProofBound {
			t.Errorf("real held verification: %+v %v %v", code, proof, err)
		}
		return code, proof, err
	}
	name := signedInterpreterName(path)
	if !renamed || name != want.OriginalName || !got.Trusted || got.Catalog != want.Catalog ||
		got.Subject != want.Subject || got.Issuer != want.Issuer ||
		got.Description != want.Description || got.OriginalName != want.OriginalName {
		t.Fatalf("held A changed to replacement B: name=%q got=%+v want=%+v B=%+v renamed=%v", name, got, want, other, renamed)
	}
	t.Logf("real native held A: %q / %q / %q; old path replaced by %q", got.OriginalName, got.Subject, got.Issuer, other.Subject)
	winTrustCall, verifyProgramFile = previousTrust, previousVerify
	newPath, proof, err := VerifyFile(path, nil)
	if err != nil || proof != ProofBound || newPath.Subject != other.Subject || newPath.OriginalName != other.OriginalName {
		t.Fatalf("unchanged path wrapper must observe replacement B: %+v %v %v", newPath, proof, err)
	}
	// The exported path API still refuses when its requested path changes
	// during the real native verification, even though the held file is trusted.
	pathMoved := false
	winTrustCall = func(choice uint32, subject unsafe.Pointer, revocation bool) (trustSigner, error) {
		if choice == windows.WTD_CHOICE_FILE && !pathMoved {
			if err := os.Rename(path, filepath.Join(dir, "path-wrapper-held.exe")); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, first, 0o600); err != nil {
				t.Fatal(err)
			}
			pathMoved = true
		}
		return previousTrust(choice, subject, revocation)
	}
	pathCode, pathProof, pathErr := VerifyFile(path, nil)
	if !pathMoved || pathErr == nil || pathProof != ProofNone || pathCode.Trusted || pathCode.Subject != "" {
		t.Fatalf("path wrapper admitted replacement: %+v %v %v", pathCode, pathProof, pathErr)
	}
}

func TestHeldSignatureRefusals(t *testing.T) {
	dir := t.TempDir()
	unsigned := filepath.Join(dir, "unsigned.exe")
	writeProgramFile(t, unsigned, "unsigned fixture")
	if name := signedInterpreterName(unsigned); name != "" {
		t.Fatalf("unsigned file named %q", name)
	}
	if name := signedInterpreterName(filepath.Join(dir, "missing.exe")); name != "" {
		t.Fatalf("missing file named %q", name)
	}
	data, err := os.ReadFile(signedGit(t))
	if err != nil {
		t.Fatal(err)
	}
	// Preserve a parseable PE and alter an authenticated DOS-header byte.
	data[0x20] ^= 1
	modified := filepath.Join(dir, "modified.exe")
	if err := os.WriteFile(modified, data, 0o600); err != nil {
		t.Fatal(err)
	}
	f, _, _, ok := openStampedWith(modified, openSignatureFile)
	if !ok {
		t.Fatal("modified fixture not opened")
	}
	defer f.Close()
	code, proof, err := verifyOpenFile(f, modified, nil)
	if err != nil || proof != ProofInvalid || code.Trusted || code.Subject != "" || code.Issuer != "" {
		t.Fatalf("modified signed file: %+v %v %v", code, proof, err)
	}
	if empty := acceptedTrustSigner(0); empty != (trustSigner{}) {
		t.Fatal("missing trust state supplied a signer")
	}
}

// The signature reader permits an updater to move its held file. Native
// signature/handle binding is exercised by TestHeldSignatureSurvivesRename.
func TestTheSignatureReaderAllowsRename(t *testing.T) {
	dir := t.TempDir()
	program := filepath.Join(dir, "renamed-tool.exe")
	writeProgramFile(t, program, "a tool")
	saved := verifyProgramFile
	verifyProgramFile = func(_ *os.File, path string, _ *Options) (Code, Proof, error) {
		if err := os.Rename(path, filepath.Join(dir, "moved.exe")); err != nil {
			t.Errorf("rename during signature verification: %v", err)
		}
		return Code{Trusted: true, OriginalName: "tool.exe"}, ProofBound, nil
	}
	t.Cleanup(func() { verifyProgramFile = saved })
	signedInterpreterName(program)
	if err := os.Remove(filepath.Join(dir, "moved.exe")); err != nil {
		t.Fatalf("remove moved fixture: %v", err)
	}
}

// A data stream holds other bytes than its file and has its file's stamp:
// one file ID and size, and writing the stream updates the file's times. A
// program spelled with a stream is refused as the older path functions
// refuse it (ID-F9, coordinator ruling D3), so the stream's code is never
// read, and no fact read from it is cached under the file's stamp. The
// file's own verdict stays its own.
func TestAStreamSpellingGetsNoFileFact(t *testing.T) {
	dir := t.TempDir()
	program := filepath.Join(dir, "p.exe")
	writeProgramFile(t, program, "python!!")
	stream := program + ":evil.exe"
	if err := os.WriteFile(stream, []byte("toolcode"), 0o755); err != nil {
		t.Skipf("this volume keeps no data streams: %v", err)
	}
	verified, saved := []string{}, verifyProgramFile
	verifyProgramFile = func(_ *os.File, path string, _ *Options) (Code, Proof, error) {
		verified = append(verified, path)
		data, err := os.ReadFile(path)
		if err != nil {
			return Code{}, ProofNone, err
		}
		if string(data) == "python!!" {
			return Code{Trusted: true, OriginalName: "python.exe"}, ProofBound, nil
		}
		return Code{Trusted: true, OriginalName: "tool.exe"}, ProofBound, nil
	}
	t.Cleanup(func() { verifyProgramFile = saved })
	reads := countBunGraphReads(t)

	if f, _, _, ok := openStamped(stream); ok {
		f.Close()
		t.Errorf("openStamped opened the stream %s", stream)
	}
	if name := signedInterpreterName(stream); name != "" {
		t.Errorf("the stream reads as the signed interpreter %q", name)
	}
	if bunStandaloneFile(stream) {
		t.Error("the stream reads as a Bun standalone image")
	}
	if code := ClassifyProgram(stream, Code{}); code.SharedInterpreter || code.RunsForeignCode {
		t.Errorf("ClassifyProgram read a fact from the stream: %+v", code)
	}
	if len(verified) != 0 || *reads != 0 {
		t.Errorf("the stream was read: %d verifications of %q, %d Bun graph reads", len(verified), verified, *reads)
	}
	stamp := stampOf(t, program)
	if name, ok := signedInterpreters.get(stamp); ok {
		t.Errorf("a signed verdict %q was cached under the file's stamp", name)
	}
	if _, ok := bunImages.get(stamp); ok {
		t.Error("a Bun graph fact was cached under the file's stamp")
	}
	if evidence, ok := foreignImages.get(stamp); ok {
		t.Errorf("marker evidence %q was cached under the file's stamp", evidence)
	}
	if name := signedInterpreterName(program); name != "python.exe" {
		t.Errorf("the signed interpreter itself reads as %q", name)
	}
}

// A program path through a junction is verified at the held file's own
// path. A junction replaced during the verification by a real folder that
// holds a signed interpreter under the program's name leaves the held
// file's verdict its own: the ordinary tool never reads as python.exe.
func TestAJunctionSwappedDuringTheVerificationKeepsTheHeldFilesVerdict(t *testing.T) {
	dir := t.TempDir()
	if long, err := filepath.EvalSymlinks(dir); err == nil {
		dir = long
	}
	real := filepath.Join(dir, "real")
	if err := os.Mkdir(real, 0o700); err != nil {
		t.Fatal(err)
	}
	tool := filepath.Join(real, "renamed-tool.exe")
	writeProgramFile(t, tool, "a tool")
	link := filepath.Join(dir, "link")
	junction(t, link, real)
	program := filepath.Join(link, "renamed-tool.exe")
	held := stampOf(t, tool)

	verified, saved := []string{}, verifyProgramFile
	verifyProgramFile = func(_ *os.File, path string, _ *Options) (Code, Proof, error) {
		if len(verified) == 0 {
			if err := os.Remove(link); err != nil {
				t.Fatalf("remove the junction: %v", err)
			}
			if err := os.Mkdir(link, 0o700); err != nil {
				t.Fatalf("put a real folder in its place: %v", err)
			}
			writeProgramFile(t, program, "python")
		}
		verified = append(verified, path)
		data, err := os.ReadFile(path)
		if err != nil {
			return Code{}, ProofNone, err
		}
		if string(data) == "python" {
			return Code{Trusted: true, OriginalName: "python.exe"}, ProofBound, nil
		}
		return Code{Trusted: true, OriginalName: "tool.exe"}, ProofBound, nil
	}
	t.Cleanup(func() { verifyProgramFile = saved })

	if name := signedInterpreterName(program); name != "" {
		t.Errorf("the held ordinary tool read as %q after its junction was swapped", name)
	}
	if name, ok := signedInterpreters.get(held); ok && name != "" {
		t.Errorf("the swapped-in file's verdict %q was cached under the held file's stamp", name)
	}
	if name := signedInterpreterName(tool); name != "" {
		t.Errorf("the ordinary tool, asked for by its own path, reads as %q", name)
	}
	if len(verified) == 0 || !samePath(verified[0], tool) {
		t.Errorf("the verification read %q, not the held file %q", verified, tool)
	}
}
