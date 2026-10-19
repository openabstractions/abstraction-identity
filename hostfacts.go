package identity

import (
	"path/filepath"
	"strings"
)

// ClassifyProgram returns code with the program's script-host facts set
// (ID-I1, TD83): SharedInterpreter, RunsForeignCode and the ForeignCode
// evidence. program is a subject program, a path or an msix:<family>; code
// is the evidence the caller holds about it, such as a peer's code binding,
// and its OriginalName counts only when Trusted. It reads, in order:
//   - an msix:<family> subject by the reviewed package families;
//   - the pyvenv.cfg Python reads for the program: a program that is the same
//     file as a file in its home is the shared interpreter, and so is one
//     whose config, home or file cannot be verified (SharedInterpreterVenv);
//   - the shared-interpreter name tables: the signed OriginalName in code, the
//     program's own file name after its 8.3 alias is resolved, and the program
//     file's own verified signature, read once per file identity, so a renamed
//     signed copy is named by its original file name. A named program beside
//     its own pyvenv.cfg whose home is another folder is an application's own
//     interpreter copy, which runs foreign code and is no shared
//     interpreter. A program named as Bun itself (the trusted OriginalName
//     bun.exe, or the file name bun) that carries a Bun standalone module
//     graph is its application's own image; any other named program stays a
//     shared interpreter whatever graph it carries;
//   - the program image's markers (ImageForeignCode), read once per file
//     identity, size and modification time.
//
// A shared interpreter also runs foreign code. A file that cannot be read
// gives no evidence. This is a boundary between cooperating programs of one
// account (RIGHTS-R15): an unsigned renamed interpreter on macOS or Linux
// carries no name this reads.
func ClassifyProgram(program string, code Code) Code {
	code.SharedInterpreter, code.RunsForeignCode, code.ForeignCode = false, false, ""
	shared, own := sharedInterpreter(program, code)
	switch {
	case shared:
		code.SharedInterpreter, code.RunsForeignCode, code.ForeignCode = true, true, ForeignCodeSharedInterpreter
	case own:
		code.RunsForeignCode, code.ForeignCode = true, ForeignCodeAppInterpreter
	default:
		if evidence := imageForeignCodeFile(program); evidence != "" {
			code.RunsForeignCode, code.ForeignCode = true, evidence
		}
	}
	return code
}

// SharedInterpreterProgram is ClassifyProgram's SharedInterpreter alone,
// without reading the program image's markers: the check a decision makes
// for every program (rights RIGHTS-R22's default exclusion).
func SharedInterpreterProgram(program string, code Code) bool {
	shared, _ := sharedInterpreter(program, code)
	return shared
}

// sharedInterpreter reports whether program is a shared interpreter, and
// whether it is an application's own interpreter copy instead.
func sharedInterpreter(program string, code Code) (shared, own bool) {
	if family, ok := strings.CutPrefix(program, PackagedProgramPrefix); ok {
		return SharedInterpreterPackage(family), false
	}
	named := code.Trusted && SharedInterpreterName(code.OriginalName) ||
		SharedInterpreterFileName(program) || SharedInterpreterFileName(CanonicalProgramPath(program))
	if !named && !filepath.IsAbs(program) {
		return false, false
	}
	switch readVenvAt(program) {
	case venvHomeFile, venvUnverified:
		return true, false
	case venvOwnCopy:
		if named || signedSharedInterpreterFile(program) {
			return false, true
		}
		return false, false
	}
	if !named && !signedSharedInterpreterFile(program) {
		return false, false
	}
	// A Bun standalone executable keeps the runtime's version resource
	// (stock OpenCode 1.18.31 on Windows: OriginalFilename bun.exe,
	// FileDescription Bun) but is its application's own image; its markers
	// decide whether it runs foreign code. Only Bun's own name evidence
	// earns this: python.exe or node.exe carrying a graph stays shared.
	if bunNamed(program, code) && bunStandaloneFile(program) {
		return false, false
	}
	return true, false
}

// bunNamed reports whether the name evidence for program is Bun's own: the
// trusted OriginalName in code or in the program file's own signature is
// Bun's (bun.exe), or the program's file name, after its 8.3 alias is
// resolved, is bun.
func bunNamed(program string, code Code) bool {
	return code.Trusted && bunFileName(code.OriginalName) ||
		bunFileName(program) || bunFileName(CanonicalProgramPath(program)) ||
		bunFileName(signedInterpreterName(program))
}

// bunImages caches bunStandalone by file stamp.
var bunImages fileCache[bool]

// bunGraphRead is the one image read bunStandaloneFile makes; tests count it.
var bunGraphRead = bunStandalone

// bunStandaloneFile reports whether the program file carries a Bun
// standalone module graph, read once per file stamp. It reads the image's
// headers and its last bytes, never the whole file; a file that cannot be
// read carries none. The answer is remembered only when the file's stamp
// after the read is the stamp before it.
func bunStandaloneFile(program string) bool {
	f, info, stamp, ok := openStamped(program)
	if !ok {
		return false
	}
	defer f.Close()
	if bun, ok := bunImages.get(stamp); ok {
		return bun
	}
	bun := bunGraphRead(f, info.Size())
	bunImages.keep(f, stamp, bun)
	return bun
}

// readVenvAt is readVenv's state for an absolute local path, and venvNone
// otherwise.
func readVenvAt(program string) venvState {
	if !filepath.IsAbs(program) || LocalPath(program) != nil {
		return venvNone
	}
	state, _ := readVenv(program)
	return state
}

// signedInterpreters caches, by file stamp, the shared-interpreter name a
// program file's own signed version resource carries, "" for none. A file
// replaced or rewritten in place has another stamp and is verified again.
var signedInterpreters fileCache[string]

// verifyProgramFile reads a program file's signature; tests replace it.
var verifyProgramFile = verifyOpenFile

// signedSharedInterpreterFile reports whether the file at program is signed
// and its trusted OriginalName names a shared interpreter, so a renamed
// signed copy is still caught.
func signedSharedInterpreterFile(program string) bool {
	return signedInterpreterName(program) != ""
}

// signedInterpreterName is the trusted OriginalName of the file at program
// when it names a shared interpreter, and "" otherwise. A
// missing file, a non-local path and a platform without file verification
// read as no evidence, and a failed read is not remembered. The file is held
// open and stamped before the verification and again after it; the name is
// remembered only when the two stamps are equal. The verification reads the
// held file itself. On Windows its final path is a native policy hint;
// signature and resource evidence are read from the handle and native trust
// state. The signature-specific opener permits rename and excludes writers.
func signedInterpreterName(program string) string {
	f, _, stamp, ok := openStampedWith(program, openSignatureFile)
	if !ok {
		return ""
	}
	defer f.Close()
	if name, ok := signedInterpreters.get(stamp); ok {
		return name
	}
	path, ok := heldFilePath(f, program)
	if !ok {
		return ""
	}
	code, _, err := verifyProgramFile(f, path, nil)
	if err != nil {
		return ""
	}
	name := ""
	if code.Trusted && SharedInterpreterName(code.OriginalName) {
		name = code.OriginalName
	}
	signedInterpreters.keep(f, stamp, name)
	return name
}

// PublisherPermitRefusal is the sentence a refused publisher permit, licence
// or answering grant shows for a program that runs foreign code (ID-I1,
// TD83): what the evidence is, and the developer's remedy. It is "" for a
// Code ClassifyProgram found no foreign code in.
func (c Code) PublisherPermitRefusal() string {
	if !c.RunsForeignCode {
		return ""
	}
	const lead = "Publisher permits do not apply: "
	switch {
	case c.ForeignCode == ForeignCodeElectronRunAsNode:
		return lead + "this Electron program can run as Node.js, so any script can act as it. The developer turns the RunAsNode fuse off."
	case c.ForeignCode == ForeignCodeBunBeBun:
		return lead + "this Bun program runs any script when " + string(bunBeBun) + " is set. The developer builds it without " + string(bunBeBun) + " support."
	case c.ForeignCode == ForeignCodeAppInterpreter:
		return lead + "this program is an application's own interpreter and runs the scripts it is given. The developer builds and signs an application-named host program."
	case strings.HasPrefix(c.ForeignCode, ForeignCodeEntitlementPrefix):
		entitlement := strings.TrimPrefix(c.ForeignCode, ForeignCodeEntitlementPrefix)
		return lead + "this program's signature carries " + entitlement + ", so code from outside it can run as it. The developer signs it without that entitlement."
	}
	return lead + "this program is a shared interpreter and runs any script. The developer ships the application's own program."
}
