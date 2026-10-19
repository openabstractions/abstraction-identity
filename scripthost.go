package identity

import "strings"

// sharedInterpreterNames is the reviewed list of shared interpreters keyed on
// the signed OriginalFilename of their version resource, lower-cased (VISION
// 2026-10-01, TD83): programs that run whatever script or assembly they are
// given, so a signature on one covers the host and says nothing about the
// code it runs. This file owns the list; asks ASK-A8 and ASK-R7 and rights
// RIGHTS-R22 cite it. Spellings were read from this machine's files on
// 2026-10-01 where present (feedback/prompt-program-names-2026-10-01.md); the
// case does not matter. PowerShell 7's pwsh.exe is a .NET application host
// that carries its assembly's resource, pwsh.dll, and both spellings are
// listed. The .NET Framework tools are the LOLBAS catalogue's code-running
// entries (https://lolbas-project.github.io/).
var sharedInterpreterNames = map[string]bool{
	"powershell.exe": true, // Windows PowerShell
	"pwsh.exe":       true, // PowerShell 7
	"pwsh.dll":       true, // PowerShell 7's application host
	"cmd.exe":        true, // Windows Command Processor
	"wscript.exe":    true, // Windows Script Host
	"cscript.exe":    true, // Windows Script Host, console
	"mshta.exe":      true, // HTML Application host
	"rundll32.exe":   true, // runs an export of any library
	"regsvr32.exe":   true, // runs a library's registration code, scriptlets included
	"wsl.exe":        true, // Windows Subsystem for Linux
	"bash.exe":       true, // WSL's bash launcher
	"python.exe":     true,
	"pythonw.exe":    true,
	"node.exe":       true,
	"bun.exe":        true,
	"deno.exe":       true,
	"java.exe":       true,
	"javaw.exe":      true,
	"dotnet.exe":     true, // runs any .NET assembly
	// Git for Windows runs hooks and "!" aliases, and its bin\bash.exe
	// launcher carries git.exe's resource ("Git for Windows", git.exe).
	"git.exe": true,
	// .NET Framework tools that compile or run code they are handed (LOLBAS).
	"msbuild.exe":                     true, // runs inline tasks in a project file
	"installutil.exe":                 true,
	"regasm.exe":                      true,
	"regsvcs.exe":                     true,
	"csc.exe":                         true,
	"vbc.exe":                         true,
	"jsc.exe":                         true,
	"ilasm.exe":                       true,
	"csi.exe":                         true,
	"rcsi.exe":                        true,
	"aspnet_compiler.exe":             true,
	"microsoft.workflow.compiler.exe": true,
	"addinprocess.exe":                true,
	"presentationhost.exe":            true,
}

// SharedInterpreterName reports whether originalName, a program's signed
// OriginalFilename, names a reviewed shared interpreter. The comparison
// ignores case.
func SharedInterpreterName(originalName string) bool {
	return sharedInterpreterNames[strings.ToLower(originalName)]
}

// sharedInterpreterFileNames is the reviewed list of shared interpreters by
// file name, the form macOS and Linux programs carry since they have no
// signed OriginalFilename resource. A name is compared after
// SharedInterpreterFileName lower-cases it and removes ".exe" or ".dll" and a
// trailing version, so python3, python3.12, perl5.36 and Python.app's
// Contents/MacOS/Python all read as their stem. Every entry of
// sharedInterpreterNames is listed here by stem too.
var sharedInterpreterFileNames = map[string]bool{
	// Windows names of sharedInterpreterNames, without ".exe" or ".dll".
	"powershell": true, "pwsh": true, "cmd": true, "wscript": true, "cscript": true,
	"mshta": true, "rundll32": true, "regsvr32": true, "msbuild": true, "wsl": true, "git": true,
	"installutil": true, "regasm": true, "regsvcs": true, "csc": true, "vbc": true, "jsc": true,
	"ilasm": true, "csi": true, "rcsi": true, "aspnet_compiler": true,
	"microsoft.workflow.compiler": true, "addinprocess": true, "presentationhost": true,
	// Shells.
	"sh": true, "bash": true, "zsh": true, "dash": true, "ksh": true, "mksh": true,
	"csh": true, "tcsh": true, "fish": true, "ash": true, "busybox": true,
	// macOS Open Scripting Architecture.
	"osascript": true,
	// Language runtimes.
	"python": true, "pythonw": true, "pypy": true, "node": true, "nodejs": true, "bun": true,
	"deno": true, "perl": true, "ruby": true, "php": true, "lua": true, "luajit": true,
	"tclsh": true, "wish": true, "expect": true, "java": true, "javaw": true, "jshell": true,
	"dotnet": true, "julia": true, "rscript": true,
	"awk": true, "gawk": true, "mawk": true, "nawk": true,
}

// SharedInterpreterFileName reports whether a program's file name, or its
// path with either separator, names a reviewed shared interpreter on any
// platform: the stem that remains after lower-casing, removing ".exe" or
// ".dll" and removing trailing version digits and dots (python3.12,
// perl5.36, node18) is on the list, or the name before that removal is
// (rundll32, regsvr32). It is a pure function of the name, so every
// platform's names test anywhere.
func SharedInterpreterFileName(program string) bool {
	base, stem := interpreterStems(program)
	return sharedInterpreterFileNames[base] || sharedInterpreterFileNames[stem]
}

// interpreterStems is a program's file name lower-cased without ".exe" or
// ".dll", and that name without trailing version digits and dots, the two
// forms SharedInterpreterFileName looks up.
func interpreterStems(program string) (base, stem string) {
	base = program
	if i := strings.LastIndexAny(base, `/\`); i >= 0 {
		base = base[i+1:]
	}
	base = strings.ToLower(base)
	base = strings.TrimSuffix(strings.TrimSuffix(base, ".exe"), ".dll")
	return base, strings.TrimRight(base, "0123456789.")
}

// bunFileName reports whether a program's file name is Bun's own: bun,
// bun.exe or a versioned bun.
func bunFileName(program string) bool {
	base, stem := interpreterStems(program)
	return base == "bun" || stem == "bun"
}

// sharedInterpreterPackages are the reviewed shared interpreters Windows runs
// as MSIX packages, whose subject is msix:<family> (SubjectProgram), keyed on
// the package name before the family's publisher id as its manifest spells
// it, which this package reports unchanged. sharedInterpreterPackagePrefixes
// covers families that carry a version in the name
// (PythonSoftwareFoundation.Python.3.12).
var sharedInterpreterPackages = map[string]bool{
	"Microsoft.PowerShell":                            true, // PowerShell 7 from the Microsoft Store
	"Microsoft.PowerShellPreview":                     true,
	"MicrosoftCorporationII.WindowsSubsystemForLinux": true, // WSL
	"TheDebianProject.DebianGNULinux":                 true, // a WSL distribution's shell
}

var sharedInterpreterPackagePrefixes = []string{
	"PythonSoftwareFoundation.Python.", // Python from the Microsoft Store
	"CanonicalGroupLimited.Ubuntu",     // Ubuntu for WSL, every release
}

// SharedInterpreterPackage reports whether an MSIX package family name,
// <Name>_<PublisherId>, is a reviewed shared interpreter's.
func SharedInterpreterPackage(family string) bool {
	name, _, _ := strings.Cut(family, "_")
	if sharedInterpreterPackages[name] {
		return true
	}
	for _, prefix := range sharedInterpreterPackagePrefixes {
		if strings.HasPrefix(name, prefix) {
			return true
		}
	}
	return false
}
