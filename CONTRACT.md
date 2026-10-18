# abstraction.identity contract

Binds: `identity.thrift`

`identity.thrift` defines `abstraction.identity/api@1`, the shared `Proof`
vocabulary — the ladder, `ProofRequirement` and `ProofFailure` — every
native binding carries across languages. Identity answers no Thrift service
of its own: the connection a caller and a service already share, a Windows
named pipe, a Unix domain socket, a loopback TCP connection or an XPC
message, is its transport, and a serialized `ProofRequirement` or `Proof`
name never supplies identity, only a policy or its refusal.
[README.md](README.md) is the door — what this package is, how to obtain
it, one example that runs.

What this package will and will not tell a service about the program on the
other end of a local connection, and what a permission system built on it
must therefore refuse to promise, on each of the three platforms it
supports. Three platforms, three different shapes of answer: Windows can
tell you which program opened the connection and cannot verify the code it
is running; Linux can tell you who the peer is and has no general answer to
what it is; macOS can verify the running code and, over a plain socket,
cannot firmly bind that code to the connection.

## Reading this page

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD",
"SHOULD NOT", "RECOMMENDED", "MAY" and "OPTIONAL" in this page are to be
interpreted as described in RFC 2119 and RFC 8174, when, and only when, they
appear in all capitals, as shown here.

A rule id such as `ID-P3` is declared once, in bold brackets before its
title, at the head of the rule it names; a conformance scenario cites it the
same way on its `# expect` line, and a citation that resolves to no rule
here is a defect in one of the two. The scenarios are in
`testdata/scenarios/`. A retired id is never reused; [HISTORY.md](HISTORY.md)
keeps it with the release it left. `HISTORY.md` also carries this
contract's earlier drafts and what was tested where, linked from here and
linking back.

| letter | topic |
|---|---|
| P | proof (the ladder, weakest first) |
| L | limits (`Ceiling`, `CanEver`, `Stronger`, the cross-platform table) |
| C | check (`Need`, `Check`, a code verdict) |
| N | never claimed (no self-reported identity) |
| B | binding safety (an identity taken once; a recycled pid refused) |
| W | Windows |
| U | Linux |
| M | macOS |
| T | loopback TCP |
| S | self (the calling process's own principal) |
| D | private folders and trusted paths (`go/privatedir`, `go/trustedpath`) |

`A` (admission), `E` (error and outcome) and `X` (extension) are reserved
with one meaning in every contract (S12) and are not separately declared
here. `A` and `X` are unused in this contract; `E` already names the error a
caller receives when the channel cannot answer at all (`ID-E1`..`ID-E7`),
matching the reserved meaning. The four rules that read `ID-X1`..`ID-X4`
before this change are `ID-M1`..`ID-M4`: `X` is reserved for extension in
every contract, and macOS's own drift finding is not one; `HISTORY.md`
keeps the retired form.

No prose-to-wire table is needed here: this release renames no wire name in
identity's own vocabulary, and `ceiling` (D65) and the verb `bind` (D27)
keep the words they already use.

## Proof

A `Peer` has five attributes — user, process, path, package, code — and each
one carries a `Proof` saying how hard it would be to make it lie. There is
no way to read a value without the proof.

**[ID-P1] The ladder.** `Proof` MUST be a total order of nine levels,
weakest first, and these are the whole of it: `none`, `claimed`, `invalid`,
`unsigned`, `unmet`, `pid`, `bound`, `kernel`, `signed`.

**[ID-P4] `none`.** Nothing. There is no value, and none is handed out
however low a minimum the caller asks for.

**[ID-P2] `claimed`.** The peer said so. This package MUST NOT ever produce
it and MUST have no API that accepts it.

**[ID-P9] `invalid`.** The platform found a signature and refused it: the
code was modified after signing, the certificate is expired or revoked, or
the chain reaches a root this machine does not trust. The lowest of the
three verdicts below — no signature is no claim, and a refused signature is
a claim the operating system rejected.

**[ID-P10] `unsigned`.** The platform looked and found no signature at all.
`Need{Code: ProofUnsigned}` says *I do not require a signature but I refuse
a broken one*, a policy a service can honestly state; the reverse — accept
tampered code but refuse unsigned code — is not one anybody can state,
which is why `invalid` sits below it.

**[ID-P11] `unmet`.** The signature is intact and the platform accepted it,
but the code does not satisfy the requirement the service asked for in
`Options.CodeRequirement`. The strongest of the three verdicts — intact
code, signed by somebody other than who was required — and still carries no
identity: nothing is read out of a signature that failed the check it was
given.

**[ID-P5] `pid`.** Read from a pid after the fact, without checking for
reuse. Good enough for a log line, never for a permission decision.

**[ID-P6] `bound`.** Read through something that ties the value to the
process that connected: a process handle whose creation predates the
connection (Windows), a pidfd the kernel derived from the connection itself
(Linux), a pid and pidversion cross-checked against the connect-time
credentials and the connection's start-time window (macOS). Each
platform's rules below state exactly what its version of `bound` excludes.

**[ID-P7] `kernel`.** The kernel stamped it on the connection when the peer
connected. A value the kernel produces honestly but resolves when asked is
not of this kind.

**[ID-P8] `signed`.** The OS validated a code signature and this identity
came out of it, rather than out of a filename.

**[ID-P12] Where the three verdicts sit.** `invalid`, `unsigned` and
`unmet` MUST be reported below `pid` and everything above it: from `pid`
upward, a proof level says how a value was bound to the peer, and a
verdict binds nothing, so a policy that implies verification refuses all
three by comparison alone. They MUST sit above `claimed`: `claimed` is *the
peer said so*, and a verdict is what the operating system said, which is
always stronger than an unchecked assertion. Only `Code` ever produces the
three verdicts.

**[ID-P3] Reading with a floor.** `Attr.AtLeast` MUST return an error
instead of a value when the evidence is weaker than the caller demanded.

## Ceiling and CanEver

**[ID-L1] `Ceiling`.** `Ceiling()` MUST report the best each attribute can
reach over the running platform's native stream transport, and MUST answer
without a connection. `CeilingFor(transport)` selects an explicit transport;
an unavailable transport MUST return `ErrUnsupportedConn`. In particular,
Darwin's plain `Ceiling()` describes Unix sockets, not XPC.

**[ID-L2] `CanEver`.** `CanEver(need)` compares a policy against that
ceiling and MUST be called once at startup, never per connection. A
service whose model rests on a proof this transport cannot produce should
fail to start, not discover it once per connection. Endpoint-based services
use `listen.CanEver(endpoint, need)` or `listen.ListenFramed(endpoint, need)`
to select the endpoint's ceiling, including `xpc:` on macOS.

**[ID-L5] No claimed ceiling.** A ceiling MUST NOT report `claimed` for any
attribute.

**[ID-L6] `Stronger`.** `Stronger` MUST name the transport that would
prove more than this one, and MUST be empty when this transport is
already the platform's best.

## Check, never claimed and weak answers

A `Need` is a minimum proof per attribute.

**[ID-C1] Every attribute that falls short.** `Check` MUST report whether
this peer meets a `Need`, and its error MUST name every attribute that
fell short rather than the first, so a service does not learn about its
second impossible requirement only after fixing the first.

**[ID-C2] The zero `Need`.** The zero `Need` requires nothing and MUST be
met by every peer.

**[ID-C3] An unnamed attribute is not judged.** An attribute the policy
does not name MUST NOT be judged, however weak it is.

**[ID-N1] Nothing in a `Peer` was spoken by the peer.** Two connections
from one program carrying two different lies about who is calling MUST
resolve to the same identity, and no string from either payload appears
anywhere in it.

**[ID-N2] No field accepts one.** There MUST be no field a caller can fill
in from a request and no constructor that takes one. `ProofClaimed` exists
only to name what is being refused.

**[ID-B1] Taken once.** An identity MUST be taken once, from the
connection the service accepted, and refused afterwards rather than
re-derived. `Bind` and `BindConn` capture stream evidence; `BindXPCRequest`
captures the exact received message's evidence. `Binding.Peer` and
`Binding.Check` MUST recheck the captured binding before returning an answer
for a decision. `Captured` is the unrechecked snapshot for diagnostics, as
are `OfHandle` and `OfConn`; they are not substitutes for a live binding.

For a direct `BindConn` capture that retains the accepted stream descriptor,
the owner MUST close the `Binding` before closing that stream. The framed
listener owns its platform-specific cleanup. Closing the owning binding MUST
make `Peer`, `Check` and `Alive` return `net.ErrClosed`, including
through every `Shared` view. `Shared.Close` MUST release no owned resource.
Evidence validity and process liveness are separate: a stream capture may
remain valid after the peer exits, while an XPC binding is valid only during
its active request. `BoundAt` and `EvidenceValidUntil` expose the capture's
timing; they do not increase any proof.

**[ID-E5] Weak is not an error.** An answer that is merely weak MUST come
back as a `Peer` with low proofs and a populated `Notes`, never as an
error, because only the caller's policy knows whether weak is fatal.

**[ID-E1] Wrong end of the connection.** A handle that is not the end the
service accepted — the client end of a pipe, or a listening socket — MUST
be refused with `ErrNotServerEnd`: both would answer, and both would
answer about the service itself.

**[ID-E2] Remote peer.** A peer not on this machine MUST be refused with
`ErrRemotePeer`.

**[ID-E3] No usable credentials.** A connection that carries no peer
credentials at all, or whose handle cannot be reached, MUST be refused
with `ErrUnsupportedConn`.

**[ID-E4] No implementation.** A platform with no implementation here MUST
return `ErrUnimplemented` instead of a weaker answer from a portable
fallback: a permission system that silently degrades to "some process on
this machine" is worse than one that will not start.

**[ID-C5] A verdict is not a claim.** `Code.Trusted` is the platform's own
trust verdict. A `Code` with `Trusted` false is a signature that exists and
failed, and `Status` MUST say how.

**[ID-C4] A rejected signature does not meet a code policy.** A policy
that demands a code identity MUST NOT be met by a signature the platform
rejected. `Check` compares proof levels, and a signature the platform
examined and did not accept is reported at `invalid`, `unsigned` or
`unmet` — below `ProofPID` and everything above it — so a service written
exactly as README.md's example shows, with a `CodeRequirement` the peer
fails and `Need{Code: ProofPID}`, is refused.

**[ID-C6] The failure stays readable.** When verification fails, `Code`
MUST be reported at the verdict's own proof level, with `Trusted` false and
`Status` naming exactly how, rather than withheld at `none`. A service
that knowingly wants to admit an unverified caller asks for the lower
level by name — `Need{Code: ProofUnsigned}` admits the unsigned peer by
saying so, not by omission. `testdata/scenarios/code-untrusted.txt`
asserts `ID-C4` and is green; its step 4 stays undecided not because the
shape is undecided — `ID-C6` settles that — but because the value itself
is not one token across platforms: `unsigned` on Windows, `unmet` on
macOS, `none` on Linux, where `Code` never verifies at all.

## Self

**[ID-S1] The calling process's own principal.** `Self` MUST return the
principal the operating system attributes to the calling process, read from
its own primary token or credentials and never from a peer: on Windows the
user SID, elevation, mandatory integrity level (name and RID) and whether
the token is restricted, as a peer's `User` carries them, and on Linux and macOS the effective uid and
gid, the credentials a socket peer's `SO_PEERCRED` or `getpeereid` reports.
A service compares a peer's kernel-proven `User` with `Self` to decide
whether the peer holds at least the service's own authority: the job
service links a result only for a caller of its own account at no lower
integrity (`abstraction-job/CONTRACT.md` JOB-A17). An integrity label that
cannot be read is `Integrity` "unknown" with RID 0 on a peer, never a level,
and `Self` returns an error instead of such an answer; RID 0 that was read
is the untrusted level. A restricted flag that cannot be read reads
restricted. `Self` proves nothing about another process.

## Windows

The user reads `kernel`: `ImpersonateNamedPipeClient` followed by
`OpenThreadToken` yields the client's own access token, and the SID, the
elevation flag and the mandatory integrity level come off that token — the
operating system's own answer, which the peer neither supplies nor can
influence. The process id reads `kernel`, from
`GetNamedPipeClientProcessId`, a fact about the connection. The image path
reaches `bound`: the pid is turned into a process handle, the handle's
creation time is compared against the moment of accept, and
`QueryFullProcessImageName` is called through that pinned handle. MSIX
package identity reaches `signed` through `GetPackageFullName` on the
pinned handle — the only Windows answer where "which program" means more
than "which file the kernel happened to execute". Authenticode reaches
`bound`, never `signed`, over `WinVerifyTrust` on the image file and the
signer's subject and issuer from the embedded PKCS#7 message. A file with
no embedded signature whose final path lies under the Windows directory
(`GetSystemWindowsDirectory`; each folder above the final path compared with
it by file identity, as `Within` compares) is looked up in the system catalogs by its SHA-256 hash
(`CryptCATAdminEnumCatalogFromHash`), verified as a member of each listing
catalog under the same `WinVerifyTrust` policy, and named by the subject
and issuer of the first accepted catalog's own PKCS#7 message, read the
same way; `Code.Catalog` is then set. A catalog refusal on the unsigned rung
(`TRUST_E_NOSIGNATURE`, `CRYPT_E_NOT_FOUND`) means that catalog does not
list the file, and the search continues. A file no catalog accepts is
`invalid` when a catalog refused it on another rung (a bad digest, an
untrusted chain), with `Code.Catalog` set and no signer named, and
`unsigned` otherwise. A file with no embedded signature anywhere else is
`unsigned` without a lookup: the system catalogs list the operating
system's files, and the rule bounds the lookup's cost. A standard user can
write under the Windows directory (`C:\Windows\Temp`, `C:\Windows\Tasks`),
and an unmodified copy placed there still names the catalog's signer, so the
location is no evidence about the program; prompts name a program by its
signed version resource (VISION 2026-10-01). The rules below say why the
result cannot be promoted.

A file Windows accepted, through its embedded signature or a catalog, also
reports `Code.Description` and `Code.OriginalName`: the `FileDescription`
and `OriginalFilename` of the `RT_VERSION` resource in the image's own
resource section. The package parses the PE headers, the resource directory
and the `VS_VERSIONINFO` block with positioned reads through the handle it
verified, without opening the path again, and the image's language resource file
(`.mui`) is never consulted. `GetFileVersionInfo` reads by path and returns
the `.mui`'s resource for an inbox program (`OriginalFilename`
`PowerShell.EXE.MUI`); it is not used. Both strings come from the string
table the first `VarFileInfo\Translation` entry names, or the first table.
The resource is read before and after the verification, and the two reads
MUST agree, or the verification is abandoned with an error: the strings are
the verified bytes. A running image cannot be opened for writing while its
section is mapped, and `VerifyFile` holds its file without write sharing
(ID-W4); the second read checks both. A trusted file whose resource read
fails in the operating system is abandoned with an error as well. A file
Windows did not accept, or one with no version resource or a malformed one,
reports both empty.

**[ID-K1] The pipe's door admits only containers its listener names.**
`listen.Listen` creates each pipe instance with a protected descriptor of
one entry, this account with full access, and the listener's own integrity
label (medium for an ordinary process), so no process of another account
and no AppContainer of this one connects. `listen.ListenAdmitting(name,
containers...)` adds one client-data read/write and sync entry per AppContainer
SID the listener names, without `FILE_CREATE_PIPE_INSTANCE`, and keeps the label;
one explicit entry lets a contained client through
the medium label (research/engine-sandbox/REPORT.md, "OA IPC from inside the
container"). The listener names containers from its own state; a connecting
process never names one. A SID that is not one AppContainer's (`S-1-15-2-`
and seven numbers), the all-application-packages groups `S-1-15-2-1` and
`S-1-15-2-2` included, MUST be refused before any pipe exists. Outside
Windows naming a container is refused. Tests: `TestPipeDescriptorEntries`;
a contained client connects and exchanges data, but cannot create a competing
server instance, in the provider kit's `TestContainedEngineBoundaries`.

**[ID-E6] Read before you identify.** `ImpersonateNamedPipeClient` fails
with `ERROR_CANNOT_IMPERSONATE` until the server has completed a read; the
client having written is not enough. A framed service MUST accept and read
the fixed four-byte request header, then identify and check its caller-proof
requirement before allocating or reading the application body. It MUST NOT
parse that body, size a buffer from its length, or read a name out of it
before identifying. An unmet caller-proof requirement sends only the fixed
transport refusal in `listen/FRAMING.md`; observed evidence and platform
explanations stay at the receiver. The package
returns `ErrMustReadFirst` when asked too early.
`TestWindowsWillNotIdentifyUntilTheServerHasRead` asserts all three cases.

**[ID-W1] Authenticode verifies a file, not a running program.** Windows
exposes no way to verify the image mapping a process is executing;
`WinVerifyTrust` takes a file, and the process is a section object mapped
from a file that may since have been renamed, deleted or replaced. The
package holds the peer's process handle open throughout, opens the image
file and passes the handle rather than the path to `WinVerifyTrust`, then
re-asks the kernel both what path the process is running from and what
path its own open handle resolves to, refusing the answer if the three
stop agreeing. One window remains open — between the peer starting and the
package opening the file, the file could be renamed away and a different
file created at the name the kernel now reports, which needs write access
to the directory and precise timing, and cannot be closed from user mode.
`Code` MUST NOT exceed `bound` on Windows, and `CanEver(Need{Code:
ProofSigned})` MUST fail there. Asserted by
`TestWindowsRefusesToPromiseASignature`.

**[ID-W2] One verification per process instance.** `WinVerifyTrust` hashes
the whole image file — about 2 ms for a small unsigned program, 30 to 40 ms
for the signed `python.exe`, 150 to 210 ms for the 90 MB signed `node.exe`
(measured 2026-09-17). The catalog lookup hashes the file again, about
4.4 ms per MB, and runs only under the Windows directory: about 8 ms for
the catalog-signed `powershell.exe` on an inbox host, and under 1.5 ms for
the unsigned 15.8 MB `go.exe` and a 6.8 MB unsigned Go test binary outside
it, which make no lookup (measured 2026-10-01). The lookup uses SHA-256
only: all 3394 files without an embedded signature under `System32`
(executables and libraries), `SysWOW64`, the Windows directory itself and
Windows PowerShell's folder on Windows 11 build 26200 matched a catalog
under SHA-256, and none needed SHA-1. The verdict for a peer MUST be kept for later
connections from the same live process instance at the same image path,
keyed on pid, creation time, the image path read afresh through the pinned
handle for each connection, and `CheckRevocation`; the kept entry holds its
own handle to the process, so while it exists the pid names that process
object and no other, and the file the first verification read stays the
file the process still runs. User, process, path and package MUST still be
read for every connection; only the Authenticode verdict is reused, and a
failed verification is never kept. A kept verdict MUST NOT see a change in
this machine's trust — a root or catalog added or removed, a certificate
expiring — until it is five minutes old. Entries for exited processes are
released when the next verdict is kept, and at most 256 are held. Asserted
by `TestSignedPeerIsVerifiedOncePerProcess` and
`TestCodeVerdictIsReusedOnlyForTheSameInstanceAndPath`.
The shared IPC session binding retires by the original verdict's five-minute
deadline, including when Bind reused a verdict from an earlier connection.
Later requests establish a new binding and receive a current verdict.

**[ID-W3] The account name is a display cache.** The account name beside a
user's SID comes from an LSA lookup of about 250 µs; it is display text,
and the SID is read from the peer's token for every connection. A
looked-up name MAY be remembered for one minute, so a renamed account can
show its old name for up to that long. Asserted by
`TestAccountNameIsRememberedBriefly`.

**[ID-W4] Verifying a file.** `VerifyFile(path, opts)` MUST run the same
Authenticode policy and signer read as a peer's `Code`, over a handle it
holds open for the verification without write sharing, and MUST report the
same rungs. No one can open the file for writing while it is held, and a
file another handle already holds open for writing is refused at the open
with a sharing violation. The rungs are: `bound`
with `Trusted` for a file Windows accepted, `unsigned` or `invalid`
otherwise. `Catalog` is set when the verdict came from a system catalog
(the lookup at the head of this section); `Subject` and `Issuer` then name the signer of the
catalog Windows accepted, and stay empty when a catalog refused the file.
`Description` and `OriginalName` are the accepted file's version resource,
read as the head of this section says. The path MUST be an absolute,
clean path on a lettered drive whose root is neither remote nor absent; any
other path, UNC, device and mapped network drive paths included, MUST return
`ErrNotLocalFile` without being opened. The handle's final path, after
junctions and symbolic links, MUST meet the same rule, or the answer is
`ErrNotLocalFile`. A junction or symbolic link anywhere in the path makes the
final path differ from the opened one, so such a file is refused and the
prompt shows it as not verified. The signer name is read by path. After that read the
handle's final path MUST still be the verified path (the check `ID-W1` makes
for a peer's image), or the answer is an error. The answer describes the file
as it is now. It is display and policy evidence about a file and says nothing
about which program a connection is running. Every other platform MUST
return `ErrUnimplemented` (ID-E4). Asserted by
`TestVerifyFileOpensOnlyLocalDrivePaths`, `TestVerifyFileRefusesRemoteDrives`,
`TestStillSameFileFollowsTheHandle`, `TestVerifyFileNamesEmbeddedSigner`,
`TestVerifyFileNamesCatalogSigner`,
`TestVerifyFileCatalogRefusal`,
`TestVerifyFileLooksUpCatalogsOnlyUnderTheWindowsDirectory`,
`TestUnderDirectoryNeedsASeparator`,
`TestVerifyFileReportsAModifiedSignedFileInvalid`,
`TestVerifyFileUnsignedAndMissing`,
`TestVerifyFileNamesTheProgramByItsVersionResource`,
`TestVerifyFileNamesNoProgramForAModifiedFile`,
`TestVersionResourceIsTheVerifiedBytes`,
`TestVerifyFileHoldsTheFileAgainstWriters`,
`TestVersionResourceReadFailureAbandonsVerification`,
`TestPeerImageNamesTheProgramByItsVersionResource`,
`TestParseVersionInfoChoosesTheTranslatedTable`,
`TestVersionResourceReaderToleratesDamagedImages` and
`TestVerifyFileIsUnimplementedOffWindows`.

**[ID-B3] `ConnectedAt` bounds pid reuse.** The check opens the process,
reads its creation time, and refuses everything derived from the pid if
that time is later than `Options.ConnectedAt`; any process that inherited
a recycled pid must have been created after the connection already
existed. `Options.ConnectedAt` MUST be set from the accept loop, on the
line after accept returns — left zero it defaults to the moment of
resolution, which still excludes reuse after that moment but not reuse
between accept and resolution. The comparison uses the wall clock; a clock
stepped backwards can cause a false refusal, and no tolerance is added,
because a tolerance is exactly the width of the hole.

**[ID-B2] A recycled pid is refused.** When the check in `ID-B3` fires,
`Process.Recycled` MUST be set and path, package and code MUST all be
reported as `none` with the reason attached. Asserted by
`TestRecycledPIDIsRefused`. When the peer has already exited, the pid is
still reported at `kernel` — a fact about the connection — but nothing is
read out of it.

**[ID-E7] Impersonation never leaks a thread.** Impersonation is a
property of an OS thread, not of a goroutine, and the Go scheduler may
move a goroutine between threads; a leaked impersonation is a thread that
will run unrelated work wearing a client's token. The package MUST run
every impersonation on its own goroutine, locked to its thread, and MUST
revert on success, on error and on panic. If `RevertToSelf` itself fails,
the goroutine exits without unlocking so the Go runtime destroys the
thread rather than returning it to the pool, and the caller gets
`ErrImpersonationStuck` instead of an identity.
`TestImpersonationIsAlwaysReverted` drives all three paths and then probes
threads from the runtime's pool for a leaked token; the probe cannot fail
spuriously, but it samples rather than proves.

A signature names a publisher, not a program: `kernel32.dll` verifies as
trusted and names *Microsoft Windows*, which answers a different question
than a consent prompt asks. Many Windows binaries, `powershell.exe` among
them, are signed only through a system catalog; their publisher is the
catalog's signer, and the package sets `Code.Catalog` beside it. A catalog
lists a file by hash and names no path; the package consults the catalogs
only for files under the Windows directory, which bounds the cost; a copy
of a listed file under that directory, including in its user-writable
folders, names the same publisher. A subject name is whatever a CA was
willing to issue, so `Code.Issuer` is reported beside it: pinning the
subject alone pins nothing, since two publishers can share a display name.
A signed program
is not a trustworthy program: `python.exe`, `powershell.exe`, `node.exe`,
`wscript.exe` and every signed Electron shell verify perfectly and say
nothing about the script they were pointed at; a rule that grants a
permission to a signed interpreter grants it to everything anyone can feed
that interpreter. `GetNamedPipeClientProcessId` reports the process that
opened the client handle, which is inheritable and duplicable, so it names
who opened the pipe, not who is writing to it — Windows does not
re-attribute the connection. A client that opens the pipe with
`SECURITY_ANONYMOUS` gives the server a token it can learn nothing from,
and the package reports the user as unknown with that reason rather than
inventing a weaker answer. A pipe is reachable over SMB unless the server
passes `PIPE_REJECT_REMOTE_CLIENTS`; a remote client has no pid on this
machine and a token that says nothing about which program is running, and
the package refuses it with `ErrRemotePeer` (`ID-E2`) — the fix belongs in
the server.

Two processes running as the same user at the same integrity level are not
isolated from each other: either can open the other with full access and
write into it — `OpenProcess`, `VirtualAllocEx`, `CreateRemoteThread`, or
simply a debugger — so a program that wants a permission granted to
*LogViewer* does not need to forge anything this package measures; it can
wait for the real LogViewer to run and borrow its process outright, plant
a DLL, or replace the binary on disk between logon sessions. "Allow
LogViewer to read the System log" is, in practice, "allow anything this
user runs to read the System log," and a permission system MUST NOT tell
the user otherwise. The boundary that does hold is across integrity levels
and across users — `User.Integrity` and `User.IntegrityRID` are reported
for that reason, and a service that only ever grants downwards is making a
decision the OS will actually enforce. A grant MUST be recorded against
something more durable than a path — the package full name where there is
one, otherwise the signer subject and issuer — and re-checked on every
connection, never once at grant time, because a path is a name and the
file behind it can be replaced by anyone who can write to it. A service
MUST never read an identity out of a request: there is no API here that
accepts one, and `ProofClaimed` exists only to name what is being refused.
`TestClaimedIdentityIsIgnored` connects twice with two different lies and
requires the derived identity to stay identical.

"app X requests Y" is honest as a description on Windows — the prompt says
which program opened the connection, where its file is, who signed it, and
which user and integrity level it runs at, all of it the operating
system's own answer rather than the caller's — and not honest as a
guarantee whenever the caller is at the same integrity level as the thing
it is asking about, where the prompt names a program but constrains
nothing. Say "application-level, not a security boundary" in that case, or
grant only downwards, where Windows enforces the answer.

## Linux

Over `AF_UNIX`, checked against Linux 6.18. **The user, at `kernel`.**
`SO_PEERCRED` returns a `struct ucred` the kernel copied into the socket at
`connect(2)`; not a lookup and not a claim, and it survives the peer's
death. **The LSM label, at `kernel`, as part of the subject.** `SO_PEERSEC`
returns the SELinux context or AppArmor `policy profile` the peer had at
connect. It is reported as `User.SecurityContext` rather than as an
attribute of its own, because that is what it is: a label the kernel
attaches to a subject, by local policy, at exec. On an AppArmor system it
is worth more than the image path — the path names a file, the `policy
profile` names the policy the kernel is actually enforcing. Strings that
mean *no label* (`""`, `unconfined`, `unlabeled`, and `kernel`, which is
what a stock WSL2 Ubuntu with AppArmor disabled answers) are discarded
rather than reported as if a policy had named the peer. **The process id,
at `kernel`.** Same `ucred`, same connect-time stamp; the number is a fact
about the connection and survives the peer.

**[ID-U2] The image path needs `SO_PEERPIDFD`.** Linux 6.5 added a
getsockopt that returns a pidfd for the peer, derived by the kernel from
the connection rather than looked up from a number afterwards; while that
fd is open the pid cannot be reassigned, so `/proc/<pid>/exe` read behind
it refers to the peer or to nothing, never to a successor, and the package
verifies the pin by requiring `/proc/self/fdinfo/<pidfd>`'s `Pid:` line to
still name the peer both before and after the read. The image path reaches
`bound` with `SO_PEERPIDFD`. Without it the same read is `pid`, with a
`why` naming the missing kernel feature.
`TestTheProofSaysWhetherThePidWasPinned` asserts a kernel that has it;
`TestWithoutPidfdNothingFromProcIsBound` asks for an option number that
does not exist, to make a modern kernel behave like an old one. Flatpak
(from `/proc/<pid>/root/.flatpak-info`) and Snap (from the cgroup path)
read a sandbox application id at the same strength as the path; see the
next paragraph before writing a rule against one.

**[ID-U4] Identification needs no read.** Everything Linux offers is
available the instant `accept` returns; unlike Windows, a Linux service
MUST be able to refuse a caller without ever taking a byte from it.
`TestIdentifiesBeforeAnythingIsRead` asserts it.

**[ID-U3] An invisible pid is refused.** `SO_PEERCRED` translates the pid
into the reader's pid namespace and reports `0` when the peer is not
visible in it — a peer in a container, for instance. The package MUST
refuse such a connection outright rather than reporting a subject with no
process attached.

**[ID-U1] `Code` is `none`, permanently.** Linux has no per-connection
verification of code signatures for ordinary ELF binaries; IMA and
dm-verity exist and are not queryable this way on a normal desktop. `Code`
MUST be `none` on Linux, `CanEver(Need{Code: …})` MUST fail for every
level, and a permission model that needs a publisher name MUST NOT ship on
Linux claiming to have one.

There is no standard way to learn what a process *is*: Linux answers *who*
strongly (uid, gid, the LSM label) and has no portable answer for *what*.
Flatpak's application id is an INI file bubblewrap mounts read-only inside
the peer's own mount namespace; Snap's `snap.<instance>.<app>` cgroup path
is writable by a same-uid process under cgroup v2 with systemd user
delegation; Firejail is detectable and carries no application id.
`Package` on Linux therefore answers what the peer's sandbox says it is —
useful for a log line, not a defence against a hostile process running as
the same user. Anything read from `/proc/<pid>` answers a question about a
number at the instant of the read; without a pidfd nothing holds it still,
which is why an unpinned read is reported at `pid` rather than dressed up,
and why the Windows-style `bound` comparison does not port — the start
time is field 22 of `/proc/<pid>/stat` in `USER_HZ` ticks since boot,
converting it needs `/proc/uptime` read non-atomically together with an
ABI tick rate, and a bound that is approximately right is not a bound, so
the conversion is allowed only to refuse, never to promote a proof
(`startTimeSlop` is two seconds, to keep that refusal from firing on the
noise). When the executable has been unlinked since exec, the kernel
appends ` (deleted)`; the package strips the marker and reports the path
at `pid` regardless, because the path no longer refers to the file the
peer is running. `/proc/<pid>/exe` and `/proc/<pid>/root` are gated by the
ptrace access mode: a root service can read any peer, a per-user service
can read its own user's peers, and a cross-user read without privilege
comes back unknown with the error attached.

A same-uid process can usually attach to another with `ptrace`
(`kernel.yama.ptrace_scope` narrows this to descendants at level 1 and
turns it off at levels 2 and 3, and level 0 or 1 is the desktop default),
plant an `LD_PRELOAD` through the user's own environment, and rewrite
anything the user owns, including the peer's binary between one connection
and the next; both sandbox identities this package can report are
writable the same way. "Allow LogViewer" on Linux means "allow anything
this user runs" — say so. A Linux grant is trustworthy at the granularity
of a user and describable at the granularity of a program; a policy that
needs more sits on top of an LSM policy, since the label from `SO_PEERSEC`
is the one thing on this platform that names a program and cannot be
forged by the program itself.

## macOS

Written and cross-compiled on a Windows workstation; `go build` and
`go vet` are clean for `darwin/amd64` and `darwin/arm64`, and the cgo file
that calls the Security framework has run on real hardware (`HISTORY.md`).
Over `AF_UNIX`, **the user, at `kernel`.** `LOCAL_PEERCRED` returns the
`xucred` XNU's `unp_connect` copied into the accepting socket at connect;
the accepting end keeps its own copy, so it survives the peer's death.
**The code signature, verified against running code.** This is the thing
macOS does that Windows cannot: `SecCodeCopyGuestWithAttributes` with
`kSecGuestAttributeAudit`, followed by `SecCodeCheckValidity`, asks the
kernel's own code-signing machinery about the code a process is executing,
not about a file on disk, and `Code.TeamID` comes out of that validated
signature. The rules below are why that strength does not reach the peer
over a plain socket.

**[ID-M1] The audit token is a pid lookup wearing a token's clothes.**
`LOCAL_PEERCRED` is a connect-time record; `LOCAL_PEERPID` and
`LOCAL_PEERTOKEN` are not. XNU answers both from the peer socket's
`last_pid` — the pid of the process that most recently performed a socket
operation on that descriptor — so a caller can connect and then hand the
connected socket to another program as its stdout: the first write from
that program moves `last_pid`, and every later question, including the
code signature, is answered about the other program. **Verified false on
hardware, 2026-09-05** (`HISTORY.md`): `p_starttime` is set at fork and
survives `execve`, so a placeholder forked before the connection and
exec'd into afterwards passes every mitigation attempted — comparing
`Options.ConnectedAt` against the process start time excludes only a later
*fork*, not a later *exec*; matching the audit token's euid against the
connect-time `xucred` excludes only a drifted account; rereading
`LOCAL_PEERPID` against the token after resolution excludes only drift
*during* identification. `process`, `path`, `package` and `code` MUST NOT
exceed `pid` on this transport — including `Code`, however good the
signature is — and nothing derived from the peer's pid closes the
remaining gap: a process that already existed when the connection was made
and can be induced to touch the socket.

**[ID-M2] Read the validated signature, never the claimed one.**
`SecCodeCopySigningInformation` reports what the code *claims*, and the
package MUST read nothing out of it until `SecCodeCheckValidity` has
returned `errSecSuccess`; a failed verification MUST carry no identifier,
no subject and no path, only the verdict. The package MUST NOT call
`SecCodeCreateWithPID`, which reintroduces the pid-lookup race `ID-M1`
describes; the supported route is `getsockopt(SOL_LOCAL, LOCAL_PEERTOKEN)`
for the `audit_token_t`, `SecCodeCopyGuestWithAttributes` to turn it into
a `SecCodeRef`, then `SecCodeCheckValidity`. For XPC, the implemented public
route is `SecCodeCreateWithXPCMessage` on the exact received dictionary,
followed by `SecCodeCheckValidity` before `SecCodeCopySigningInformation`.
The implementation does not call `xpc_connection_get_audit_token` or
`xpc_dictionary_get_audit_token`, and does not expose a raw message audit
token, pidversion or audit session as measured evidence.

**[ID-M3] The XPC request is the binding.** Both Unix sockets and XPC are
implemented, but neither current path supplies `Code` at `ProofSigned`.
Plain `CanEver(Need{Code: ProofSigned})` MUST fail, as MUST a code policy
checked against `CeilingFor(TransportXPC)`. XPC validates the message's code
structurally; ad-hoc validity supplies no trusted publisher, so its `Code`
and `Package` MUST remain unknown.

The current XPC receiver MUST bind the exact dictionary before exposing its
frame. Its remote connection MUST match the handler's connection, and the
connection process path MUST agree with the validated message code's main
executable. When that coherence holds, user and process are `kernel` and
path is `bound`, meeting `listen.Program`; invalid code or mismatched paths
MUST be refused before a handler sees the frame. `BindXPCRequest` keeps the
capture tied to that active request; completion invalidates later rechecks.
The client bootstrap independently checks the expected runtime executable
and user before sending a capability frame. These are program-admission
checks, not a publisher trust policy.

| | `AF_UNIX` socket | current XPC receiver |
| --- | --- | --- |
| user | `kernel`, connect-time | `kernel`, coherent message and remote connection |
| process | `pid`, most recent writer | `kernel`, coherent message and remote connection |
| path | `pid` | `bound`, agrees with validated message code |
| package | at most `pid` with cgo | `none` |
| code | at most `pid` with cgo | `none` |
| bindable | no | yes, for the active request |

The high-level receiving API is Go's `listen.ListenFramed` and
`listen.ReceiveFramed`. Shared C++/Python/Rust/Node client transports do not
provide equivalent native receiving `Peer` and `Binding` APIs; generated
proof vocabulary alone is not a receiving implementation.

**[ID-M4] Without cgo there is no code identity.** A macOS build with
`CGO_ENABLED=0` MUST report `Ceiling().Best.Code` as `none`, with the reason,
so a service whose policy needs a signature is refused at startup rather
than per connection. Unix credential extraction remains available;
`CeilingFor(TransportXPC)` MUST refuse without cgo. The implemented XPC
client expectation APIs also require macOS 12 or newer.

Every word of the Windows section on signatures naming a publisher, not a
program, applies unchanged: `/usr/bin/python3`, `/bin/sh`, an Electron
shell and a signed automation tool all verify perfectly and say nothing
about what they were told to do, and on macOS the interpreters are signed
by Apple, which makes the prompt read more reassuringly and change
nothing. Once the peer is gone, `LOCAL_PEERTOKEN` has nothing to resolve
and the pid is unavailable, but `LOCAL_PEERCRED` still answers because the
accepting socket kept its own copy — the reverse of Linux, where the pid
is a connect-time stamp that outlives the process it names.

`task_for_pid` against another process requires root and is refused for
hardened-runtime and SIP-protected binaries, so the Windows "open the
process and write into it" move is not generally available to a same-user
attacker on macOS, and code signing makes the program a more meaningful
unit than anywhere else — a strength the drift in `ID-M1` undercuts, not
the code identity, which is why the transport matters more than the API on
this platform. Trustworthy about the user; about the program, trustworthy
only against a caller with no confederate already running before the
connection — a real class of attacker, so over a plain socket a macOS
grant is a strong description and a weak guarantee. The implemented XPC
message binding supplies stronger program-admission evidence under `ID-M3`;
it does not establish a trusted publisher.

## Loopback TCP

A loopback TCP connection carries no peer credentials. A service that must
accept one — for example a local window speaking a vendor's HTTP wire to
programs that only know a base URL — binds its peer through the operating
system's record of which process owns the client socket.

**[ID-T1] `BindLoopback`.** `BindLoopback` MUST bind a peer this way and
`LoopbackCeiling()` MUST report its ceiling; both report transport
`tcp-loopback`.

**[ID-T2] Scope.** A connection whose ends are not IPv4 loopback addresses
MUST be refused with `ErrRemotePeer`, and a connection that is not TCP
MUST be refused with `ErrUnsupportedConn`.

**[ID-T3] Windows.** `GetExtendedTcpTable` (`TCP_TABLE_OWNER_PID_CONNECTIONS`)
names the process that created the client socket. `BindLoopback` opens it,
requires a creation time before the connection, and reads user, path and
package through that handle, so user, process and path reach `bound`. A
creator that has exited while the connection is still established MUST be
refused with `ErrPeerMoved`, at bind and at every recheck; a creator that
is alive and shares its socket with a second process stays invisible, the
same limit the pipe bind states.

**[ID-T4] Linux.** `/proc/net/tcp` names the socket inode and the uid the
kernel attached to the socket at creation (`kernel`). `BindLoopback` scans
same-uid descriptor tables for that inode, requires exactly one holder,
pins it with `pidfd_open`, confirms the holder behind the pin and captures
its image path, so process and path reach `bound`. Two holders, a later
change of holder, or an exec into another image MUST be refused with
`ErrPeerMoved`; a socket owned by another uid MUST be refused with
`ErrNoBinding`. Binding a peer after the only process that connected has
passed the socket names the process that now holds it.

**[ID-T5] macOS.** `BindLoopback` MUST always fail with `ErrNoBinding`,
and `Bindable` MUST read false: the per-socket process record follows the
most recent writer, the same defeat `ID-M1` measures for `AF_UNIX`, so
protected calls keep the recorded identity's refusal.

**[ID-T6] What an audit records.** `Peer.Rung()` MUST summarise transport,
platform and the proof of user, process and path in one line, the value a
decision's audit records. Binding a loopback peer reaches a weaker proof
level than the platform's native transport, and `Stronger` names that
transport. A peer MUST be bound on the line after accept, before the
service reads a byte, and rechecked before each action; the
handle-passing attack in `loopback_test.go` passes a bound connection to a
child and exits, and the recheck answers `ErrPeerMoved` on Windows and
Linux. A closed loopback `Binding` answers `net.ErrClosed` from `Peer`,
`Check` and `Alive`, through every `Shared` view, and a second `Close`
returns the first result, the same close guard `Bind` gives.

**[ID-T7] A process tree's sockets.** `Sockets()` MUST return every
listening TCP socket and bound UDP socket, IPv4 and IPv6, with the process
id the operating system's owner table names; on Windows it reads
`GetExtendedTcpTable` (`TCP_TABLE_OWNER_PID_LISTENER`) and
`GetExtendedUdpTable` (`UDP_TABLE_OWNER_PID`), and elsewhere it answers
`ErrNoBinding`. `CheckTreeLoopback(listener, contains)` MUST prove each
socket's owner a member of the caller's contained tree by process id and
creation time (`OwnedByTree`), and MUST answer `ErrBeyondLoopback` unless
every owned socket is on a loopback address (127.0.0.0/8 or `::1`) and the
tree holds its TCP listener at exactly `listener`. An empty or unreadable
table MUST NOT pass. A provider that launches a foreign engine calls it after
readiness and around each forwarded request. `AllSockets()` MUST return
every TCP socket in any state (`TCP_TABLE_OWNER_PID_ALL`: listening,
connecting, established and closing, outbound connections included, by
their local address) and every bound UDP socket, IPv4 and IPv6, with the
owner's process id, and elsewhere answers `ErrNoBinding`; a provider whose
engine must hold no network socket at all reads it.

**[ID-T8] A dialed AF_UNIX socket's server.** `BindUnixServer(c, opts)`
MUST bind the process that listens at the far end of a dialed AF_UNIX
stream connection, and a provider calls it on the line after the dial,
before sending a byte. On Windows `SIO_AF_UNIX_GETPEERPID` (`afunix.h`,
`_WSAIOR(IOC_VENDOR, 256)`) on the client socket names the server's process
id; the binding opens that process, requires its creation time to predate
the connection, asks the kernel again with the process pinned, and reads
user, path and package through the handle, so user, process and path reach
`bound`. A later answer naming another process or creation time MUST be
refused with `ErrPeerMoved`. A recheck passes unanswered only when the
socket is closed or disconnected (`WSAENOTSOCK`, `WSAENOTCONN`,
`WSAECONNRESET`, `WSAECONNABORTED`, `WSAESHUTDOWN`); any other failure to
ask MUST refuse with `ErrNoBinding`. The kernel keeps naming the server's
process after the server exits. On Linux the client socket's peer
credentials name the process that called `listen(2)`, and the binding is
`Bind`'s (`ID-B1`..`ID-B3`). macOS MUST answer `ErrNoBinding`: the client
socket's `LOCAL_PEERPID` and `LOCAL_PEERTOKEN` follow the server socket's
most recent writer (`ID-M1`), so no primitive pins the listening process,
the same refusal `BindLoopbackServer` gives there. A connection that is not
AF_UNIX MUST be refused with `ErrUnsupportedConn`; other platforms answer
`ErrNoBinding`. The caller compares the bound process with the engine it
started (abstraction-inference CONTRACT.md INF-EL2): a socket path in a
directory only the account can write keeps other accounts out, and the
process check refuses another program of the same account that bound the
path first.

## Elevated helper

A protected operation runs in OA's helper, elevated by the platform's prompt,
which talks to the person's unelevated runtime (abstraction-facade FAC-H1,
FAC-H2). Each end checks the other with the bindings above.

**[ID-H1] An elevated helper of this account.** `CheckElevatedHelper(peer,
self, program)` MUST accept a peer only when its user reads at `kernel`, is a
Windows user with the same SID as `self` (ID-S1), is elevated and carries a
high or higher mandatory integrity level (RID at least `0x3000`); its process
reads at `kernel`; and its image path reads at `bound` and names `program` by
`SameSubjectProgram`. Every other peer MUST be refused with `ErrNotHelper`:
another account (a different administrator approved in the prompt included),
an unelevated or medium-integrity token, an unreadable integrity level or
another image. It reads no file; the caller checks `program` with ID-D2 before
trusting it. Outside Windows it refuses every peer. Tests:
`TestCheckElevatedHelper`.

**[ID-H2] The helper's server.** The helper verifies the runtime it connects
to with `listen.FrameClient.Server` before sending a byte: a
`ServerExpectation` whose principal is the helper's own token user and whose
program is an installed runtime image beside the helper
(`openabstractionsw.exe`, then `openabstractions.exe`) that ID-D2 accepts with
`MachineOwners()`. The binding is `BindServerConn`'s; a server bound to
another user or image is refused with `ErrServerUntrusted`, and the helper
then tries the next image or stops. Tests: `TestHelperServerExpectation`
(abstraction-facade go-core/protected).

## Path identity

**[ID-F1] Which question, which function.** Whether two paths name one file
is asked of the filesystem (VISION.md L623; DL-R31 in the download
contract). This package owns every path comparison OA makes, one function
per question:
- `SameFile(a, b)`: two existing paths name one file exactly when their file
  identity, volume serial number and file ID (`os.SameFile`), is one. A
  junction or link and its target, and an 8.3 alias and its long name, are
  one file; names the volume keeps apart, such as twins differing by a KELVIN
  SIGN or a LONG S, are two. A side that cannot be read MUST answer false
  with its error.
- `Within(path, folder)`: path lies inside an existing folder when a folder
  above it, after the deepest existing one is resolved through links, is
  folder by file identity. It replaces every prefix and `filepath.Rel` test
  of containment.
- `SamePathName(a, b)` and `PathNameWithin`: the names of files that may not
  exist, compared as the file system compares names (on Windows ordinal
  ignoring case through the system uppercase table, `CompareStringOrdinal`;
  elsewhere byte for byte). Only a rights rule naming a program not yet
  installed, a collision check before placement and a fixed or pinned file
  name use them. Unicode case folding MUST NOT compare paths anywhere.
  Known limit (0.4.0): macOS volumes ignore case by default, yet these
  compare byte for byte there, so two names they keep apart can name one
  file on a Mac.

A set or map of existing files keys by `FileKey`, the same file identity; a
place that may not exist yet keys by `PlaceKey`, the final path of its
deepest existing folder and the names still to be created below it, each
without the trailing dots and spaces Windows strips when it creates a name.
`SameSubjectProgram` takes byte-equal canonical spellings as one program.
When both programs exist on a local drive, their file identity
(`ProgramKey`) decides, so two files in a case-sensitive folder whose names
differ only in case are two programs. When either does not exist or is off
a local drive, `SamePathName` of the canonical spellings decides.

These functions MUST open nothing off a local drive. `LocalPath` decides
from the spelling, the full path and the drive's type, and opens nothing.
On Windows it admits an absolute path on a local drive letter, given
directly or as `\\?\X:\`, and refuses with a `NotLocalPathError`
(`errors.Is(err, ErrNotLocalPath)`) a UNC path (`\\host\…`, `\\?\UNC\…`), a
`\\.\` path, every other `\\?\` path such as `\\?\GLOBALROOT`, an NT object
path (`\??\`), a network drive letter, and a path with a reserved device
name (CON, PRN, AUX, NUL, COM0-9, LPT0-9 and their superscript forms,
CONIN$, CONOUT$) as any component, with any extension. On macOS it admits a
path whose volume, or the volume of its deepest existing folder, reports
`MNT_LOCAL` to `statfs`, and refuses with the same error a network volume
(SMB, NFS, AFP, WebDAV), a path no part of which can be read, and a volume
that does not answer within 500 ms. A dead mount can block `statfs`, so
probes are counted per mount, the mount-table entry whose mount point is
the longest prefix of the path's spelling: at most eight are outstanding
on one mount, a further path on a mount with a probe past its deadline is
refused at once, and one on a mount whose eight probes are all still
within their deadline waits for a slot within its own 500 ms. A dead mount
therefore refuses only paths spelled on it. On macOS a path and the mount
points are first rewritten through the firmlinks in `/usr/share/firmlinks`
and the symbolic links directly in `/` (`/Users` is
`/System/Volumes/Data/Users`, `/home` is the `auto_home` automount at
`/System/Volumes/Data/home`), so a firmlinked folder counts against the
data volume; a path reaching a mount through any other link counts against
the mount its spelling names. The mount table is read without asking any
volume (`getfsstat` with `MNT_NOWAIT`, `/proc/self/mountinfo`), by one
reader at a time and never past a caller's deadline: a stale table is used
while a fresh one is read, and a caller that finds no table yet waits for
the first read only within its 500 ms. `statfs` looks the path up and opens nothing. On Linux the same
deadline and cap apply, and the volume's `statfs` `f_type` decides: NFS,
SMB, CIFS, SMB2, Ceph, AFS, 9P, Coda, NCP, Lustre, GPFS, BeeGFS, GFS2,
OCFS2, PanFS, StorNext, IBRIX, ACFS, VirtualBox, VMware and Parallels shared
folders, and an automount point left unmounted (autofs) are refused with
the same error, and so is WSL's 9P view of the Windows drives under `/mnt`.
`f_type` is one value for every FUSE mount, so a FUSE path is local only
when the mount with its device number in `/proc/self/mountinfo` has a type
known to hold local data (`fuseblk`, `fuse.lxcfs`, `fuse.squashfuse`,
`fuse.squashfuse_ll`, `fuse.fuse-overlayfs`); sshfs, rclone, gvfsd-fuse,
virtiofs, a plain `fuse` and every unknown type are refused, and so is a
mount missing from the table. Every other file system is local. A stacked
file system (overlayfs, fuse-overlayfs, squashfuse, a file system on a loop
image) is judged by its top layer, the volume `statfs` reports for the
path, and the layers below it are not probed, so a container root on
overlayfs is local. Linux reads
the path's device number by lookup (`stat`) and the mount table from procfs,
and opens nothing on the volume. Every consumer fails closed on a refusal: it never reads a
refused path, or a comparison it could not make, as the permissive answer.
`Inside(path, folder)` answers by `Within` when both are local and folder
exists, by spelling (path's cleaned spelling begins with folder's and a
separator) only when folder does not exist yet, and false when either path
is refused or cannot be read; a caller for whom false is permissive, such as
a guard that keeps what lies inside, checks `LocalPath` itself.
`InsideRel(path, folder)` answers the same question with path's remainder
below folder and the error behind a false answer: `ErrNotLocalPath` for a
refused path, or the read error when folder exists. A caller for whom
either answer is permissive, such as discovery that records what lies
outside a store, skips a path whose `InsideRel` returns an error.
`privatedir.CheckModelsRoot` refuses a root `LocalPath` refuses, and its
home check reads a comparison error as "may hold". `SameFile`,
`Within`, `WithinRel`, `FileKey` and `PlaceKey` answer that error for a
refused side before any open, and `CanonicalProgramPath` returns a refused
path unchanged. Opening a share would send the account's credentials to
its host and can stall for as long as the host takes to answer. A caller
that must name a program on a share, such as a rights rule for a program
run from one, compares it by `SamePathName`; `SameSubjectProgram` does so
itself. Every handle these functions open carries a security quality of
service at identification level (`SECURITY_SQOS_PRESENT |
SECURITY_IDENTIFICATION`). A symbolic link on a local drive whose target
is a share is followed by the system when the link is opened; a final path
off a local drive is refused for every later open. A drive letter remapped
to a share after the check is not covered.

## Private folders

**[ID-D1] A folder private to this account.** `go/privatedir` is OA's one
helper for a folder only this account may write. `Make` MUST create the
folder with its private descriptor applied at creation: on Windows owned by
this account with a protected DACL of two entries, this account and SYSTEM
with full control, inherited by what it holds; elsewhere mode 0700. It MUST
refuse an existing path, a link included. `CheckDir` MUST refuse
(`ErrNotPrivate`) a folder that is a file, a link or a junction, that
another principal owns, or whose access reaches beyond this account (and
SYSTEM on Windows): an inherited or unprotected DACL, an entry for any other
principal, no DACL at all; any group or other bit, or a mode other than
0700, elsewhere. `Ensure` makes an absent folder with `Make`, creating its
parent as an ordinary folder, and then MUST apply `CheckDir` to whatever
stands at the path. A relative path MUST be refused. Its callers are the
engine socket root and launch directories (inference INF-EL2), the span
record folder (INF-MS7), the Lemonade provider's state and package folders,
and the storage reader's digest record (storage-over-local-stores LS-12).
Tests: `TestEnsure`, `TestThePrivateFolderDescriptorRule` (Windows),
`privatedir_unix_test.go`.

**[ID-D2] A path only trusted principals can change.**
`trustedpath.CheckFile(path, owners)` decides whether a file may be read as
content only trusted principals wrote, reading attributes and security
descriptors and never content. `owners` names the trusted principals by
SID; `trustedpath.MachineOwners()` is SYSTEM, Administrators and TrustedInstaller,
and setting its `Account` adds the calling account (a folder OA keeps for
itself). On Windows it MUST refuse (`ErrUntrusted`) a path that is not an
absolute local path; a path where the file or any folder above it up to the
volume root is a reparse point (link, junction or mount point), checked
before any owner; a file or folder whose owner is not trusted; a file whose
DACL lets another principal write or append data, write extended
attributes or attributes, delete it, or change its access or owner; a
folder whose DACL lets another principal delete children, delete or rename
the folder, or change its access or owner; and a missing DACL. An
inherit-only entry does not apply to the object it sits on, and a deny
entry narrows access. Adding a file or subfolder is allowed to anyone: what
another account adds is owned by that account. `trustedpath.CheckExecutable`
is the executable-folder mode for a program that runs elevated (abstraction-
facade FAC-H1): the folder holding the file MUST also refuse another
principal's right to add a file or a subfolder, or generic write, since the
loader may pick up a library planted beside the program. Tests:
`TestTheExecutableFolderRule`. Outside Windows it refuses
every path until a rule is written there. Callers: the storage reader's
pinned ASUS files (storage-over-local-stores LS-12) and the video
provider's in-place model files. Tests: `TestTheRuleOnDescriptors`,
`TestRealPaths`, `TestASUSModelFilesPass`.

**[ID-D3] A model folder of this account.** A folder OA keeps model files in
for itself is a model folder: on Windows owned by this account, with a
protected DACL of three entries, this account, SYSTEM and Administrators with
full control; every file and folder below it is owned by this account and
carries exactly those entries, marked inherited from it. Elsewhere no group
or other write bit is on it or below it. Its files then pass ID-D2 with the
machine's owners and this account, and the metadata shortcut applies to them.

`privatedir.ProtectModelFolder(dir, roots)` changes no file with a name
outside `roots`: a file whose second name lies in the job store is the same
file, and its ACL changes with the folder. It MUST refuse a root that
exists and fails `CheckModelsRoot`, and leaves out one that does not exist.
It MUST open `dir` and every entry below it as itself (a reparse point opened as
the reparse point), each folder before what it holds, and hold every handle,
with data access and without delete sharing so the entry cannot be renamed,
deleted or replaced, until it returns. It MUST refuse the whole folder, and
change nothing, when `dir` lies under none of `roots`; when `dir` or any entry
below it is a reparse point, judged on the handle; and when a file below has
more than one name and any of its names lies outside every folder in `roots`.
On Windows every name is listed with `FindFirstFileNameW` and
`FindNextFileNameW`; elsewhere a file of more than one name is refused. A
caller names OA's own folders as `roots`: the models root and the runtime's
job store, whose results `LinkResult` gives a second name (job JOB-A17). Only
after every entry is judged does it write, and each descriptor MUST be written
through that entry's own handle (`SetKernelObjectSecurity` on Windows,
`fchmod` elsewhere), never by path, and with no inheritance propagated by the
system. `privatedir.CheckModelFolder(dir)` MUST refuse (`ErrNotModelFolder`)
a folder that is a file, a link or a junction, owned by another principal,
with an unprotected DACL, no DACL, or an allow entry for anyone beyond those
three. `privatedir.CheckModelsRoot(root)` MUST refuse a folder OA would own, a
models root or a job store, when it is a drive or volume root, this account's home
or a folder holding it, or a known folder (Documents, Desktop, Downloads,
AppData and its Roaming and Local folders); when it or any folder above it is
a reparse point; or when its handle's final path
(`GetFinalPathNameByHandleW`) is not the path given. A relative path MUST be
refused. Callers: the video provider's recorded set folders under its models
root (`modelhostd models install`, `models protect`). Tests:
`TestProtectModelFolder`, `TestProtectModelFolderHardLinks`,
`TestProtectModelFolderSwapAfterScan`, `TestCheckModelsRoot` (Windows).

## Limits, side by side

| | Windows (npipe) | macOS (unix) | macOS (XPC) | Linux (unix) |
| --- | --- | --- | --- | --- |
| user | `kernel` | `kernel` | `kernel` under `ID-M3` | `kernel` |
| process | `kernel` | `pid` | `kernel` under `ID-M3` | `kernel` |
| path | `bound` | `pid` | `bound` | `bound` with `SO_PEERPIDFD`, else `pid` |
| package | `signed` (MSIX) | at most `pid` with cgo | `none` | `bound` / `pid` (sandbox id, advisory) |
| code | `bound` (Authenticode) | at most `pid` with cgo | `none` | `none` |
| bindable | yes | no | active request | with `SO_PEERPIDFD` |
| identify before parsing a frame | yes, after a bounded read | yes | yes, from the exact message | yes |
| fresh lookup after peer exit | pid only | user only | active request required | user and pid |

**[ID-L3] The subject ports.** `user` reads `kernel` on every platform,
which is why a policy about the subject — Windows and Java call the same
account-plus-program idea a principal — is the one policy that ports
unchanged. Over Unix sockets, `process` is weaker on macOS than on Windows: Windows records
the client's pid on the pipe instance when it opens, fixed for the life of
the connection, while macOS re-resolves it on every call from a field that
moves.

**[ID-L4] `signed` is package evidence on Windows.** MSIX `Package` can
reach `signed`; ordinary-program `Code` does not. Windows Authenticode is
`bound`: the verified subject is a file rather than the running program.
Unix macOS code verification is of the running program, but its selection
rests on a mutable field and is capped at `pid` (`ID-M1`). Current XPC
structural validity does not promote `Code` or `Package` (`ID-M3`).

**[ID-L7] Privilege is not a proof level.** A ceiling is a fact about the
platform and the transport, not about the account the service listens as;
running as a more privileged subject MUST move no entry in the table
above. A service under `NT SERVICE\<name>`, under `DynamicUser=yes`, or
under a dedicated user in a `LaunchDaemon` as Apple's TN2083 recommends
reaches exactly the proof levels above and no others — `ProofSigned` stays
out of reach over a pipe or a socket whoever listens. A separate subject
does buy something on the far side of the connection: state the person's
own programs cannot write, so a policy file or an audit record becomes
tamper-evident against same-user code. That is auditability, not
containment; read *privileged* as *stronger identity*, not *stronger
isolation*.

The same-user, same-integrity argument made for Windows above holds on
both Unix platforms too, with different mechanics: Linux's ptrace and
`LD_PRELOAD` routes are in the Linux rules above; macOS is the platform
where the program is genuinely a stronger unit, undercut only by the
socket drift `ID-M1` measures, not by the code identity itself.

## Outcomes

| call | outcomes |
|---|---|
| `OfHandle`, `OfConn` | a `Peer` with a `Proof` per attribute, or `ErrNotServerEnd` (`ID-E1`), `ErrRemotePeer` (`ID-E2`), `ErrUnsupportedConn` (`ID-E3`), `ErrUnimplemented` (`ID-E4`), `ErrMustReadFirst` (`ID-E6`, Windows) |
| `Bind`, `BindConn`, `BindLoopback` | a `Binding`, or the same errors, plus `ErrNoBinding` when this platform has no primitive for it (`ID-T5`) and, on a later recheck, `ErrPeerMoved` (`ID-T3`, `ID-T4`) |
| `Check` | nil, or an error naming every attribute that fell short (`ID-C1`) |
| `Sockets`, `AllSockets`, `CheckTreeLoopback`, `CheckLoopbackOnly` | the sockets, or nil; `ErrBeyondLoopback` for an owned socket beyond loopback or an unobserved own listener; `ErrNoBinding` off Windows (`ID-T7`) |
| `BindUnixServer` | a `Binding` of the listening process; `ErrUnsupportedConn` for a connection that is not AF_UNIX, `ErrPeerGone` for a server process that cannot be opened, `ErrPeerMoved` for one created after the connection or a later answer naming another, `ErrNoBinding` where no primitive exists (`ID-T8`) |
| `CanEver` | nil, or an error naming the attribute this platform can never prove |
| `CheckElevatedHelper` | nil, or `ErrNotHelper` naming the first condition that failed (`ID-H1`) |
| impersonation (Windows) | the identity, or `ErrImpersonationStuck` when `RevertToSelf` itself fails (`ID-E7`) |

No numbered refusal enum is declared beyond the named `Err*` values above;
`ProofFailure.why` on the wire carries free text naming the attribute and
the shortfall.

## Bounds

At most 256 cached Authenticode verdicts are held on Windows, each valid
for five minutes against a change in this machine's trust (`ID-W2`); an
account name is cached for one minute (`ID-W3`); a loopback bind's own
bounds are `ID-T1`..`ID-T6`.

Seventeen rules are reachable by a driver alone, needing nothing but the
machine it runs on: the ladder and `Attr.AtLeast`, `Ceiling` and
`CanEver`, `Check`, the claim that never lands, the wrong end of the
connection, a weak answer that is not an error, and the code the platform
refused. Six scenarios in `testdata/scenarios/` cover them.

Every rule that binds a peer needs an adversary that does not exist as a
driver fixture: `ID-B1`, `ID-B2`, `ID-B3` and the macOS drift `ID-M1`
assert what happens when a hostile peer hands a connected socket to
another program, forks a placeholder before connecting and execs into it
afterwards, or lets its pid be recycled. `bind_attack_*_test.go` is that
adversary, in Go only; until the same adversary exists as a fixture the
shared runner can drive, these rules are UNPROVEN across languages, and a
run that omits them says so.

MSIX package identity at `signed`, a Developer ID team identifier needing a
certificate and a console logon session to unlock it, `ID-U2`'s two
kernels (with and without `SO_PEERPIDFD`), `ID-U4`'s LSM enforcement,
`ID-E2`'s peer over SMB, `ID-E7`'s failed `RevertToSelf`, and `ID-L7`'s two
ceilings under two subjects (the second made at install time by an
administrator) are each measurable only on a platform, and no fixture
closes the gap; each is UNPROVEN by name until somebody runs it there.
`conformance/capabilities.list` and `conformance/DRIVER.md` now include the
`identity` token, the scenario operations and verdicts (`unproven`,
`no-answer`, `differs`, `unimplemented`). A driver that does not advertise
the required capability still reports those scenarios unreachable; the
presence of the token does not close the adversary or platform gaps above.

Retained macOS release evidence is specific: the 0.3.0 runtime receipt in
`research/release-0.3.0/macos-installed/receipt.json` pins identity `v0.4.2`
at `98a2d9a42684a9c58d9d137d91e196e51ba1e2d6`, on macOS 26.6.2 arm64.
Its `logs/installed_check.log` and `logs/reinstalled_check.log` both record
successful default-discovery `ReadUser`, forbidden `ReplaceUser`, an
unchanged revision and `INSTALLED XPC CHECK PASSED`. This proves those
installed-package checks, not every rule or every platform of current source.

## Divergences

The proof ladder diverges from an assurance-level ladder such as
[NIST SP 800-63](https://pages.nist.gov/800-63-3/sp800-63-3.html):
`invalid`, `unsigned` and `unmet` are verdicts on a signature check that
failed, not claims about how strongly an attribute was bound, and they sit
below `pid` for that reason (`ID-P9`, `ID-P10`, `ID-P11`, `ID-P12`).

Identity's `claimed` proof level names the same idea — an unverified
assertion — as logging's `claimed` attestation standing
(`research/vocabulary/DECISION.md` D23), but the two are different scales
for different subjects; abstraction-logging's own CONTRACT.md states its
meaning.

## Not built

The adversary fixtures `bind_attack_*_test.go` drives exist in Go only;
the shared scenario protocol does not expose the same lifetime attacks to
other languages. Native receiving `Peer`/`Binding` APIs equivalent to Go's
are not implemented by the other language client wrappers. A trusted
publisher policy for XPC is not supplied by structural validity. The
platform-specific fixtures listed in Bounds remain separate obligations;
neither the shared `identity` token nor the retained macOS release receipt
establishes all-platform conformance for current source.
