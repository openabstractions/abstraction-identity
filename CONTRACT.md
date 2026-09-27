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
reach on the running platform, and MUST answer without a connection.

**[ID-L2] `CanEver`.** `CanEver(need)` compares a policy against that
ceiling and MUST be called once at startup, never per connection. A
service whose model rests on a proof this operating system cannot produce
should fail to start, not discover it once per connection.

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
re-derived.

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
signer's subject and issuer from the embedded PKCS#7 message; the rules
below say why the result cannot be promoted.

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
(measured 2026-09-17). The verdict for a peer MUST be kept for later
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
than a consent prompt asks. Many Windows binaries are signed by catalog
rather than embedded signature and verify as trusted with nothing in the
file to extract a publisher name from — the package sets `Code.Catalog` in
this case — and a subject name is whatever a CA was willing to issue, so
`Code.Issuer` is reported beside it: pinning the subject alone pins
nothing, since two publishers can share a display name. A signed program
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
exceed `bound` on this transport — including `Code`, however good the
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
a `SecCodeRef`, then `SecCodeCheckValidity`. `xpc_connection_get_audit_token`
is not public API and is not this route; the token that arrives with an
XPC message (`xpc_dictionary_get_audit_token`) is, because the kernel
stamps it on that message, precisely because a connection's own token has
been used to elevate privileges before (Computest/Sector 7, *Elevating
Privileges on macOS by Audit Token Spoofing*, 2023).

**[ID-M3] `ProofSigned` is not reachable here.** This package speaks
sockets, not XPC: `CanEver(Need{Code: ProofSigned})` MUST fail on macOS,
and the failure MUST name XPC as the transport that would prove it.

| | `AF_UNIX` socket | XPC |
| --- | --- | --- |
| user | connect-time, unforgeable | unforgeable |
| which process | resolved from the socket's current owner | stamped on the message |
| audit token | `task_info` on a looked-up pid | from the mach message trailer |
| code signature | verified — about that looked-up process | verified — about the sender |
| best honest proof | `bound` | `signed` |

A service that genuinely needs a signed identity on macOS should move its
transport, not raise its expectations of this one.

**[ID-M4] Without cgo there is no code identity.** A macOS build with
`CGO_ENABLED=0` MUST report `Ceiling().Code` as `none`, with the reason,
so a service whose policy needs a signature is refused at startup rather
than per connection; everything else on the platform still works.

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
grant is a strong description and a weak guarantee. To get a guarantee,
use XPC and the message's own audit token.

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
Linux.

## Limits, side by side

| | Windows (npipe) | macOS (unix) | Linux (unix) |
| --- | --- | --- | --- |
| user | `kernel` | `kernel` | `kernel` |
| process | `kernel` | `bound` | `kernel` |
| path | `bound` | `bound` | `bound` with `SO_PEERPIDFD`, else `pid` |
| package | `signed` (MSIX) | `bound` (bundle id) | `bound` / `pid` (sandbox id, advisory) |
| code | `bound` (Authenticode) | `bound` (Security framework) | `none` |
| identify before reading | no | yes | yes |
| identity survives the peer | pid only | user only | user and pid |

**[ID-L3] The subject ports.** `user` reads `kernel` on every platform,
which is why a policy about the subject — Windows and Java call the same
account-plus-program idea a principal — is the one policy that ports
unchanged. `process` is weaker on macOS than on Windows: Windows records
the client's pid on the pipe instance when it opens, fixed for the life of
the connection, while macOS re-resolves it on every call from a field that
moves.

**[ID-L4] `code` reaches `signed` only for a packaged application.** No
transport this package speaks reaches `signed` for an ordinary program, on
any platform; only MSIX packages on Windows reach it. `code` sits at the
same level on macOS and Windows for opposite reasons: on Windows the
verification is sound and the subject is a file rather than the running
program, on macOS the verification is of the running program and the
selection of *which* program rests on a mutable field (`ID-M1`).

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
| `CanEver` | nil, or an error naming the attribute this platform can never prove |
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
`conformance/DRIVER.md` closes the capability set to four job and download
tokens today, so an identity scenario is reported unreachable — the honest
answer, and not a pass — until it gains a fifth capability token, four
verdicts (`unproven`, `no-answer`, `differs`, `unimplemented`) and the
operations the scenario files use.

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

The shared conformance runner does not yet carry a capability token for
identity; every scenario here reports unreachable rather than pass or fail
until `conformance/DRIVER.md` gains one (Bounds). The adversary fixtures
`bind_attack_*_test.go` drives exist in Go only; no other language client
runs the same attack yet. XPC is current source behavior on macOS
(`xpc_darwin.go`, `xpc_native.h`) and this contract does not yet state its
own rules for that path; [README.md](README.md)'s "Today" section
describes what it does now.
