# Contract

Every rule this layer states, each carrying a tag, in the order they were
decided. A conformance scenario cites the tag it tests on its `# expect` line,
and a citation that resolves to no rule here is a defect in one of the two.
The scenarios are in `testdata/scenarios/`; what they can and cannot reach is
the last section of this page.

[README.md](README.md) is the door — what this layer is, how to obtain it, one
example that runs. No rule on that page carries a tag.

What this package will and will not tell a service about the program on the
other end of a local connection, and what a permission system built on it must
therefore refuse to promise.

Windows and Linux were checked by the tests in this repository — Windows 11 and
Linux 6.18 — not taken from documentation. Where a test proves a claim, it is
named. **macOS has been executed on hardware** — the drift attack reproduced
2026-09-05, the cgo file compiled and run 2026-09-08, its signature failure
paths driven 2026-09-09 — and "What was tested where" at the end of this
document is the full list of what has and has not been run.

Three platforms, three different shapes of answer. The one-line summary, before
the detail: Windows can tell you which program opened the connection and cannot
verify the code it is running; Linux can tell you who the peer is and has no
general answer to what it is; macOS can verify the running code and, over a
plain socket, cannot firmly bind that code to the connection.

---

## The shape of the answer

A `Peer` has five attributes — user, process, path, package, code — and each one
carries a `Proof` saying how hard it would be to make it lie. There is no way to
read a value without the proof; `Attr.AtLeast` returns an error instead of a
value when the evidence is weaker than the caller demanded [ID-P3].

The ladder is a total order, weakest first, and these nine names are the whole
of it [ID-P1].

| Proof | What it rests on |
| --- | --- |
| `none` | Nothing. There is no value, and none is handed out however low a minimum the caller asks for [ID-P4]. |
| `claimed` | The peer said so. **This package never produces it and has no API that accepts it** [ID-P2]. |
| `invalid` | The platform found a signature and refused it: the code was modified after signing, the certificate is expired or revoked, or the chain reaches a root this machine does not trust. The lowest of the three verdicts below — no signature is no claim, and a refused signature is a claim the operating system rejected [ID-P9]. |
| `unsigned` | The platform looked and found no signature at all. `Need{Code: ProofUnsigned}` says *I do not require a signature but I refuse a broken one*, a policy a service can honestly state; the reverse — accept tampered code but refuse unsigned code — is not one anybody can state, which is why `invalid` sits below it [ID-P10]. |
| `unmet` | The signature is intact and the platform accepted it, but the code does not satisfy the requirement the service asked for in `Options.CodeRequirement`. The strongest of the three verdicts — intact code, signed by somebody other than who was required — and still carries no identity: nothing is read out of a signature that failed the check it was given [ID-P11]. |
| `pid` | Read from a pid after the fact, without checking for reuse. Good enough for a log line, never for a permission decision [ID-P5]. |
| `bound` | Read through something that ties the value to the process that connected: a process handle whose creation predates the connection (Windows), a pidfd the kernel derived from the connection itself (Linux), a pid and pidversion cross-checked against the connect-time credentials and the connection's start-time window (macOS). Each platform's section says exactly what its version of `bound` excludes and what it does not [ID-P6]. |
| `kernel` | The kernel stamped it on the connection when the peer connected. A value the kernel produces honestly but resolves when asked is not of this kind [ID-P7]. |
| `signed` | The OS validated a code signature and this identity came out of it, rather than out of a filename [ID-P8]. |

`invalid`, `unsigned` and `unmet` are verdicts, not claims or bindings, and
only `Code` ever produces them. They sit below `pid` and everything above it:
from `pid` upward a rung says how a value was *bound* to the peer, and a
verdict is not a binding of anything, so a policy that implies verification
refuses all three by comparison alone. They sit above `claimed`: `claimed` is
*the peer said so*, and a verdict is what the operating system said, which is
always stronger than an unchecked assertion [ID-P12].

`Ceiling()` reports the best each attribute can reach on the running platform,
and it answers without a connection [ID-L1]. `CanEver(need)` compares a policy
against that ceiling and is called once at startup, never per connection
[ID-L2]. A service whose model rests on a proof this operating system cannot
produce should fail to start, not discover it once per connection.

A ceiling never reports `claimed` for any attribute [ID-L5], and `Stronger`
names the transport that would prove more than this one, empty when this
transport is already the platform's best [ID-L6].

## A policy, and what `Check` answers

A `Need` is a minimum proof per attribute. `Check` reports whether this peer
meets it, and the error names **every** attribute that fell short rather than
the first, so a service does not learn about its second impossible requirement
only after fixing the first [ID-C1]. The zero `Need` requires nothing and is
met by every peer [ID-C2]; an attribute the policy does not name is not judged,
however weak it is [ID-C3].

Nothing in a `Peer` was ever spoken by the peer. Two connections from one
program carrying two different lies about who is calling resolve to the same
identity, and no string from either payload appears anywhere in it [ID-N1].
There is no field a caller can fill in from a request and no constructor that
takes one; `ProofClaimed` exists only to name what is being refused [ID-N2].

An identity is taken once, from the connection the service accepted, and
afterwards refused rather than re-derived [ID-B1].

### Answering weakly, and not answering at all

These are different outcomes and the API keeps them apart. An answer that is
merely weak comes back as a `Peer` with low proofs and a populated `Notes`,
never as an error, because only the caller's policy knows whether weak is fatal
[ID-E5]. An error means the channel cannot answer the question at all:

- The handle is not the end the service accepted — the client end of a pipe, or
  a listening socket. Both would answer, and both would answer about the
  service itself, so both are refused with `ErrNotServerEnd` [ID-E1].
- The peer is not on this machine: `ErrRemotePeer` [ID-E2].
- The connection carries no peer credentials at all, or its handle cannot be
  reached: `ErrUnsupportedConn` [ID-E3].
- The platform has no implementation here. It returns `ErrUnimplemented`
  instead of a weaker answer from a portable fallback, because a permission
  system that silently degrades to "some process on this machine" is worse than
  one that will not start [ID-E4].

### A verdict is not a claim

`Code.Trusted` is the platform's own trust verdict. A `Code` with `Trusted`
false is a signature that exists and **failed**, and `Status` says how [ID-C5].

**A policy that demands a code identity is not met by a signature the platform
rejected [ID-C4].** `Check` compares proof levels, and a signature the
platform examined and did not accept is reported at `invalid`, `unsigned` or
`unmet` — below `ProofPID` and everything above it — so a service written
exactly as README.md's example shows, with a `CodeRequirement` the peer fails
and `Need{Code: ProofPID}`, is refused.

When verification fails, `Code` is reported at the verdict's own rung, with
`Trusted` false and `Status` naming exactly how, rather than withheld at
`none` [ID-C6]. The failure stays readable in a log line, and a service that
knowingly wants to admit an unverified caller asks for the lower rung by
name — `Need{Code: ProofUnsigned}` admits the unsigned peer by saying so, not
by omission. `testdata/scenarios/code-untrusted.txt` asserts `ID-C4` and is
green. Its step 4 stays undecided here, not because the API is undecided —
`ID-C6` settles that — but because the value itself is not one token across
platforms: `unsigned` on Windows, `unmet` on macOS, `none` on Linux where
`Code` never verifies at all.

---

## Windows: what it can honestly support

**The user, at `kernel`.** `ImpersonateNamedPipeClient` followed by
`OpenThreadToken` yields the client's own access token. The SID, the elevation
flag, and the mandatory integrity level come off that token. This is the
operating system's own answer about the security principal on the other end;
the peer neither supplies it nor can influence it.

**The process id, at `kernel`.** `GetNamedPipeClientProcessId` returns the pid
Windows recorded on the pipe instance when the client opened it. The *number* is
a fact about the connection.

**The image path, at `bound`.** The pid is turned into a process handle, the
handle's creation time is compared against the moment of accept, and anything
read out of the pid is refused unless the process was already running when the
connection existed. `QueryFullProcessImageName` is then called through that
pinned handle. See "pid reuse" below.

**MSIX package identity, at `signed`.** `GetPackageFullName` on the pinned
handle. A package full name contains a publisher hash derived from the
certificate Windows validated when the package was installed, and no unpackaged
process can be given one. This is the only Windows answer where "which program"
means more than "which file the kernel happened to execute".

**Authenticode, at `bound` — never `signed`.** `WinVerifyTrust` over an open
handle to the image file, plus the signer's subject and issuer from the embedded
PKCS#7 message. Windows really did check the signature and the chain. But see
the next section for why the result cannot be promoted.

---

## What Windows will not tell you

### You must listen before you can ask who is speaking

`ImpersonateNamedPipeClient` fails with `ERROR_CANNOT_IMPERSONATE` — *"Unable to
impersonate using a named pipe until data has been read from that pipe"* — until
the **server** has completed a read. The client having written is not enough;
the read is what unlocks it. Verified by
`TestWindowsWillNotIdentifyUntilTheServerHasRead`, which asserts all three
cases.

So a service cannot authenticate before it accepts input. The order is forced:
accept, read one bounded frame, identify, and only then decide what that frame
was allowed to ask for. Do not parse the frame first, do not size a buffer from
a length in it, and do not read a name out of it. The package returns
`ErrMustReadFirst` if asked too early [ID-E6].

### Authenticode verifies a file, not a running program

Windows exposes no way to verify the image mapping a process is executing. There
is no `SecCodeCheckValidity` here. `WinVerifyTrust` takes a file, and the process
is a section object mapped from a file that may since have been renamed,
deleted, or replaced.

This package narrows the gap as far as Windows allows: it holds the peer's
process handle open throughout, opens the image file and passes the *handle*
rather than the path to `WinVerifyTrust`, and afterwards re-asks the kernel both
what path the process is running from and what path its own open handle resolves
to, refusing the answer if the three stop agreeing. What remains is one window —
between the peer starting and this package opening the file, the file could have
been renamed away and a different file created at the name the kernel now
reports. It needs write access to the directory and precise timing, and it
cannot be closed from user mode.

That is why `Code` never exceeds `bound` on Windows, and why `CanEver(Need{Code:
ProofSigned})` fails there [ID-W1]. Asserted by
`TestWindowsRefusesToPromiseASignature`.

### A signature names a publisher, not a program

`kernel32.dll` verifies as trusted and its embedded signature names *Microsoft
Windows*. That is the best case, and it still answers a different question than
the one a consent prompt asks. Two things follow:

- Many Windows binaries are signed by **catalog** rather than embedded
  signature. They verify as trusted, but there is nothing in the file to extract
  a publisher name from. "Trusted" and "attributable" are separate answers, and
  a prompt needs the second. The package sets `Code.Catalog` in this case.
- A subject name is whatever a CA was willing to issue. `Code.Issuer` is
  reported beside it because pinning the subject alone pins nothing; two
  publishers can share a display name and any of them can buy a certificate.

### A signed program is not a trustworthy program

`python.exe`, `powershell.exe`, `node.exe`, `wscript.exe` and every signed
Electron shell verify perfectly, and say nothing whatever about the script they
were pointed at. A rule that grants a permission to a signed interpreter grants
it to everything anyone can feed that interpreter. This is not a limitation of
this package; it is a limitation of the question.

### The pid names who opened the pipe, not who is writing

`GetNamedPipeClientProcessId` reports the process that opened the client handle.
Handles are inheritable and duplicable. A process can open a pipe and hand the
handle to another process, which then does the talking. Windows does not
re-attribute the connection. The identity is of the opener, for the life of the
connection.

### pid reuse is bounded, not eliminated

Bounded, and here is exactly how far. The check is: open the process, read its
creation time, and refuse everything derived from the pid if that time is later
than `Options.ConnectedAt`. Any process that inherited a recycled pid must have
been created after the connection already existed, so this excludes all of them.
Once the handle is open the pid cannot be reassigned, so every later question is
asked of the same process.

Two conditions on that:

- **`Options.ConnectedAt` must be set** from the accept loop, on the line after
  accept returns. Left zero it defaults to the moment of resolution, which still
  excludes reuse after that moment but not reuse between accept and resolution
  [ID-B3].
- **The comparison uses the wall clock.** A clock stepped backwards can cause a
  false refusal. Refusal is the safe direction, and no tolerance is added,
  because a tolerance is exactly the width of the hole.

When the check fires, `Process.Recycled` is set and path, package and code are
all reported as `none` with the reason attached [ID-B2]. Asserted by
`TestRecycledPIDIsRefused`. When the peer has already exited, the pid is still
reported at `kernel` — it is a fact about the connection — but nothing is read
out of it.

### An anonymous client identifies nobody, on purpose

A client that opens the pipe with `SECURITY_ANONYMOUS` gives the server a token
it can learn nothing from. This is the client's choice and there is no server
override. The package reports the user as unknown with that reason, rather than
inventing a weaker answer.

### Named pipes are reachable over the network

Unless the server passes `PIPE_REJECT_REMOTE_CLIENTS`, a pipe is reachable over
SMB. A remote client has no pid on this machine and its token is a network logon
that says nothing about which program is running. This package refuses such a
peer with `ErrRemotePeer`, which is `ID-E2`, but the correct fix is in the
server: pass the flag.

### Impersonation is a per-thread privilege escalation waiting to happen

Impersonation is a property of an OS thread, not of a goroutine, and the Go
scheduler may move a goroutine between threads. A leaked impersonation is not a
wrong answer; it is a thread that will run unrelated work wearing a client's
token.

The package runs every impersonation on its own goroutine, locked to its thread,
and reverts on success, on error and on panic. If `RevertToSelf` *itself* fails
there is no way to make that thread safe again: the goroutine exits without
unlocking, which makes the Go runtime destroy the thread rather than return it
to the pool, and the caller gets `ErrImpersonationStuck` instead of an identity
[ID-E7].
Losing a thread is cheap. `TestImpersonationIsAlwaysReverted` drives all three
paths and then probes threads from the runtime's pool for a leaked token; the
probe cannot fail spuriously, but it samples rather than proves.

---

## The thing a permission system must refuse to promise, on Windows

The other two platforms have their own version of this, further down.

**Same user, same integrity level is not a security boundary on Windows.**

Two processes running as the same user at the same integrity level are not
isolated from each other. Either can open the other with full access and write
into it: `OpenProcess`, `VirtualAllocEx`, `CreateRemoteThread`, or simply a
debugger. So a program that wants a permission granted to *LogViewer* does not
need to forge anything this package measures — it can wait for the real
LogViewer to run and borrow its process outright, or plant a DLL, or replace the
binary on disk between sessions.

Which means:

- **"Allow LogViewer to read the System log" is, in practice, "allow anything
  this user runs to read the System log."** A permission system on Windows must
  not tell the user otherwise. Granting per-application, to a same-user peer,
  buys convenience and auditability. It does not buy containment, and a prompt
  that implies it does is lying to the person clicking it.
- The boundary that *does* hold is across integrity levels and across users. A
  medium-integrity process cannot touch a high-integrity one; an AppContainer
  (low or untrusted) cannot touch either. `User.Integrity` and
  `User.IntegrityRID` are reported for exactly this reason. A service that only
  ever grants *downwards* — an elevated service deciding about medium-integrity
  callers — is making a decision the OS will actually enforce.
- A permission grant must be recorded against something more durable than a
  path. A path is a name, and the file behind it can be replaced by anyone who
  can write to it. Record the package full name where there is one, and
  otherwise the signer subject *and* issuer, and re-check both on every
  connection — not once at grant time.
- A service must never read an identity out of a request. There is no API here
  that accepts one; `ProofClaimed` exists only to name what is being refused.
  Asserted by `TestClaimedIdentityIsIgnored`, which connects twice with two
  different lies and requires the derived identity to be identical.

### So: can "app X requests Y" be made trustworthy on Windows?

Only approximately, and the approximation should be stated rather than hidden.

It is honest as a **description**: the prompt can say which program opened the
connection, where its file is, who signed that file, and which user and
integrity level it runs at, and every one of those is the operating system's
answer rather than the caller's. That is a real improvement over an `owner`
string in a message, which is what the tool this package was written against
does, and which any user on the machine can write anything into.

It is not honest as a **guarantee**, whenever the caller is at the same
integrity level as the thing it is asking about. At that point the prompt names
a program but does not constrain one, and a user who reads "LogViewer wants to
read the System log" as "and nothing else can" has been misled. Say
"application-level, not a security boundary" in that case, or grant only
downwards, where Windows will enforce the answer.

---

## Linux: what it can honestly support

Over `AF_UNIX`. Checked against Linux 6.18 by the tests in this repository.

**The user, at `kernel`.** `SO_PEERCRED` returns a `struct ucred` the kernel
copied into the socket at `connect(2)`. It is not a lookup and not a claim, and
it survives the peer's death. The uid and gid are the strongest thing Linux
offers.

**The LSM label, at `kernel`, as part of the principal.** `SO_PEERSEC` returns
the SELinux context or AppArmor profile the peer had at connect. It is reported
as `User.SecurityContext` rather than as an attribute of its own, because that
is what it is: a label the kernel attaches to a subject, by local policy, at
exec. On an AppArmor system it is worth more than the image path — the path
names a file, the profile names the policy the kernel is actually enforcing.
Strings that mean *no label* (`""`, `unconfined`, `unlabeled`, and `kernel`,
which is what a stock WSL2 Ubuntu with AppArmor disabled answers) are discarded
rather than reported as if a policy had named the peer.

**The process id, at `kernel`.** Same `ucred`, same connect-time stamp. The
*number* is a fact about the connection and survives the peer.

**The image path, at `bound` — but only with `SO_PEERPIDFD`.** Linux 6.5 added a
getsockopt that returns a pidfd for the peer, derived by the kernel from the
connection rather than looked up from a number afterwards. While that fd is
open the pid cannot be reassigned, so `/proc/<pid>/exe` read behind it refers to
the peer or to nothing — never to a successor. The package verifies the pin
rather than assuming it: `/proc/self/fdinfo/<pidfd>` carries a `Pid:` line, and
it is required to still name the peer both before and after the read.

Without `SO_PEERPIDFD` the same read is `pid`, with a `why` naming the missing
kernel feature [ID-U2]. Both branches are asserted — `TestTheProofSaysWhetherThePidWasPinned`
on a kernel that has it, and `TestWithoutPidfdNothingFromProcIsBound`, which asks
for an option number that does not exist in order to make a modern kernel behave
like an old one.

**A sandbox application id, at the same strength as the path.** Flatpak from
`/proc/<pid>/root/.flatpak-info`, Snap from the cgroup path, Firejail named but
not identified. Read the next section before writing a rule against one.

**Identification needs no read from the connection.** Unlike Windows, where the
server must complete a read before it may ask who the client is, everything above
is available the instant `accept` returns. `TestIdentifiesBeforeAnythingIsRead`
asserts it. A Linux service can refuse a caller without ever taking a byte from
it [ID-U4].

---

## What Linux will not tell you

### There is no standard way to learn what a process *is*

This is the honest headline. Linux has a strong answer for *who* (uid, gid, LSM
label) and no portable answer at all for *what*. What exists instead:

- **Flatpak**: `/proc/<pid>/root/.flatpak-info`, an INI file inside the peer's
  own mount namespace. bubblewrap mounts it read-only, which is why the desktop
  portals read it. It is still a file in a namespace the peer's sandbox
  constructed, not a record the kernel keeps.
- **Snap**: `snap.<instance>.<app>` in the peer's cgroup path. Under cgroup v2
  with systemd user delegation, a process running as that user may create
  cgroups with names of its choosing and migrate itself into them.
- **Firejail**: detectable, and carries no application id to report.
- **Everything else**: nothing. An ordinary `/usr/bin/foo` has no identity
  beyond its path.

So `Package` on Linux answers *what does the peer's sandbox say it is*. That is
useful for a log line and for telling two cooperating applications apart. It is
not a defence against a hostile process running as the same user, and a
permission model that treats it as one is mistaken in a way that will not show
up in testing.

### Anything read from /proc is a question about a number

`/proc/<pid>/anything` is answered by whoever holds that number at the instant
of the read. Without a pidfd there is nothing holding it still, which is why
this package reports those reads at `pid` and refuses to dress them up.

**The Windows bound does not port.** There, the peer's process handle yields an
exact creation `FILETIME` and the comparison against `Options.ConnectedAt` is
precise and complete. On Linux the start time is field 22 of
`/proc/<pid>/stat`, in `USER_HZ` ticks since boot, and turning it into a wall
clock requires `/proc/uptime` read non-atomically at 10ms resolution together
with a tick rate that is an ABI constant. A bound that is approximately right is
not a bound. The conversion is therefore allowed only to **refuse** — a process
that started demonstrably after the connection is not the peer, whatever the
precision — and never to promote a proof. `startTimeSlop` is two seconds and
exists to keep that refusal from firing on the noise.

### /proc/<pid>/exe is a name the kernel keeps, and it can already be stale

When the executable has been unlinked since exec, the kernel appends
` (deleted)`. The package strips the marker, reports the path at `pid` whatever
else it knows, and notes it — because the path no longer refers to the file the
peer is running, which is exactly the trick a rule written against a path is
vulnerable to.

### Reading /proc needs permission the service may not have

`/proc/<pid>/exe` and `/proc/<pid>/root` are gated by the ptrace access mode. A
root service can read any peer; a per-user service can read its own user's
peers; a cross-user read without privilege gets `EACCES` and the attribute comes
back unknown with the error attached. A service that expects paths and runs
unprivileged should test that case rather than discover it in production.

### A pid can be invisible

`SO_PEERCRED` translates the pid into the reader's pid namespace and reports `0`
when the peer is not visible in it — a peer in a container, for instance. This
package refuses such a connection outright rather than reporting a principal
with no process attached [ID-U3].

### There is no code signature, and there is not going to be one

Linux has no per-connection verification of code signatures for ordinary ELF
binaries. IMA and dm-verity exist and are not queryable this way on a normal
desktop. **`Code` is `none` on Linux, permanently** [ID-U1], `CanEver(Need{Code: …})`
fails for every level, and a permission model that needs a publisher name should
not ship on Linux claiming to have one.

---

## macOS: what it can honestly support

Over `AF_UNIX`. **Not executed**: written and cross-compiled on a Windows
workstation, `go build` and `go vet` clean for `darwin/amd64` and `darwin/arm64`,
never run against a real XNU kernel. The cgo file that calls the Security
framework has not been compiled at all — `CGO_ENABLED=0` cross-compilation
excludes it, and there was no macOS toolchain in reach. Treat the macOS numbers
below as *designed and argued*, not as *measured*, and read the tests in
`identity_darwin_test.go` as the list of things to watch fail first.

**The user, at `kernel`.** `LOCAL_PEERCRED` returns the `xucred` XNU's
`unp_connect` copied into the accepting socket at connect. The accepting end
keeps its own copy, so it survives the peer's death.

**The code signature, verified against running code.** This is the thing macOS
does that Windows cannot: `SecCodeCopyGuestWithAttributes` with
`kSecGuestAttributeAudit`, followed by `SecCodeCheckValidity`, asks the kernel's
own code signing machinery about the code a process is executing, not about a
file on disk. `Code.TeamID` comes out of that validated signature, and
`Options.CodeRequirement` hands a requirement string to the OS so that the
anchor, the chain and the leaf are checked together by the code that owns the
question.

**And that is where the good news stops**, because of the next section.

---

## What macOS will not tell you

### On a unix socket, the audit token is a pid lookup wearing a token's clothes

This is the finding that changes the design, and it contradicts what an earlier
draft of this document expected.

`LOCAL_PEERCRED` is a connect-time record. `LOCAL_PEERPID` and `LOCAL_PEERTOKEN`
are not. XNU answers both from the peer socket's `last_pid` — the pid of the
process that most recently performed a socket operation on that descriptor — and
`LOCAL_PEERTOKEN` then does `proc_find(last_pid)` and asks that task for its
audit token with `task_info(TASK_AUDIT_TOKEN)`. There is no comparison against a
unique id stored at connect; there is nothing stored at connect to compare
against.

So the pidversion inside a socket-derived audit token proves that the token is
*self-consistent* — that it names one process instance rather than a recyclable
number. It does not prove that the instance is the one that connected. The
unforgeable, kernel-stamped token is the one in a mach message trailer, and a
socket does not carry one.

The consequence is concrete, not theoretical: **a caller can connect and then
hand the connected socket to another program as its stdout.** The first write
from that program moves `last_pid`, and every question asked afterwards —
including the code signature — is answered about the other program. Spawn
`/bin/echo` that way and the service sees a binary signed by Apple.

**VERIFIED FALSE ON HARDWARE, 2026-09-05.** The mitigation below does not
hold, and macOS `process`, `path`, `package` and `code` over AF_UNIX are
therefore capped at `pid`, not `bound` [ID-X1]. `p_starttime` is set at fork and is
NOT reset by exec, so an attacker forks a placeholder, connects, then execs any
chosen binary into it -- one fork before connect, and the code signature then
reads as whatever was exec'd. A connection from an ad-hoc-signed binary reported
/bin/cat signed by Apple, at the ceiling this package advertised. The strong
answer lives only in XPC, over the message's audit token; a plain socket cannot
provide one. What follows is what was attempted and why it fails:

- `Options.ConnectedAt`, compared against the process start time from
  `kern.proc.pid`, refuses every process *forked* after the connection existed.
  It does not exclude the spawn-and-hand-over family, because exec keeps the
  fork-time start stamp: the placeholder was forked before the connection and
  execs the payload after it.
- The audit token's euid must match the connect-time `xucred`. A socket that has
  drifted to a process running as somebody else is refused, not reported.
- `LOCAL_PEERPID` is read separately and must agree with the pid inside the
  token, and the token is read again after resolution and must not have moved.
  Drift *during* identification is withdrawn rather than reported.

What remains, and cannot be closed from user mode over a socket: a process that
already existed when the connection was made, and that can be induced to touch
the socket. That is why **nothing derived from the peer's pid exceeds `bound` on
this transport — including `Code`, however good the signature is.**

### `xpc_connection_get_audit_token` is the documented trap

It is not public API, and it has been the subject of a real exploitation
technique: the token attached to an XPC *connection* is not necessarily the
token of the sender of a given *message*, and the confusion has been used to
elevate privileges on macOS (Computest/Sector 7, *Elevating Privileges on macOS
by Audit Token Spoofing*, 2023). The safe primitive is the token that arrives
with the message itself — `xpc_dictionary_get_audit_token` — precisely because
the kernel stamps it on that message.

The supported route for the transport this package actually speaks is different
and simpler, and is the one implemented:

1. `getsockopt(fd, SOL_LOCAL, LOCAL_PEERTOKEN)` for the `audit_token_t`, with
   every caveat in the section above.
2. `SecCodeCopyGuestWithAttributes(NULL, {kSecGuestAttributeAudit: token}, …)`
   to turn the token into a `SecCodeRef`. `SecCodeCreateWithAuditToken` is the
   newer spelling of the same idea and is not used only because it is not
   present on every macOS this package supports.
3. `SecCodeCheckValidity(code, flags, requirement)` — the call that verifies.

**Never** take the pid out of the token and call `SecCodeCreateWithPID`. That
reintroduces exactly the race the token exists to remove, and it is a different
and worse bug than the one described above.

### `SecCodeCopySigningInformation` is not a check

It reports what the code *claims*. A team identifier read out of it without a
successful `SecCodeCheckValidity` first is a string the peer wrote into its own
binary. This package reads nothing out of the signing information until validity
has returned `errSecSuccess`, and a failed verification carries no identifier,
no subject and no path out of the function — only the verdict [ID-X2].

### A signature still names a publisher, not a program

Every word of the Windows section on this applies unchanged. `/usr/bin/python3`,
`/bin/sh`, an Electron shell and a signed automation tool all verify perfectly
and say nothing about what they were told to do. A rule that grants a permission
to a signed interpreter grants it to everything anyone can feed that
interpreter — and on macOS the interpreters are signed by Apple, which makes the
prompt read more reassuringly and change nothing.

### Nothing survives the peer's death except the principal

Once the peer is gone, `LOCAL_PEERTOKEN` has nothing to resolve and the pid is
unavailable. `LOCAL_PEERCRED` still answers, because the accepting socket kept
its own copy. This is the reverse of Linux, where the pid is a connect-time
stamp and outlives the process it names.

### Without cgo there is no code identity at all

A macOS build with `CGO_ENABLED=0` cannot reach the Security framework.
`Ceiling()` reports `code: none` in that build, with the reason, so a service
whose policy needs a signature is refused at startup rather than per connection
[ID-X4].
Everything else on the platform still works.

---

## Sockets versus XPC on macOS

| | `AF_UNIX` socket | XPC |
| --- | --- | --- |
| user | connect-time, unforgeable | unforgeable |
| which process | resolved from the socket's *current* owner | stamped on the message |
| audit token | `task_info` on a looked-up pid | from the mach message trailer |
| code signature | verified — about that looked-up process | verified — about the sender |
| best honest proof | `bound` | `signed` |

This package speaks sockets. `ProofSigned` is therefore not reachable on macOS
here, `CanEver(Need{Code: ProofSigned})` fails, and the failure names XPC
[ID-X3]. A
service that genuinely needs a signed identity on macOS should move its
transport, not raise its expectations of this one.

---

## Ceilings, side by side

| | Windows (npipe) | macOS (unix) | Linux (unix) |
| --- | --- | --- | --- |
| user | `kernel` | `kernel` | `kernel` — every platform, which is why a policy about the principal is the one that ports [ID-L3] |
| process | `kernel` | `bound` | `kernel` |
| path | `bound` | `bound` | `bound` with `SO_PEERPIDFD`, else `pid` |
| package | `signed` (MSIX) | `bound` (bundle id) | `bound` / `pid` (sandbox id, advisory) |
| code | `bound` (Authenticode) | `bound` (Security framework) | `none` — no transport this package speaks reaches `signed` for an ordinary program, on any platform [ID-L4] |
| identify before reading | no | yes | yes |
| identity survives the peer | pid only | user only | user and pid |

Two entries deserve to be read twice.

**`process` is weaker on macOS than on Windows.** Windows records the client's
pid on the pipe instance when the client opens it, and it does not change for
the life of the connection. macOS re-resolves it on every call from a field that
moves. Windows fixes the wrong-ish answer at open time; macOS offers a
right-looking answer at query time.

**`code` is the same level on macOS and Windows for opposite reasons.** On
Windows the verification is sound and the subject is a file rather than the
running program. On macOS the verification is of the running program and the
selection of *which* program rests on a mutable field. Neither reaches `signed`;
only MSIX does, on Windows, and only for packaged applications.

### Privilege is not a rung

**A ceiling is a fact about the platform and the transport, and not about the
account the service listens as. Running as a more privileged principal moves no
entry in this table [ID-L7].** A service under `NT SERVICE\<name>`, under
`DynamicUser=yes`, or under a dedicated user in a `LaunchDaemon` as Apple's
TN2083 recommends, reaches exactly the rungs above and no others; `ProofSigned`
stays out of reach over a pipe or a socket whoever listens. A service that needs
a stronger identity moves its transport, which is the thing `Stronger` names and
on macOS is XPC — § Sockets versus XPC on macOS.

What a separate principal does buy is on the far side of the connection: state
the person's own programs cannot write, so a policy file or an audit record
becomes tamper-evident against same-user code. That is auditability, and the
next section is why auditability is not containment. Read *privileged* as
*stronger identity* and this whole page has been read backwards.

---

## What a service must refuse to promise, per platform

The Windows argument above — that two processes at the same integrity level
running as the same user are not isolated from each other, so a per-application
grant buys auditability and not containment — holds on both Unix platforms too,
with different mechanics:

- **Linux.** A same-uid process can usually attach to another with `ptrace`
  (`kernel.yama.ptrace_scope` narrows this to descendants at level 1 and turns
  it off at levels 2 and 3, but level 0 or 1 is the desktop default), can plant
  an `LD_PRELOAD` through the user's own environment, and can rewrite anything
  the user owns — including the peer's binary between one connection and the
  next. On top of that, both sandbox identities this package can report are
  writable by a same-uid process (a cgroup name it can choose, a mount namespace
  it can build). **"Allow LogViewer" on Linux means "allow anything this user
  runs".** Say so.
- **macOS.** Here the platform is genuinely stronger: `task_for_pid` against
  another process requires root and is refused for hardened-runtime and
  SIP-protected binaries, so the Windows "just open the process and write into
  it" move is not generally available to a same-user attacker. Code signing and
  the hardened runtime make the *program* a more meaningful unit than it is
  anywhere else. That strength is undercut by the socket binding described
  above, not by the code identity — which is exactly why the transport matters
  more than the API on this platform.

So, to answer the question this package exists for, per platform:

- **Windows.** An honest *description*, not a *guarantee*, for a same-integrity
  peer. Grant downwards, or say "application-level, not a security boundary".
- **Linux.** An honest description of *who* — uid, gid, and on an
  LSM-enforcing system the profile, all unforgeable. An honest description of
  *what*, only as far as `/proc` and a sandbox's own bookkeeping go, and not
  against an adversary. **A permission decision on Linux is trustworthy at the
  granularity of a user, and describable at the granularity of a program.** If a
  policy needs more than that, it needs an LSM policy underneath it — the label
  from `SO_PEERSEC` is the only thing on this platform that names a program and
  cannot be forged by the program.
- **macOS.** Trustworthy about the user. About the program: trustworthy *only*
  against callers that did not already have a confederate running before the
  connection — which is a real class of attacker, so the honest phrasing is that
  over a plain socket a macOS grant is a strong description and a weak
  guarantee. To get a guarantee, use XPC and the message's own audit token.

And on every platform: a grant must be recorded against the most durable thing
available — the MSIX package name or signer subject *and* issuer on Windows, the
team identifier and a code requirement on macOS, the LSM profile on Linux — and
re-checked on every connection, never once at grant time. A path is a name, and
the file behind it can be replaced by anyone who can write to it.

---

## What a conformance run can reach

Identity is platform-furnished — a Windows named pipe, a Unix socket bind — so a
scenario here is not the shape of a download replay. Three tiers, and which tier
a rule is in is a fact about the rule, not a plan:

**Reachable by a driver alone**, needing nothing but the machine it runs on.
Seventeen rules, six scenarios in `testdata/scenarios/`: the ladder and
`Attr.AtLeast`, `Ceiling` and `CanEver`, `Check`, the claim that never lands,
the wrong end of the connection, a weak answer that is not an error, and the
code the platform refused.

**Needs an adversary that does not exist.** Every binding rule asserts what
happens when a *hostile* peer does something an honest one never does: hand a
connected socket to another program, fork a placeholder before connecting and
exec into it afterwards, exit and let its pid be recycled. A driver can fork an
honest peer; it cannot produce those without a purpose-built adversary binary
per platform. The Go tests in `bind_attack_*_test.go` are that adversary, in one
language. Until the same adversary exists as a fixture the suite can drive, the
binding rules — `ID-B1`, `ID-B2`, `ID-B3`, and the macOS drift `ID-X1` — are
**UNPROVEN** across languages, and a run that omits them says so.

**Only measurable on a platform**, and no fixture closes the gap. MSIX package
identity at `signed` needs a packaged application; a Developer ID team
identifier needs a certificate and a console session to unlock it; `ID-U2` needs
two kernels, one with `SO_PEERPIDFD` and one without; `ID-U4` needs an LSM
enforcing; `ID-E2` needs a peer over SMB; `ID-E7` needs `RevertToSelf` to fail;
`ID-L7` needs one driver run twice under two principals and a diff of the two
ceilings, and the second principal is made at install time by an administrator.
Each is **UNPROVEN** by name until somebody runs it there.

The shared runner cannot judge any of this yet. `conformance/DRIVER.md` closes
the capability set to four job and download tokens, and `run.sh` classifies
every operation it does not recognise as needing a job store, so an identity
scenario is reported **unreachable** — the honest answer, and not a pass. What
these scenarios need from that page is a fifth capability token, four verdicts
(`unproven`, `no-answer`, `differs`, `unimplemented`) and the operations the
scenario files use.

---

## What was tested where

| | ran | did not run |
| --- | --- | --- |
| Windows | the whole suite, on Windows 11 | — |
| Linux | the whole suite, on Linux 6.18 (WSL2, Ubuntu 26.04), as root, with `SO_PEERPIDFD` present and with it simulated absent | as a non-root service; against a cross-user peer; on a kernel older than 6.5; on a system with SELinux or AppArmor enforcing; against a real Flatpak, Snap or Firejail peer |
| macOS | everything | compiled and run on macOS 15.7.4 arm64, Go 1.27.1 with cgo, 2026-09-05: the drift vulnerability was reproduced with a standalone probe and the mitigation shown not to catch it |

The macOS row is the one to act on. Nothing in the macOS implementation should
be trusted until `identity_darwin_test.go` has been run on a Mac, in a cgo
build, and `TestSocketOwnerDriftIsRefused` in particular has been watched to
fail before it passes — it encodes a claim about XNU's behaviour that was read
out of the kernel source, not observed.
