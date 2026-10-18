# abstraction-identity

*For provider authors and service authors. Applications read
[For application developers](#for-application-developers).*

abstraction-identity tells a local service which program and which account is
on the other end of a connection.

Windows named pipes, Linux Unix sockets with `SO_PEERPIDFD`, and macOS XPC
provide the account, process and executable evidence required by
`listen.Program`. macOS Unix sockets have a lower process/path ceiling.
Every fact carries the proof level the transport and build supplied.

Let a local service verify which account and executable connected before it
reads a protected request. Each fact records how strongly the operating system
proved it. A service that needs executable-level proof receives no identity when
the platform can prove only the user or process.

## The problem

A privileged service that grants narrow permissions to named applications —
"allow LogViewer to read the System log" — is only as good as its ability to
tell that the caller really is LogViewer. If it cannot, every grant is theatre:
any process on the machine claims to be LogViewer and the permission model is a
list of names nobody checks.

A shipped Windows tool's own "hold the machine awake on my behalf" API takes
an unverified `owner` string over an open named pipe: two callers hold the
same lock under one name, and either releases the other's.

The operating system already knows the answer. On Windows,
`ImpersonateNamedPipeClient` plus `OpenThreadToken` hands the service the
caller's own access token, and `GetNamedPipeClientProcessId` gives a pid the
kernel wrote onto the pipe. What is missing is not the syscall — it is a way to
say how much each part of the answer is worth, so that a service needing a
verified signature can find out it cannot have one instead of quietly accepting
something weaker.

The example is in [Using it](#using-it).

The shared native IPC transport composes this package before parsing a
capability request. Applications normally consume the resulting authorization
and attribution through capability clients. Service and transport authors use
`Peer`, `Proof`, `CanEver` and the native listener directly.

## For application developers

An application does not call this layer. OA's capability services — asks,
rights, credentials, logging and the rest — call it at their own receiving
boundary, to verify who connected before reading a request. The platform
table under [Today](#today) shows the proof available on each transport.
Current source provides Program proof over macOS XPC; the macOS Unix-socket
and loopback paths still refuse calls requiring that proof.

## Words

| word | meaning |
|---|---|
| **peer** | the program on the other end: five attributes, each with a proof |
| **proof** | how hard the value would be to fake, weakest first: `none`, `claimed`, `invalid`, `unsigned`, `unmet`, `pid`, `bound`, `kernel`, `signed`. This is an assurance level in the sense of [NIST SP 800-63](https://pages.nist.gov/800-63-3/sp800-63-3.html), and **diverges** from one: three proof levels are verdicts on a check that failed rather than claims about strength; [CONTRACT.md](CONTRACT.md) says why they sit where they do |
| **claimed** | *the peer said so*; this package never produces it and has no API that accepts it |
| **bound** | read through something that ties the value to the process that connected, so no successor can take its place |
| **ceiling** | the best each attribute can reach on the running platform, known before any connection exists |
| **bind** | take the answer once at accept and refuse it afterwards rather than re-deriving it |

No rule on this page carries a tag; the contract is
[CONTRACT.md](CONTRACT.md), and the attack tests named there are what hold an
implementation to it.

Identity's proof level `claimed` differs from logging's attestation standing
`claimed`; see
[abstraction-logging](https://github.com/openabstractions/abstraction-logging)'s
[CONTRACT.md](https://github.com/openabstractions/abstraction-logging/blob/main/CONTRACT.md).

## Obtain

Install the runtime first: https://openabstractions.org/adopt.html

- **Go.** `go get github.com/openabstractions/abstraction-identity`. The module
  is at the repository root. One dependency, `golang.org/x/sys`. Releases use
  root-level `vX.Y.Z` tags; pin a release by adding `@vX.Y.Z` to the module path.
- **Other languages.** C++, Python, Rust and Node have shared capability-client
  transports in this repository. Bun supports the stream paths and refuses XPC.
  Generated identity proof vocabulary is committed for Go, C++ and Python.
  These clients reach a receiving service that derives the caller's identity;
  the language wrappers do not expose equivalent native `Peer`/`Binding`
  receiving-host APIs. The supported high-level receiver is Go's `listen/`.
  Client transport qualification and receiving-host support are separate.

The definition's `native_operations` and `native_binding_types` are descriptive
names for the core Go API. They generate common vocabulary, not native receiver
implementations in each language. `BindXPCRequest` and `XPCRequest` are exported
only in Darwin cgo builds; `CeilingFor` reports whether a selected transport is
available on this build and platform.

## What it does

```go
b, err := identity.Bind(identity.Handle(h), &identity.Options{ConnectedAt: at})
if err != nil { return err }
defer b.Close() // before the accepted connection is closed
peer, err := b.Peer() // rechecks the capture; use b.Check(policy) for a policy
if err != nil { return err }
```

`peer` carries five attributes — user, process, path, package, code — and every
one of them is welded to a `Proof`:

```
windows/npipe
  user=WORKSTATION\alice (S-1-5-21-…-1001) medium-integrity     [kernel]
  process=pid 34828 started 2026-09-05T14:24:02.234+03:00       [kernel]
  path=C:\Program Files\LogViewer\LogViewer.exe                 [bound]
  package=unknown(the peer is an ordinary executable…)
  code=LogViewer Ltd (issued by Some CA)                        [bound]
```

There is no way to read a value without being handed its proof at the same time:

```go
path, err := peer.Path.AtLeast(identity.ProofBound) // err, and no value, if weaker
```

The ladder, weakest first: `none`, `claimed`, `invalid`, `unsigned`, `unmet`,
`pid`, `bound`, `kernel`, `signed`. `claimed` means *the peer said so* — **this
package never produces it**, and has no API that accepts it. It exists so that
a service tempted to read an `owner` field out of the request payload has
somewhere to look and be told no. `invalid`, `unsigned` and `unmet` are
verdicts, not claims: the platform examined a signature and did not accept it,
and only `Code` ever lands on them. [CONTRACT.md](CONTRACT.md) says why they
sit below `pid` and in that order among themselves.

## Ask before you serve, not per connection

```go
if err := identity.CanEver(policy); err != nil {
    return fmt.Errorf("this build cannot enforce its own permission model: %w", err)
}
```

`CanEver` compares a policy against the default native stream transport's ceiling.
For a framed endpoint use `listen.CanEver(endpoint, policy)` or
`listen.ListenFramed(endpoint, policy)`; they select XPC for `xpc:` endpoints.
A policy demanding a `signed` code identity fails on all three, for three
different reasons — Authenticode verifies a file rather than a running image;
macOS verifies the running image but a socket cannot bind it to the peer; Linux
has no signature to verify. Current XPC also leaves `Code` and `Package` unknown:
structural code validity supplies no trusted publisher policy. On Linux it
also fails if the kernel is older than
6.5 and the policy wants a `bound` path, because without `SO_PEERPIDFD` there is
nothing to pin the pid. Better to fail to start than to discover that once per
connection and be tempted to relax it.

## Using it

Use the existing framed listener for a receiving service. It owns the
platform-specific capture timing and closes the binding with the call:

```go
l, err := listen.ListenFramed(endpoint, listen.Program)
if err != nil { return err } // refuses an impossible endpoint policy at startup
defer l.Close()
c, err := l.Accept()
if err != nil { return err }
defer c.Close() // also covers errors before ReceiveFramed takes ownership
call, err := listen.ReceiveFramed(ctx, c, listen.Program, listen.DefaultMaxFrame)
if err != nil { return err } // no capability frame exposed without checked proof
defer call.Close()
peer, err := call.Peer() // recheck before using the capture for an effect
if err != nil { return err }
return handle(peer, call.Frame) // application handler; never use payload identity
```

The imports are `github.com/openabstractions/abstraction-identity` and its
`listen` subpackage. `endpoint`, `ctx` and `handle` belong to the service.
`listen.Program` requires kernel user/process and bound path evidence. It
refuses macOS Unix sockets and Linux kernels without `SO_PEERPIDFD` at startup.
On macOS use a launchd-registered `xpc:service-name` with a cgo build. A
different explicitly chosen policy can admit weaker evidence; the listener
does not silently lower it. `call.WaitContext()` tracks the caller's waiting
lifetime. Accepted durable work keeps its own service-owned lifetime.

For a custom stream transport, keep the accepted connection open and close
the binding first. On Windows read one bounded frame before `Bind`, then check
the binding before parsing that frame. On Unix bind on the line after accept,
before reading any bytes:

```go
c, err := listener.AcceptUnix()
at := time.Now()                 // the line after accept

if err != nil { return err }
defer c.Close()
b, err := identity.BindConn(c, &identity.Options{ConnectedAt: at})
if err != nil { return err }
defer b.Close() // runs before c.Close
if err := b.Check(policy); err != nil { return err }
```

`Options.ConnectedAt` is worth setting on every platform, and on macOS it is
doing more work than anywhere else. It is what bounds pid reuse: nothing is read
out of the peer's pid unless the process behind it can be shown to have existed
before the connection did. On macOS this check does not prevent substitution by a process that existed
before connection; see the measured limitation below and CONTRACT.md.

## Binding a peer, instead of looking one up

`OfHandle` answers by looking the peer up when it is called, and a lookup is a
race: every platform here resolves a program from a number, and what that number
refers to can change. `Bind` takes the answer once, at accept, and refuses
afterwards rather than re-deriving.

```go
b, err := identity.BindConn(c, &identity.Options{ConnectedAt: at}) // on the line after accept
if err != nil { return err }
defer b.Close()
if err := b.Check(policy); err != nil { return err } // ErrPeerMoved, not a stale answer
```

`Bind` returns `ErrNoBinding` on a machine that has no primitive for it — a
Linux kernel below 6.5 — rather than degrading to a lookup. `Ceiling().Bindable`
says so before a connection exists, so a service can refuse to start.

`Binding.Peer` and `Binding.Check` recheck; `Captured` is a diagnostic snapshot
for logs and tests. Closing the owning binding makes subsequent rechecks return
`net.ErrClosed`. `Shared` views use that same owner and their `Close` releases
nothing. Keep views finished before closing the owner. On stream bindings,
peer exit can leave the captured identity valid; `Alive` asks about liveness
separately. Darwin Unix capture still has the ceiling below. XPC bindings belong
to one active request and become unusable when that request completes or closes.

`OfHandle` and `OfConn` are one-time lookup diagnostics. They retain no binding
to recheck later and should not replace this lifecycle in authorization code.

## Today

**Native stream profile.** `listen/` is the local listener the services above it share.

| | Windows (npipe) | macOS (unix) | Linux (unix) |
| --- | --- | --- | --- |
| user | `kernel` | `kernel` | `kernel` |
| process | `kernel` | `pid` † | `kernel` |
| path | `bound` | `pid` † | `bound` with `SO_PEERPIDFD`, else `pid` |
| package | `signed` (MSIX) | `pid` † (bundle id) | `bound` / `pid` (sandbox id, advisory) |
| code | `bound` (Authenticode) | `pid` † (Security framework) | `none` |
| can bind a peer | yes, process handle | **no** | yes with `SO_PEERPIDFD`, else no |
| identify before reading | no | yes | yes |

† macOS is the only one of the three that verifies the signature of *running
code* rather than of a file, and it is still capped at `pid`, because over a
plain `AF_UNIX` socket the audit token that selects which code to verify is
resolved by XNU from the peer socket's *most recent writer*, not stamped at
connect. `Options.ConnectedAt` was believed to close that and does not:
`p_starttime` survives `execve`, so a helper forked before the connection and
exec'ing `/bin/cat` after it passes every check and is handed Apple's signature.
Measured twice on 15.7.4; see `bind_attack_darwin_test.go`.

Current source also provides launchd-registered `xpc:service-name` endpoints.
Each request is bound to the exact XPC message before its frame reaches a
handler. The measured implementation supplies `kernel` user and process evidence
when the exact message's remote-connection process path agrees with its validated
message code, and a `bound` executable path, satisfying `listen.Program`. It validates the
message sender's code structurally, while `Package` and `Code` remain unknown
because ad-hoc validity establishes no trusted publisher. Client bootstrap
checks an independently selected runtime executable and user before sending a
capability frame. The client APIs used here require macOS 12 or newer; execution
evidence is from macOS 26.6.2 arm64. `identity.CeilingFor(identity.TransportXPC)`
reports this transport; plain `Ceiling()` continues to describe Unix sockets.

Linux is the mirror image: unforgeable answers about *who* — uid, gid, and the
LSM profile from `SO_PEERSEC` — and no general answer at all about *what*.
`Code` is `none` there permanently.

Two processes running as the same user at the same integrity level are not
isolated from each other on Windows, so "allow LogViewer to read the System
log" is in practice "allow anything this user runs to read the System log".
This package makes the prompt an accurate *description*; it does not make it a
*guarantee*, and a prompt that implies otherwise is lying to the person
clicking it. The same holds on Linux, where a same-uid process can `ptrace` its
neighbour, rewrite its binary, and fabricate both of the sandbox identities this
package can report. macOS is the one platform where the program is a meaningful
unit — `task_for_pid` is refused against hardened binaries — and it is also the
one where binding that program to the connection is weakest over a socket.
Neither trade is obvious from the API, which is why
[CONTRACT.md](CONTRACT.md) is long: what Windows will not tell you, and what a
permission system built on this must therefore refuse to promise.

## Conformance

The repository contains platform tests and retained execution evidence from
Windows 11, Linux 6.18 and 4.4, macOS 15.7.4 arm64 for Unix sockets, and macOS
26.6.2 arm64 for XPC. Those records do not establish that every current test has
run on every platform. [CONTRACT.md](CONTRACT.md) states the rules and remaining
fixture gaps; [HISTORY.md](HISTORY.md) preserves the earlier measurements.

The existing `cmd/peerid` example prints the native stream ceiling, then runs
an honest caller and this platform's impersonation attack against a service
using snapshots and bindings. From this module's root, run:

```sh
go run ./cmd/peerid
```

From the private workspace root the same command is
`go -C openabstractions-flat/abstraction-identity run ./cmd/peerid`. This exercises
real processes and a native stream connection; it does not demonstrate XPC.
The `bind_attack_*_test.go` files contain the corresponding platform attacks.

### Why macOS is the one that needs a Mac

Cross-compiling turns off the cgo that reads a running program's signature, so
darwin's own checks type-check the file without ever executing it and report
`UNPROVEN` by name until a Mac runs it; the full account is in
`research/identity/MACOS-BUILD.md`, a private research note held in this
project's own tree.

## Where it sits

Below: the platform. Above:
[abstraction-asks](https://github.com/openabstractions/abstraction-asks) and
[abstraction-rights](https://github.com/openabstractions/abstraction-rights)
bind every caller through it before reading a request, and
[abstraction-download](https://github.com/openabstractions/abstraction-download)
imports it for the same reason.

One layer of [openabstractions](https://github.com/openabstractions/abstractions).
Every layer names one thing local tools rebuild on their own; the name means the
same in each language that implements it, and the conformance scenarios are what
hold an implementation to it.

## Requirements

Go 1.25 or newer and `golang.org/x/sys`. Windows, Linux, macOS.

## Design records

Private research notes held in this project's own tree, behind the claims
made above.

- `research/macos-xpc-clients.md`
- `research/macos-xpc-exec-proof.md`
- `research/adoption/opencode-bun-binding/RESULTS.md`

## Status

**In development.** Windows named pipes, Linux Unix sockets and macOS XPC provide
the Program evidence used by current protected service tests. The macOS Unix
socket path remains below that policy and fails closed. The XPC implementation
described here is current source behavior. The retained macOS 0.3.0 runtime
release receipt pins identity `v0.4.2` at
`98a2d9a42684a9c58d9d137d91e196e51ba1e2d6`. On macOS 26.6.2 arm64 its installed
and reinstalled XPC checks both passed: default discovery `ReadUser` succeeded,
`ReplaceUser` was forbidden, and the revision stayed unchanged. The exact private
records are `research/release-0.3.0/macos-installed/receipt.json`,
`logs/installed_check.log` and `logs/reinstalled_check.log` beneath that directory.
This is release evidence for that package, not an all-platform test claim for
the current source tree.

## Licence

Apache-2.0. See [LICENSE](https://github.com/openabstractions/abstraction-identity/blob/main/LICENSE).

<!-- BEGIN GENERATED PERMISSION DEFINITIONS -->

## Permission definitions

Generated from the existing compiled catalogue. [RIGHTS.json](RIGHTS.json) contains the complete action/profile records, disclosure, lifecycle, first-use behavior, selector support and finite bundles.

This projection has no named action definition for Identity. Receiving peer proof and program comparison retain their existing contract.

<!-- END GENERATED PERMISSION DEFINITIONS -->
