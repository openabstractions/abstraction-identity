# abstraction-identity

**In development.** No tagged release; the Windows, macOS and Linux
implementations here are exercised but carry no version yet.

Every attribute a service learns about the program on the other end of a local
connection — user, process, path, package, code — arrives welded to a proof of
how strongly the platform established it, and there is no way to read the value
without the proof.

## The problem

A privileged service that grants narrow permissions to named applications —
"allow LogViewer to read the System log" — is only as good as its ability to
tell that the caller really is LogViewer. If it cannot, every grant is theatre:
any process on the machine claims to be LogViewer and the permission model is a
list of names nobody checks.

This is not hypothetical. A shipped Windows tool exposes a "hold the machine
awake on my behalf" API over a named pipe that any interactive user can write
to, takes an `owner` string in the message, and never verifies it. Two callers
can hold the same lock under the same name; either can release the other's.

The operating system already knows the answer. On Windows,
`ImpersonateNamedPipeClient` plus `OpenThreadToken` hands the service the
caller's own access token, and `GetNamedPipeClientProcessId` gives a pid the
kernel wrote onto the pipe. What is missing is not the syscall — it is a way to
say how much each part of the answer is worth, so that a service needing a
verified signature can find out it cannot have one instead of quietly accepting
something weaker.

## Words

| word | meaning |
|---|---|
| **peer** | the program on the other end: five attributes, each with a proof |
| **proof** | how hard the value would be to fake, weakest first: `none`, `claimed`, `invalid`, `unsigned`, `unmet`, `pid`, `bound`, `kernel`, `signed`. This is an assurance level in the sense of [NIST SP 800-63](https://pages.nist.gov/800-63-3/sp800-63-3.html), and **diverges** from one: three rungs are verdicts on a check that failed rather than claims about strength; [CONTRACT.md](CONTRACT.md) says why they sit where they do |
| **claimed** | *the peer said so*; this package never produces it and has no API that accepts it |
| **bound** | read through something that ties the value to the process that connected, so no successor can take its place |
| **ceiling** | the best each attribute can reach on the running platform, known before any connection exists |
| **binding** | the answer taken once at accept and refused afterwards rather than re-derived |

No rule on this page carries a tag; the contract is
[CONTRACT.md](CONTRACT.md), and the attack tests named there are what hold an
implementation to it.

## Obtain

- **Go.** `go get github.com/openabstractions/abstraction-identity`. The module
  is at the repository root. One dependency, `golang.org/x/sys`. No tag yet;
  `go get` resolves a pseudo-version of `main`.
- **Other languages.** See generated protocol and shared transport/client packages
  in this repository and the facade. Native provider support is separate.

## What it does

```go
peer, err := identity.OfHandle(identity.Handle(h), &identity.Options{ConnectedAt: at})
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

`CanEver` compares a policy against what the running platform can prove at best.
A policy demanding a `signed` code identity fails on all three, for three
different reasons — Authenticode verifies a file rather than a running image;
macOS verifies the running image but a socket cannot bind it to the peer; Linux
has no signature to verify. On Linux it also fails if the kernel is older than
6.5 and the policy wants a `bound` path, because without `SO_PEERPIDFD` there is
nothing to pin the pid. Better to fail to start than to discover that once per
connection and be tempted to relax it.

## Using it

```go
// Windows will not identify the peer until the server has read from the pipe.
// This is not optional and there is no way round it; see CONTRACT.md.
h := acceptPipeInstance()
at := time.Now()                 // the line after accept
frame := readOneBoundedFrame(h)  // do not parse it yet

peer, err := identity.OfHandle(identity.Handle(h), &identity.Options{ConnectedAt: at})
if err != nil { reject(h); return }
if err := peer.Check(policy); err != nil { reject(h); return }

handle(peer, frame) // now the bytes are a request, and never a claim about
                    // who is making it
```

On Unix the same loop is shorter, because the credentials are on the socket at
`accept` and no read is needed first:

```go
c, err := listener.AcceptUnix()
at := time.Now()                 // the line after accept

peer, err := identity.OfConn(c, &identity.Options{ConnectedAt: at})
if err != nil { c.Close(); return }
if err := peer.Check(policy); err != nil { c.Close(); return }
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
defer b.Close()
if err := b.Check(policy); err != nil { reject(c); return }       // ErrPeerMoved, not a stale answer
```

`Bind` returns `ErrNoBinding` on a machine that has no primitive for it — a
Linux kernel below 6.5 — rather than degrading to a lookup. `Ceiling().Bindable`
says so before a connection exists, so a service can refuse to start.

A peer that merely exits does not invalidate a binding: "the process that opened
this connection was X" stays true after X is gone, and every primitive here pins
the process so no successor can take its place. `Binding.Alive` is the separate
question.

## Today

**Native Go provider profile.** `listen/` is the local listener the services above it share.

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
Measured twice on 15.7.4; see `bind_attack_darwin_test.go`. XPC is where macOS
reaches `signed`, and this package speaks sockets.

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
one where the *binding* between that program and the connection is weakest over
a socket. Neither trade is obvious from the API, which is why
[CONTRACT.md](CONTRACT.md) is long: what Windows will not tell you, and what a
permission system built on this must therefore refuse to promise.

## Conformance

All three platforms are covered by tests in this repository, run on Windows 11,
Linux 6.18 and 4.4, and macOS 15.7.4 arm64 with and without cgo.
[CONTRACT.md](CONTRACT.md) has the full "what was tested where" table, and the
reasoning for every cell above. The `bind_attack_*_test.go` files run this
platform's own impersonation attack against `Bind`, and `go run ./cmd/peerid`
prints what this machine can prove, then runs an honest caller and the attack
against a service that uses both paths — two real processes, one real
connection, no simulation.

### Why macOS is the one that needs a Mac

Windows and Linux are proved by cross-compiling and then running: `go vet` for
the target catches what build tags hide, and a Linux kernel is available to
execute against. macOS is different for one reason. `codesign_darwin.go` calls
the Security framework through cgo, and **cross-compiling turns cgo off** — so
every darwin build a non-Mac can perform selects `codesign_nocgo_darwin.go`
instead, and the file that verifies a running program's signature is in no build
at all. It is not weakly checked here; it is unread.

What can be checked without a Mac, and is, by
`TestDarwinCgoBuildTypeChecks`: the file parses, and the darwin-plus-cgo build
of the package type-checks with a stub standing in for the pseudo-package `C`.
That catches a renamed constant, a struct field that no longer exists, a method
gone from `*Options`, a return type or parameter list drifting from what
`identity_darwin.go` calls, and a syntax error — each demonstrated by
reintroducing it. What it cannot catch is anything whose type comes from `C`:
`go/types` marks those expressions invalid and stops, so a return statement
built out of `C.GoString` calls can lose a value and the check stays green.

What a real check needs, in full: a macOS host with the Xcode command line
tools, and `CGO_ENABLED=1 go test ./...` in this directory — about a minute
cold. None of it can move off a Mac: the SDK headers, the framework binaries and
a signed running process to ask about are all macOS. Without a macOS runner it
stays a deliberate measurement rather than a continuous one, so our own checks
report darwin as `UNPROVEN` by name instead of passing it, and a Mac run is
dated and recorded when it happens.

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

## Licence

Apache-2.0. See [LICENSE](https://github.com/openabstractions/abstraction-identity/blob/main/LICENSE).
