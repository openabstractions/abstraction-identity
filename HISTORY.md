# History: abstraction-identity

Linked from [CONTRACT.md](CONTRACT.md)'s "Reading this page."

## Superseded ids

- **`ID-X1`..`ID-X4`** became **`ID-M1`..`ID-M4`** (macOS), same numbering,
  letter only. `X` is reserved for extension with one meaning in every
  contract (`research/vocabulary/DECISION.md` S12), and macOS's own drift
  finding, the signing-information caveat, `ProofSigned`'s unreachability
  over a socket and the no-cgo case are not extensions — they are what this
  platform cannot honestly support. Per
  `research/vocabulary/RENAME-PLAN.md`'s identity step 1. `X` is retired
  for this contract and never reused.
- Every rule's declaration moved from an inline `[ID-P2]`-style citation,
  wherever the sentence happened to end, to `**[ID-P2] Title.**` at the
  head of the paragraph that states it (S3). No id's number or letter
  changed for this move, `ID-X1`..`ID-X4` excepted.

| retired | now | rule |
| --- | --- | --- |
| `ID-X1` | ID-M1 | the audit token is a pid lookup |
| `ID-X2` | ID-M2 | read the validated signature |
| `ID-X3` | ID-M3 | `ProofSigned` is not reachable over a socket |
| `ID-X4` | ID-M4 | without cgo there is no code identity |

## Applied from research/vocabulary/DECISION.md

- D21: "rung" is "proof level" throughout — the ladder `Proof` walks, what
  `Code` is reported at when verification fails, what a loopback bind
  reaches relative to the platform's native transport, and what a more
  privileged subject does not move.
- D51: "verdict" is kept where it already named the operating system's own
  three-way signature answer (`invalid`, `unsigned`, `unmet`) — identity's
  one exception, the same way rights keeps "decision" for permit/deny.
  Nothing in this contract's prose changed for D51; identity has no typed
  outcome enum for D51 to rename.
- D16: "principal" is "subject" everywhere it named the account-plus-program
  a decision is about, keeping one sentence — `ID-L3` — that names
  principal as Java's and Windows' own word for the same idea, so a reader
  arriving from either platform can still find themselves.
- D27: "binding" as a noun for the tie between this package and a peer is
  "bound peer," "bind" (the verb) or a code citation of `BindLoopback`; the
  Go, Python, Rust and C++ type `Binding` and the functions `Bind`,
  `BindConn`, `BindLoopback` keep their names unchanged — this is a
  doc-only rename. D27's decided word, "binding," is spent by facade's
  resolved client-to-service reference, and this contract's own prose no
  longer uses the bare noun to mean something else.
- D4: "SELinux context or AppArmor profile" is "SELinux context or AppArmor
  `policy profile`," in code font, so a reader does not read Bluetooth's or
  USB's "profile" (spent by D4 for "service") into an LSM label.
- D77: "between sessions" (a Windows binary replaced on disk while a user
  is logged off and on again) and "a console session" (unlocking a
  Developer ID certificate) are "between logon sessions" and "a console
  logon session."
- D65: `Ceiling()` and the word "ceiling" keep their names; identity is the
  one contract this release where "ceiling" is not renamed to "budget"
  (inference's own `Ceiling`/`CeilingLimit` is, at D64).

## Moved here

**Tested.** Windows and Linux were checked by the tests in this repository
— Windows 11 and Linux 6.18 — not taken from documentation; where a test
proves a claim, its name is given beside the rule it proves in
[CONTRACT.md](CONTRACT.md). macOS has been executed on hardware: the drift
attack reproduced 2026-09-05, the cgo file compiled and run 2026-09-08, its
signature failure paths driven 2026-09-09.

**What was tested where**, verbatim from the CONTRACT page this replaces:

| | ran | did not run |
| --- | --- | --- |
| Windows | the whole suite, on Windows 11 | — |
| Linux | the whole suite, on Linux 6.18 (WSL2, Ubuntu 26.04), as root, with `SO_PEERPIDFD` present and with it simulated absent | as a non-root service; against a cross-user peer; on a kernel older than 6.5; on a system with SELinux or AppArmor enforcing; against a real Flatpak, Snap or Firejail peer |
| macOS | everything | compiled and run on macOS 15.7.4 arm64, Go 1.27.1 with cgo, 2026-09-05: the drift vulnerability was reproduced with a standalone probe and the mitigation shown not to catch it |

Nothing in the macOS implementation should be trusted until
`identity_darwin_test.go` has been run on a Mac, in a cgo build, and
`TestSocketOwnerDriftIsRefused` in particular has been watched to fail
before it passes — it encodes a claim about XNU's behaviour that was read
out of the kernel source, not observed.

**Reachability tiers**, the fuller account behind the current Bounds
section: identity is platform-furnished — a Windows named pipe, a Unix
socket bind — so a conformance scenario here is not the shape of a
download replay. Which tier a rule is in is a fact about the rule, not a
plan. Seventeen rules need nothing but the machine the driver runs on.
Every binding rule needs a purpose-built adversary binary per platform —
`bind_attack_*_test.go` is that adversary today, in Go, and the binding
rules are UNPROVEN across languages until the same adversary exists as a
fixture the shared runner can drive. MSIX package identity, a Developer ID
team identifier, `SO_PEERPIDFD`'s absence, an LSM enforcing, a peer over
SMB, a failed `RevertToSelf`, and two ceilings diffed under two
administrator-made subjects are each only measurable on a real platform,
and no fixture closes the gap. `conformance/DRIVER.md` closes the
capability set to four job and download tokens and classifies every
operation it does not recognise as needing a job store, so today an
identity scenario is reported unreachable rather than a pass. What these
scenarios need from that page is a fifth capability token, four verdicts
(`unproven`, `no-answer`, `differs`, `unimplemented`) and the operations
the scenario files use.

## Not carried forward here

`testdata/scenarios/*.txt` and this module's Go, C++, Python, Rust and
JavaScript source and test files cite `ID-P`, `ID-L`, `ID-C`, `ID-N`,
`ID-B` and `ID-E` ids already, unchanged by this release; none cited
`ID-X1`..`ID-X4`, so the `ID-M1`..`ID-M4` rename needed no dual reader
anywhere outside this page.
`openabstractions-flat/openabstractions.github.io/reference.html` cites
`ID-B1`, and `openabstractions-flat/abstraction-inference/CONTRACT.md`
cites `ID-T1`..`ID-T6`; both ids are unchanged by this release and both
citations still resolve. `APPLICATIONS.md` and the site's other pages are
outside this module's `WRITES` for this task and are a follow-up if they
use identity's retired words.
