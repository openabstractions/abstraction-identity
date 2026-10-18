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

## Added

- **`ID-F1` firmlinks and the mount-table read** (2026-10-07). Review of
  the per-mount cap: on macOS `/Users/...` and `/Applications/...` counted
  against `/` and not `/System/Volumes/Data`, and `/home` is a root link to
  the `auto_home` automount, so a dead home share used up `/` for every
  path. Paths and mount points are now rewritten through
  `/usr/share/firmlinks` and the root's symbolic links before the longest
  mount point is chosen; on the Mac `/home/u` counts against
  `/System/Volumes/Data/home`. The mount-table refresh ran under the shared
  lock outside the deadline; it now runs in one background goroutine, a
  stale table is used meanwhile, and a caller with no table waits only
  within its deadline. Readers are swapped under the table's lock, which
  `-race` showed was needed.
- **`ID-F1` probe cap per mount; stacked file systems** (2026-10-07).
  Review of the Linux change: one dead, hard-mounted NFS share held all
  eight process-wide probe slots, after which `LocalPath` refused every
  path, local ones included, on macOS and Linux alike; a burst of more than
  eight calls on a healthy volume was also refused when the probes ran
  slowly. The cap is now kept per mount, chosen from the mount table by the
  path's spelling and read without asking any volume. A mount with a probe
  past its deadline refuses further paths at once, and a healthy mount's
  burst waits for a slot within the deadline. Coordinator decision: a
  stacked file system (overlayfs, fuse-overlayfs, squashfuse, loop images)
  is judged by its top layer and its lower layers are not probed, so
  container roots stay local. A FUSE path whose device-number `stat` blocks
  is refused within the deadline and releases its slot once the `stat`
  returns.
- **`ID-F1` on Linux** (2026-10-07): `LocalPath` refuses a path whose
  volume's `statfs` `f_type` is a network or shared file system (NFS,
  SMB/CIFS/SMB2, Ceph, AFS, 9P and the others the contract lists) or an
  unmounted autofs point, and a FUSE mount whose `/proc/self/mountinfo` type,
  matched by device number, is not known local; until then Linux admitted
  every path. The deadline, the eight-probe cap counted from start, the
  `TreatVolumeAsNetwork` test hook and the walk up to the deepest existing
  folder are shared with macOS in one file (`localpath_statfs.go`); each
  platform supplies only its answer for the volume. WSL's Windows drives
  under `/mnt` are 9P and are refused. No Linux-only consumer calls the path
  functions; the cross-platform consumers already fail closed, and
  `privatedir`'s fail-closed models-root test now runs on Linux.
- **`ID-F1` on macOS** (2026-10-06): `LocalPath` refuses a path whose volume
  `statfs` does not report `MNT_LOCAL`, and one whose volume does not answer
  within 500 ms. Review of the permission prompt's requester icon found a
  program under `/Volumes/<share>` reaching `NSWorkspace.icon` on the
  launcher's UI thread, where a dead mount hangs the prompt; until then every
  path off Windows was local. Coordinator decision: fix at this owner. Every
  `SameFile`, `Within`, `FileKey`, `PlaceKey` and `LocalPath` caller on macOS
  now refuses network volumes; a subject program on one compares by
  `SamePathName`. Linux is unchanged. Review of that change: every consumer
  must fail closed. `Inside` no longer places a refused path by spelling
  (spelling is kept only for a folder not created yet); `CheckModelsRoot`
  refuses a refused root and reads a home-comparison error as "may hold";
  the statfs cap counts each probe from its start, so a burst against a dead
  mount leaves at most eight outstanding; and the Panel's ComfyUI retire
  guard (`ProgramWithin`) keeps a version it cannot compare.
- **`ID-D3`** (2026-10-02): `privatedir.ProtectModelFolder` and
  `CheckModelFolder`. OA's own model folders under `OA-models` failed ID-D2:
  files moved in from `%TEMP%` kept a sandbox group's modify and delete
  entries, and every video launch hashed them in full. Coordinator decision
  of 2026-10-02: OA owns its model folders with a protected DACL of this
  account, SYSTEM and Administrators. Review of 6607b567d (2026-10-02): the
  first form wrote by path with `SetNamedSecurityInfo`, whose propagation
  reached a file outside the folder through a hard link, and could follow a
  folder swapped mid-run. Every entry is now opened as itself and held with
  data access (Windows records no share mode for a handle without it),
  hard-linked files are accepted only when every name lies under OA's own
  roots, each descriptor is written through its handle with
  `SetKernelObjectSecurity`, and `CheckModelsRoot` refuses a drive root,
  the home, known folders, a linked path and one that resolves elsewhere.
- **`ID-S1`** (2026-10-01): `Self` exports the calling process's own
  principal, read the way a peer's process token is read (`processUser`).
  The job service's `LinkResult` (job JOB-A17) compares a caller with it;
  before this the job module kept its own copy of the integrity-label SID
  parser from `internal/integrity`. Review of 2026-10-01: an unreadable
  label was RID 0 and an empty name, which compared as the lowest level; it
  is now `Integrity` "unknown" on a peer and an error from `Self`, and RID 0
  that was read names the untrusted level. `User.Restricted` reports a
  restricted token, and an unreadable flag reads restricted.
- **`ID-T8`** (2026-10-01): `BindUnixServer` binds the listening process
  of a dialed AF_UNIX connection, through `SIO_AF_UNIX_GETPEERPID` on
  Windows (an in-house `WSAIoctl` call; `afunix.sys` fills the process id
  and reports zero bytes returned, measured on Windows 11 26200) and the
  existing peer-credential bind on Linux and macOS. Engines OA launches
  move from loopback ports to socket paths (VISION 2026-10-01, "Engines
  adopt model bytes…"; `research/model-bytes/ENGINE-TRANSPORT.md` T2), and
  the provider kit's engine client checks the socket's server with it
  before the first byte (abstraction-inference INF-EL2). The Windows
  loopback bind and this one share `pinnedProcessPeer`, which reads user,
  path, package and code through the pinned handle. Review of 2026-10-01:
  a recheck passes unanswered only for a closed or disconnected socket
  (the ioctl keeps naming the server after the server exits, measured),
  and any other failure refuses; the start-time guard and the
  process-changed recheck have tests. 2026-10-08, 0.4.0 Mac probe: the
  macOS half never bound. `requireAcceptedUnixSocket` refuses the client
  end there with `ErrNotServerEnd`, and the socket's process would read
  only at `pid` (`ID-M1`) had it passed. macOS now answers `ErrNoBinding`
  with that reason, as `BindLoopbackServer` does; `ID-T8` says so.
- **`AllSockets`** (2026-10-01, `ID-T7`): every TCP socket in any state
  and every bound UDP socket with its owner (`TCP_TABLE_OWNER_PID_ALL`).
  The coordinator decided that an engine OA launches on a socket path may
  hold no network socket at all, outbound connections included
  (abstraction-inference INF-EL2); `Sockets` lists listeners only.
- **`ID-T7`** (2026-10-01): `Sockets`, `OwnedByTree`, `CheckLoopbackOnly`
  and `CheckTreeLoopback` export the Windows socket owner tables and the
  loopback-only rule for a contained process tree. The Lemonade provider
  wrote them first under its own server package for the Lemonade 2026.39.1
  security review's condition 6; the LocalAI attach check needs the same
  proof, and the owner-table code already lived here beside `BindLoopback`.
- **`ID-W4`** (2026-10-01): `VerifyFile` exports the Windows Authenticode
  check for a file path. The Panel's native permission prompt (TODO HP8)
  shows the requesting program's publisher with it; before this the
  monitor kept its own copy of the WinVerifyTrust and signer-name calls.
  Evidence: `feedback/hp8-native-authorization.md`.
- **`Code.Description`, `Code.OriginalName`** (2026-10-01): a trusted
  Windows image reports the `FileDescription` and `OriginalFilename` of its
  own version resource, read through the verified handle (`ID-W4`, the
  Windows section). Prompts name a signed program by them (`VISION.md`
  2026-10-01, "A prompt names a signed program by its signed version
  resource"). `Code` is not on the wire; no service version changes.
  Review of 2026-10-01: `VerifyFile` holds its file without
  `FILE_SHARE_WRITE` for the verification, so a file another handle holds
  open for writing is refused at the open with a sharing violation, and a
  failed resource read abandons a trusted verification. No caller in this
  repository passes `VerifyFile` a file open for writing.

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

**2026-10-01: `privatedir` from abstraction-inference.** The private-folder
helper was `abstraction-inference/go/providerhost/privatedir`. The storage
reader's digest record (storage-over-local-stores LS-12) needed it, and the
review's first choice of home, `abstraction-facade/go`, already requires
inference, so inference importing it from there would have made the two
modules require each other. Identity is the module every caller already
requires, requires no OA module, and owns accounts and SIDs; the package
moved here as `go/privatedir` with no change of behaviour, under ID-D1.

| id | before | now |
| --- | --- | --- |
| ID-D1 | inference's private-folder rule, stated in INF-EL2 and INF-MS7 | identity's own rule; INF-EL2, INF-MS7, Lemonade's folders and LS-12 cite it |

**2026-10-01: `trustedpath` from the storage reader.** The owner and access
check for the pinned ASUS files was the storage adapter's own
(`adapters/asusai/trust_windows.go`, LS-12). The video provider binds model
files in place and needs the same check, so it moved here as
`go/trustedpath` with one owner, and now also walks every folder up to the
volume root and refuses reparse points on the path.

| id | before | now |
| --- | --- | --- |
| ID-D2 | storage LS-12's own check of the file and its folder | identity's rule over the file and every folder to the volume root, reparse points refused; LS-12 and the video provider call `trustedpath.CheckFile` |

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
