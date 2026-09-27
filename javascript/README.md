# Shared Node client transport

This page is for whoever builds or embeds an OA client transport in Node or
Bun, or a generated JavaScript service client on top of it. An application
calling a capability resolves a typed client through the facade instead.

Install the runtime first: https://openabstractions.org/adopt.html

This development package delegates local IPC, receiving identity requirements,
bootstrap, cancellation and connection deadlines to the C ABI library it ships
with. It supports generated asynchronous clients accepting `writeFrame(Uint8Array)`
and `exchangeFrame(Uint8Array)`. Waiting cancellation preserves uncertain service
acceptance; callers reconcile using their original operation identity.

## Where the native client comes from

The client library is the application's own code: it decides which runtime the
application trusts, and that decision comes from the application rather than
from the installation being judged. This package therefore declares one
optional dependency per qualified platform,
`@openabstractions/ipc-<os>-<cpu>`, each carrying the shared C ABI library and
the Node addon built on that platform at the runtime's version.

`platform.js` holds the table. Packages exist for `win32-x64`, `linux-x64`,
`darwin-x64` and `darwin-arm64`. A platform absent from the table is refused by
name with `Status.ProofUnavailable`, before any native load, rather than
receiving an unqualified binary.

`addonPath()` resolves the Node addon: `ABSTRACTION_IPC_NODE` when it names an
absolute file, then this platform's package, then the `native/oa_ipc_node.node`
file a CMake source build installs beside these sources. `libraryPath()` in the
`/bun` subpath resolves the shared library: `ABSTRACTION_IPC_LIBRARY` when it
names an absolute file, then this platform's package. Both environment
variables are development overrides and both refuse a relative path. Neither
loader performs a working-directory search, and there are no installation
hooks.

No package is on npm yet. Publication needs the owner's npm organization and
consent; the release packaging job packs the tarballs and retains them.

Build the addon with CMake against an installed `abstraction_ipc` static prefix.
Set `NODE_INCLUDE_DIR` to official Node-API headers and, on Windows,
`NODE_IMPORT_LIBRARY` to the matching architecture's official `node.lib`.
Install this CMake package into its own package directory for a source build.
Its installed package metadata includes `native/oa_ipc_node.node` in the npm
file list. The source metadata keeps binaries in the optional platform packages.

`selectRuntime({timeout, deadline, cancellation})` (also `NativeConnector.selectRuntime`)
returns the installed runtime's identity from the shared C ABI selector, on a
libuv worker under the same waiting rules. It connects to nothing. No or an
ambiguous installation rejects with `Status.Untrusted`; a platform without the
facilities rejects with `Status.ProofUnavailable`. Pass the result as `server`.

`new FrameTransport(endpoint, {timeout:5000, deadline:null, cancellation:null})`
uses milliseconds and a monotonic `performance.now()` deadline. Defaults receive
a fresh budget for each call. An explicit deadline stays absolute. Cancellation
accepts an AbortSignal. `callScope()` returns an independent view with one budget
for a composite operation. `withWaiting()` explicitly replaces waiting policy
while preserving endpoint and limits. Both methods preserve the original binding.

Native asynchronous work copies outbound bytes, owns its connection and shares
the cancellation lifetime through completion. Frames default to 1 MiB and can
be configured up to 2 MiB, and at most 32 addon calls may be queued/in
flight. Native handles are never exposed.
Errors retain C ABI status and confirmed transfer count; an aborted write may
have delivered more bytes than the confirmed prefix. One-way EOF acknowledges
transport completion and supplies no durability receipt.

The experimental `@openabstractions/ipc/bun` subpath provides the same framed
transport for Bun, over the library `libraryPath()` resolves. A Worker owns each synchronous C ABI
session call while the caller's event loop signals its cancellation handle.
`selectRuntime()` and `runtimeEndpoint()` call the shared library's installed
selector and bootstrap query, the same ones the Node addon, C++ and Python use.
A configured server expectation is marshalled as `oa_ipc_server_expectation`
and enforced by `oa_ipc_session_call` before any application byte is sent. XPC
endpoints require an expectation and a library reporting XPC support; the
binding refuses them otherwise with `Status.ProofUnavailable`, and it never
drops a configured verification. Outside the Bun runtime every native use fails
with `Status.ProofUnavailable`. Calls are bounded to the same 32 active-operation
capacity as the Node binding. Bun 1.4.2 ran the selector, the endpoint query
and framed Describe calls through the shared library against an isolated
runtime on Windows and Linux, accepting the matching expectation and refusing
a wrong program with `Status.Untrusted` and zero bytes sent. On macOS the
local socket transport for a non-installed, ad-hoc-signed test binary proves
identity only at the process-ID level, below what the gated test requires; it
skips before any Bun process starts there, and macOS execution through this
binding remains unrecorded. The boundary tests here cover validation only; the
full record is one of this layer's design records, in
[../README.md](../README.md#design-records).

Node-API workers keep the event loop available for AbortSignal callbacks. They
use the bounded libuv worker pool; queued time consumes the same call deadline.
The source fixture verifies Windows/MSVC and Linux/GCC. Other native platforms
need execution evidence before claiming support. Package version 0.0.0 is development metadata.
