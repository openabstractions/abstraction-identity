# Shared Node client transport

This development package delegates local IPC, receiving identity requirements,
bootstrap, cancellation and connection deadlines to the installed C ABI library.
It supports generated asynchronous clients accepting `writeFrame(Uint8Array)`
and `exchangeFrame(Uint8Array)`. Waiting cancellation preserves uncertain service
acceptance; callers reconcile using their original operation identity.

Build with CMake against an installed `abstraction_ipc` static prefix. Set
`NODE_INCLUDE_DIR` to official Node-API headers and, on Windows,
`NODE_IMPORT_LIBRARY` to the matching architecture's official `node.lib`.
Install this CMake package into its own package directory. The loader uses its
fixed `native/oa_ipc_node.node` file. `ABSTRACTION_IPC_NODE` may select an explicit
absolute addon file. It performs no working-directory DLL search. No npm runtime
dependencies or installation hooks are needed.

`new FrameTransport(endpoint, {timeout:5000, deadline:null, cancellation:null})`
uses milliseconds and a monotonic `performance.now()` deadline. Defaults receive
a fresh budget for each call. An explicit deadline stays absolute. Cancellation
accepts an AbortSignal. `callScope()` returns an independent view with one budget
for a composite operation. `withWaiting()` explicitly replaces waiting policy
while preserving endpoint and limits. Both methods preserve the original binding.

Native asynchronous work copies outbound bytes, owns its connection and shares
the cancellation lifetime through completion. Frames are limited to 2 MiB and
at most 32 addon calls may be queued/in flight. Native handles are never exposed.
Errors retain C ABI status and confirmed transfer count; an aborted write may
have delivered more bytes than the confirmed prefix. One-way EOF acknowledges
transport completion and supplies no durability receipt.

Node-API workers keep the event loop available for AbortSignal callbacks. They
use the bounded libuv worker pool; queued time consumes the same call deadline.
The source fixture verifies Windows/MSVC. Other native platforms need execution
evidence before claiming support. Package version 0.0.0 is development metadata.
