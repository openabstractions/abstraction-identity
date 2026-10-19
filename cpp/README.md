# Shared IPC client byte transport

The same Identity C++ SDK also exports local file identity through
`find_package(abstraction_fileid CONFIG REQUIRED)` and `abstraction::fileid`.
Include `<abstraction/fileid.h>` for current-process physical folder/leaf
resolution, locality refusal and native-identity containment. Its static archive
links the system C++/thread and loader runtimes and imports no IPC target. Missing remainder
names can be resolved without creating them; `folder(path, true)` explicitly
creates folders. The header documents that these results supply names rather
than retained file capabilities or caller authority. CAS uses this target for
its layout while keeping locking and replacement in CAS.

On POSIX, FileID bounds native volume queries to 500 ms and eight outstanding
probes per device. A timed-out native query retains its own close-on-exec
descriptor until its inspection finishes. Worker TLS lifetime registration
protects code in an embedding
shared module; healthy queries finish their workers before returning. On
Darwin, the OS loader retains an image containing these TLS descriptors until
process exit. `dlclose` success therefore does not promise memory reclamation
or unload/reload reset there. Linux/glibc retains a module while worker TLS
destruction remains pending; a later loader collection can reclaim it. This
adds no adopter lifecycle call. Existing IPC transport targets are independent.

*For transport and client-library authors writing C++.*

This page is for whoever builds or embeds an OA client transport in C++, or a
generated C++ service client on top of it. An application calling a capability
resolves a typed client through the facade instead.

Install the runtime first: https://openabstractions.org/adopt.html

Connect generated C++ service clients to a local OA endpoint with bounded reads,
writes, deadlines and cancellation. `abstraction_ipc` / `abstraction::ipc` uses
Windows named pipes or POSIX Unix sockets and exposes a stable C ABI plus a C++17
RAII wrapper.

On macOS, framed clients also accept an explicit `xpc:service-name` endpoint.
Supply an independently trusted runtime executable and POSIX user through
`ServerExpectation`. The shared native transport validates the bootstrap reply
before sending the capability payload, then uses its anonymous endpoint and
runtime generation. Each call currently creates a fresh authenticated session.
The configured executable must be protected by the installation's trust policy.
An executable supplied by the responding service cannot establish that trust.

This path requires macOS 12 or newer and a registered Mach service.
Current source uses the installed LaunchAgent's fixed XPC service name as
the default endpoint on macOS; the published 0.2.0 package predates it. The raw
`open/read/write` API rejects XPC endpoints; use `FrameTransport` or
`oa_ipc_session_call`. C++, Python, Rust and Node wrappers check
`oa_ipc_features()` before routing XPC frames. An older library without that
feature must be refused before sending data. Bun currently refuses XPC because
its binding cannot enforce server expectations. Generated capability payloads
retain their existing form.

This package supplies client byte transport. Server listening, framing, service
discovery, generated RPC interfaces, provider behavior and authorization remain
separate components.

The C ABI is in `<abstraction/ipc/client.h>`; its opaque connection is allocated and freed by the same library. Version is `1`. Status values are explicit integers. Buffers belong to callers. A failed open clears the output handle. Close accepts NULL; calls must not race with I/O or another close. Errors and C++ allocation failures return statuses, not exceptions. Invalid arguments perform no I/O.

Ordinary `FrameTransport` calls use the ABI-1 `oa_ipc_session_call` entry point
with `OA_IPC_CALL_SINGLE_EXCHANGE=2` (combine `OA_IPC_CALL_ONE_WAY=1` for EOF
completion). They require `OA_IPC_FEATURE_SINGLE_EXCHANGE=4` before I/O. The
native core opens a fresh connection and sends one plain frame under one total
deadline, without session negotiation, pooling or replay. Payloads are opaque
bytes, including an empty payload. `with_sessions()` keeps its existing opt-in
pooling semantics; XPC keeps its authenticated native message path. Raw `Stream`
remains available for byte-stream consumers.

The C ABI's `sent` value counts payload bytes. Zero cannot establish that an
empty request's header was never delivered, so an empty-request failure leaves
acceptance unknown and cannot trigger activation or resend. Native status is
the error authority. Caller-proof refusal returns `ProofUnavailable`; that
status also covers unavailable local proof facilities. The ABI exposes no
refused attribute/required-proof tokens, and C++ reports that shared status
without synthesizing those details. Existing published ABI-1 libraries reject
the new flag; updated ordinary bindings refuse their missing feature before I/O.

`OA_IPC_FEATURE_OPEN_FAILURE=8` permits opting into
`OA_IPC_CALL_REPORT_OPEN_FAILURE=4`. Only that opted-in call can return
`OA_IPC_OPEN_IO_ERROR=10` for a confirmed initial stream-open I/O failure before
any protocol write attempt. Negotiation, fallback, connection reuse and all
write/read failures retain their usual status, even with zero payload bytes
confirmed. XPC never returns this classification. Flags without this opt-in
retain statuses 0..9 and the same payload counts. C++ uses the affirmative
`Status::OpenIoError` for its private pre-send marker; Facade's selected default
runtime may activate once only on that marker. A library without feature 8 can
still exchange frames, but supplies no inferred activation permission.

The optional ABI-1 `oa_ipc_current_principal` query returns this process's
primary-token SID on Windows or effective uid on POSIX. It reuses the native
process identity owner and supplies no connection, peer trust or authority.
Query size with a null buffer and zero capacity, then copy into caller-owned
memory. The required size includes the trailing NUL. Failure clears the kind;
insufficient capacity preserves the buffer and reports the needed size.
Older libraries may lack the export; bindings report `PROOF_UNAVAILABLE` and
perform no language-specific OS or shell lookup. `CurrentPrincipal` is the
local native fixture for the query and its buffer rules.

Open establishes one monotonic deadline from `timeout_ms`; connection setup and all later reads/writes consume that same budget. This is a bounded connection/transaction lifetime, not a persistent connection with a new timeout per call. Zero timeout expires immediately. Read returns at least one byte or a status; EOF is disconnected. Write attempts all bytes and reports confirmed completed bytes. Cancellation can leave an additional indeterminate prefix at the peer: never resend an entire message after a failed write. No message boundaries or delivery acknowledgement are implied. Frames default to 1 MiB (`kDefaultMaxFrame`) and `max_frame` can raise that up to 2 MiB.

Windows requires a nonempty ASCII `\\.\pipe\name` endpoint. POSIX uses filesystem Unix-socket path bytes subject to the platform length limit. Embedded NUL is invalid argument; unsupported endpoint spelling and connection errors currently map to I/O error. No endpoint path is unlinked by the client. Windows retains SECURITY_IDENTIFICATION and drains cancelled overlapped operations; POSIX suppresses SIGPIPE without changing the process-wide signal disposition.

Windows bootstrap reads `ABSTRACTION_RUNTIME_ENDPOINT` from the process
environment with `GetEnvironmentVariableW` and copies strict UTF-8 bytes. A
portable DLL and its caller can have [independent CRT environment
state](https://learn.microsoft.com/en-us/cpp/c-runtime-library/potential-errors-passing-crt-objects-across-dll-boundaries);
the [Win32 process environment](https://learn.microsoft.com/en-us/windows/win32/api/processenv/nf-processenv-getenvironmentvariablew)
is the shared source. Endpoint naming and activation's override refusal use
that same read. Missing or empty values select the existing default; read or
encoding failures remain errors. Callers synchronize environment mutation.
This changes no pipe encoding limits, server trust or installed-runtime policy.

`<abstraction/ipc/client.hpp>` provides a small noncopyable RAII wrapper over the same C ABI, using an absolute steady-clock deadline converted to the ABI's millisecond budget. Its status remains terminal after a failed operation. Consumers of that header need C++17. C callers need only the C header.

## Build and consume

```
cmake -S . -B build -DBUILD_SHARED_LIBS=ON
cmake --build build --config Debug
ctest --test-dir build -C Debug --output-on-failure
cmake --install build --config Debug --prefix /absolute/staging/prefix
cmake -S test/consumer -B consumer-build -DCMAKE_PREFIX_PATH=/absolute/staging/prefix
cmake --build consumer-build --config Debug
ctest --test-dir consumer-build -C Debug --output-on-failure
```

For a Windows shared build, put the staging `bin` directory on the test process's PATH (or deploy the DLL beside the executable). Static builds are the default. `test/consumer` uses only `find_package(abstraction_ipc CONFIG REQUIRED)` and public include paths; its C main exercises the C ABI against a fixture listener. All listener code is test-only and tests have a 10-second limit.

## Per-operation cancellation

`CancellationSource` owns a cancellation handle. `source.token()` returns a
copyable token and `source.cancel()` signals it idempotently from another thread.
Tokens keep the handle alive; a default token is uncancelable. Keep the source
available while an application needs to signal it. Concurrent assignment or
destruction of the same C++ object requires external synchronization.

```cpp
abstraction::ipc::CancellationSource stop;
auto operation = transport.with_cancellation(stop.token());
// Another thread may call stop.cancel() while this exchange waits.
auto reply = operation.exchange_frame(request);
```

`with_cancellation` returns an operation-scoped transport copy and preserves its
endpoint, frame limit and deadline. The original transport remains reusable.
Use a new source for a new cancellation lifetime. Waiting cancellation throws
`FrameError` with `Status::Cancelled`; it leaves provider acceptance or execution
unresolved and sends no cancel-work request. `Stream(endpoint, deadline, token)`
uses the same native cancellation mechanism for byte I/O.

The C API exposes create/signal/release and `oa_ipc_open_cancelable`. Connections
retain the native state after open, allowing the handle to be released while the
connection remains active. Releasing a raw handle must not race with signalling
or opening through that same raw pointer. Existing open and default C++ transport
calls retain their original behavior.

The `test/cancellation` installed consumer exercises cancellation and handle
lifetime with local fixture listeners. Its CTest timeout is 20 seconds.
