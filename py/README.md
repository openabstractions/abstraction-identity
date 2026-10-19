# Python shared IPC client

*For transport and client-library authors writing Python.*

This page is for whoever builds or embeds an OA client transport in Python, or
a generated Python service client on top of it. An application calling a
capability resolves a typed client through the facade instead.

Install the runtime first: https://openabstractions.org/adopt.html

`abstraction.ipc` binds the existing C++ C ABI through Python's standard-library
`ctypes`. Build identity/cpp with `BUILD_SHARED_LIBS=ON` and install it into a
private prefix. Supply its absolute path through `Library(path)` or
`ABSTRACTION_IPC_LIBRARY`. Alternatively use `Library(prefix=absolute_prefix)` or
`ABSTRACTION_IPC_PREFIX`: Windows loads `bin/abstraction_ipc.dll`, Linux loads
`lib/libabstraction_ipc.so`, and macOS loads `lib/libabstraction_ipc.dylib` beneath
that prefix. A nonstandard installation layout uses the explicit library path.
Library loading performs no PATH or current-directory lookup. Explicit arguments
take precedence; a platform wheel's own bundled library comes next, ahead of
either environment variable; the environment library path then takes
precedence over its prefix. On Windows, with none of these set, the installed
runtime's recorded library comes last: the `ipc_library` value of
`Software\OpenAbstractions\Abstraction` under HKLM, then HKCU. A value that is
not an absolute path to an existing file is skipped. Installing the runtime is
enough. This fallback works with the Service feature alone and requires no Panel
record. An adopter may combine this reader with its own runtime-folder and link
checks and a fallback beside the recorded Panel.

A platform-tagged wheel built by `scripts/py_wheels.py`
(`win_amd64`, `win_arm64`, `manylinux_2_28_x86_64`, `manylinux_2_28_aarch64`,
`macosx_11_0_arm64`, `macosx_11_0_x86_64`) carries the matching native library
as package data under `abstraction/ipc/_native/`. `Library()` with no `path`
and no `prefix` resolves that bundled library through `importlib.resources`
before consulting either environment variable, so `pip install abstraction-ipc`
needs no configuration when the resolved wheel matches the running platform. A
source checkout or an `sdist`-built install carries no `_native/` data and
falls back to the explicit configuration above unchanged.

```python
from abstraction.ipc import Library, FrameTransport

library = Library(absolute_installed_library_path)
with library.cancellation() as cancellation:
    transport = FrameTransport(library, explicit_endpoint, timeout=2,
                               cancellation=cancellation)
    # Pass transport to a generated service client.
```

Each exchange opens and closes one native connection. A monotonic absolute
`deadline` can span several exchanges; the default gives each call a fresh
timeout. `Cancellation.signal()` may run in another thread. Close the signal
explicitly or use its context manager. Close waits for an active native call to
return. Native connections retain their signal independently. Concurrent
exchanges use separate connections.

Frame sizes are bounded before allocation: 1 MiB by default, configurable up to
2 MiB. `FrameError.status` preserves the native status and `transferred` preserves
the native confirmed request-payload count. Framing bytes are excluded; zero
does not establish that an empty request's header was never delivered. Ordinary
calls require the native single-exchange feature and refuse an older library
before I/O. A failed write is never
replayed automatically. Cancellation ends waiting; accepted work remains subject
to the service's recovery and cancellation contract.

With the optional native open-failure feature, stream calls request typed
`OPEN_IO_ERROR` (10) only for an initial open I/O failure before any protocol
write attempt. Other I/O failures keep `IO_ERROR`, including zero confirmed
payload bytes. Older libraries can connect without this feature and supply no
open-phase proof. This additive ABI-1 status belongs to matching unreleased
native SDK artifacts; generated service/wire statuses remain unchanged.

`Library.runtime_endpoint()` calls the shared native bootstrap helper. Windows
and Linux honor the explicit `ABSTRACTION_RUNTIME_ENDPOINT` override; macOS uses
the installed LaunchAgent's fixed XPC service name. Other defaults use the same
process-token SID / Unix socket convention as C++. A bounded query/copy retry
handles size changes between calls. Native failures propagate as FrameError;
configuration must not be mutated concurrently with native environment reads.

`Library.current_principal()` uses the optional shared ABI-1 process-principal
query. `ServerExpectation.current_account(program, library=...)` pairs that
principal with an absolute program path. Neither operation contacts a runtime
or grants authority. An older library without the export raises
`FrameError(PROOF_UNAVAILABLE)`; no Python OS query or subprocess substitutes.
The helper's default is `Library(allow_installed=False)`: it accepts this
client's bundled library or explicit path/prefix environment configuration,
and never reads installed-library registration. A caller may supply an already
loaded `Library`. Ordinary `Library()` retains its documented discovery order.

`Library.select_runtime(timeout=..., deadline=..., cancellation=...)` returns an
owned `ServerExpectation` from native installation metadata. Pass it as `server=`
to `FrameTransport` to verify the peer before sending application bytes. Windows
selects the registered MSI; Linux selects the loaded user runtime unit; macOS
validates the per-user LaunchAgent and its fixed executable/service map. Missing
or ambiguous installation returns `UNTRUSTED`; unavailable platform facilities
or an older native library return `PROOF_UNAVAILABLE`. Waiting-policy copies
preserve the expectation. Program paths identify the process image; they carry
no publisher assertion. The macOS XPC transport dynamically verifies the selected
program and uid before it sends application frames.

The package's 0.0.0 metadata is a development installation aid. Native artifact
distribution and released package version coordination remain pending. The
isolated conformance fixture builds the library, installs packages into a clean
prefix and runs a separate consumer; no Python provider or daemon is included.
