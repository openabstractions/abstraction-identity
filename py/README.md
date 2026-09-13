# Python shared IPC client

`abstraction.ipc` binds the existing C++ C ABI through Python's standard-library
`ctypes`. Build identity/cpp with `BUILD_SHARED_LIBS=ON` and install it into a
private prefix. Supply its absolute path through `Library(path)` or
`ABSTRACTION_IPC_LIBRARY`. Alternatively use `Library(prefix=absolute_prefix)` or
`ABSTRACTION_IPC_PREFIX`: Windows loads `bin/abstraction_ipc.dll`, Linux loads
`lib/libabstraction_ipc.so`, and macOS loads `lib/libabstraction_ipc.dylib` beneath
that prefix. A nonstandard installation layout uses the explicit library path.
Library loading performs no PATH or current-directory lookup. Explicit arguments
take precedence; the environment library path takes precedence over its prefix.

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
explicitly or use its context manager. Close waits for an active open to return;
native connections retain their signal independently after open. Concurrent
exchanges use separate connections.

Frame sizes are bounded before allocation, with a maximum configurable limit of
2 MiB. `FrameError.status` preserves the native status and `transferred` preserves
the confirmed prefix where supplied. The count can include framing bytes and
does not prove the total received before cancellation. A failed write is never
replayed automatically. Cancellation ends waiting; accepted work remains subject
to the service's recovery and cancellation contract.

`Library.runtime_endpoint()` calls the shared native bootstrap helper. It honors
the explicit `ABSTRACTION_RUNTIME_ENDPOINT` override and otherwise uses the same
process-token SID / Unix socket convention as C++. A bounded query/copy retry
handles size changes between calls. Native failures propagate as FrameError;
configuration must not be mutated concurrently with native environment reads.

`Library.select_runtime(timeout=..., deadline=..., cancellation=...)` returns an
owned `ServerExpectation` from native installation metadata. Pass it as `server=`
to `FrameTransport` to verify the peer before sending application bytes. Windows
selects the registered MSI; Linux selects the loaded user runtime unit. Missing
or ambiguous installation returns `UNTRUSTED`; unavailable platform facilities
or an older native library return `PROOF_UNAVAILABLE`. Waiting-policy copies
preserve the expectation. Program paths identify the process image; they carry
no code-signing assertion. macOS verification remains unavailable.

The package's 0.0.0 metadata is a development installation aid. Native artifact
distribution and released package version coordination remain pending. The
isolated conformance fixture builds the library, installs packages into a clean
prefix and runs a separate consumer; no Python provider or daemon is included.
