# Shared IPC client byte transport

`abstraction_ipc` / `abstraction::ipc` supplies client connection I/O over local Windows named pipes and POSIX Unix sockets. It is reused from the existing discovery client. This is not a C++ implementation of identity's complete proof or authorization API. It supplies neither servers nor framing, service discovery, generated RPC interfaces, nor provider behavior.

The C ABI is in `<abstraction/ipc/client.h>`; its opaque connection is allocated and freed by the same library. Version is `1`. Status values are explicit integers. Buffers belong to callers. A failed open clears the output handle. Close accepts NULL; calls must not race with I/O or another close. Errors and C++ allocation failures return statuses, not exceptions. Invalid arguments perform no I/O.

Open establishes one monotonic deadline from `timeout_ms`; connection setup and all later reads/writes consume that same budget. This is a bounded connection/transaction lifetime, not a persistent connection with a new timeout per call. Zero timeout expires immediately. Read returns at least one byte or a status; EOF is disconnected. Write attempts all bytes and reports confirmed completed bytes. Cancellation can leave an additional indeterminate prefix at the peer: never resend an entire message after a failed write. No message boundaries or delivery acknowledgement are implied.

Windows requires a nonempty ASCII `\\.\pipe\name` endpoint. POSIX uses filesystem Unix-socket path bytes subject to the platform length limit. Embedded NUL is invalid argument; unsupported endpoint spelling and connection errors currently map to I/O error. No endpoint path is unlinked by the client. Windows retains SECURITY_IDENTIFICATION and drains cancelled overlapped operations; POSIX suppresses SIGPIPE without changing the process-wide signal disposition.

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

For a Windows shared build, put the staging `bin` directory on the test process's PATH (or deploy the DLL beside the executable). Static builds are the default. `test/consumer` uses only `find_package(abstraction_ipc CONFIG REQUIRED)` and public include paths; its C main exercises the C ABI against a fixture listener. With an installed download package, `-DTEST_DOWNLOAD_PACKAGE=ON` also links its discovery target. All listener code is test-only and tests have a 10-second limit.
