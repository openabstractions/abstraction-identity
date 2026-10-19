# Installed C verified-open consumer

*For maintainers running the C++ transport tests.*

This test compiles `main.c` against the installed `abstraction/ipc/client.h` and
links the installed shared IPC target. `fixture.cpp` supplies an isolated native
peer and independently obtains the test process's image/principal. The
application-facing test performs no platform calls.

```sh
cmake -S openabstractions-flat/abstraction-identity/cpp -B .build/ipc-trust \
  -DBUILD_SHARED_LIBS=ON -DCMAKE_INSTALL_PREFIX=/absolute/isolated/prefix
cmake --build .build/ipc-trust --config Release
cmake --install .build/ipc-trust --config Release
cmake -S openabstractions-flat/abstraction-identity/cpp/test/server_trust \
  -B .build/ipc-trust-consumer -DCMAKE_PREFIX_PATH=/absolute/isolated/prefix
cmake --build .build/ipc-trust-consumer --config Release
ctest --test-dir .build/ipc-trust-consumer -C Release --output-on-failure
```

On Windows, add the isolated prefix's `bin` directory to this process's PATH for
the shared DLL loader. Do not install or launch an OS service. The fixture uses
unique local endpoints and removes them; CTest bounds execution to 20 seconds.

The same test is registered as ServerTrust in the native library's normal test
block. Windows and Linux with SO_PEERPIDFD support prove exact bytes, wrong
principal/image refusal before payload, copied expectations, deadline and active
read cancellation, and unchanged handle counts after repeated cleanup. macOS
explicitly tests PROOF_UNAVAILABLE; its native execution remains unverified in
this work. Older Linux kernels refuse the requested proof and cannot run the
successful binding controls. Existing ABI-1 open calls remain unverified; users
of dynamic libraries must require the new verified-open symbol explicitly.

The server image check compares file identity (PT-5a): volume serial and file
ID on Windows, `st_dev` and `st_ino` on Linux. At open, the guard first checks the
server's account (token SID or peer uid). It then reads the identity of the
running server process's image (on Linux through `/proc/<pid>/exe`, which
follows the mapped file; on Windows from a handle opened on the reported image
name) and of the expected installed program, and requires them to be one file.
On Windows only local drive paths are opened: a reported UNC, WebDAV, device or
network-drive name is refused without an open. Another name for the running
image (a rename, hard link, 8.3 alias or junction spelling) passes.

The cases this check refuses, for a same-user process listening on the runtime
endpoint:

- The server runs a file other than the one now at the expected installed
  name, including when the running image was renamed away and another file
  was put at its old name. On this Windows build (26200)
  `QueryFullProcessImageNameW` follows a rename of the running image.
- On Linux, a server whose image was deleted and replaced; it no longer passes
  by its `(deleted)` name.
- On Windows, a server running a case-twin of the installed file in a
  case-sensitive folder.

A program written to the installed name and started from there is the
installed image, and the check accepts it. Writing to the install location is
outside this check; the guarantee depends on that folder being protected. A
runtime replaced on disk by an update while the old server still runs fails
the check until that server restarts, because the running image is no longer
the installed one. Process herpaderping (an image rewritten after mapping keeps its
file ID) stays outside this check. `ServerTrust` and the Python, Rust and Node
tests named `server_identity`/`server_image_is_matched_by_file_identity` prove
both directions through the C ABI.
