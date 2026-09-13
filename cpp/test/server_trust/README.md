# Installed C verified-open consumer

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
