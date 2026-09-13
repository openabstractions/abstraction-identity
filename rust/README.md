# Rust binding to shared IPC

The raw transport example below is explicitly unverified compatibility. Supply
`ServerExpectation` from independent host configuration for authenticated local
use; an endpoint convention alone is not installation trust.


This crate depends on the pure `abstraction-frame` contract and wraps the existing native client C ABI. It supplies
native bootstrap, bounded framed bytes, deadlines and cancellation. Generated
Rust capability clients use this transport through the shared framing trait.
Transport evidence and each capability behavior have separate scopes. It contains no service, local provider or per-capability JSON.

## Build against an installed native prefix

Build identity/cpp with `BUILD_SHARED_LIBS=OFF` and install it under an absolute
prefix. Select the matching compiler/architecture; Windows currently requires
Rust's MSVC target and an MSVC-built library. Point Cargo at that installation:

```sh
export OA_IPC_PREFIX="/absolute/static-ipc-prefix"
cargo test --offline --manifest-path rust/Cargo.toml
```

Use your shell's environment syntax and an absolute drive path on Windows.
The build script requires `lib/abstraction_ipc.lib` on Windows or
`lib/libabstraction_ipc.a` on Unix. It links the C++ runtime and Windows security
library where applicable. A missing library or Windows prefix containing the
IPC DLL is refused. Static linkage supplies no runtime IPC DLL search.

An outside application's Cargo.toml can depend on this source crate through a
path dependency. Version 0.0.0 is development metadata, with no registry release
claim. Installation of a runtime is a separate deployment step.

```rust,no_run
use abstraction_ipc::{runtime_endpoint, FrameTransport, Cancellation};
use std::time::{Duration, Instant};

let cancellation = Cancellation::new()?;
let transport = FrameTransport::new(runtime_endpoint()?, Duration::from_secs(2))?
    .with_deadline(Instant::now() + Duration::from_secs(2))
    .with_cancellation(cancellation.clone());
// A generated client will pass encoded frames to transport.exchange_frame().
// Another thread can call cancellation.signal() to stop waiting.
# Ok::<(), abstraction_ipc::Error>(())
```

Each exchange owns one connection and closes it through Drop. A cancellation
handle is Arc-owned; clones can signal concurrently and final release follows
the last borrowed native call. The native connection retains its own signal after
open. Cancellation affects waiting and supplies no cancellation of accepted work.

The frame cap defaults to 1 MiB and can be configured up to 2 MiB. Inbound size is
checked before allocating its payload. Errors preserve native status and confirmed
prefix count; a failed write may have delivered additional unconfirmed bytes.
There is no automatic retry. Reply data remains bytes. Native bootstrap strings
use checked UTF-8 conversion and a bounded size-query/copy retry.

`with_deadline` carries an absolute monotonic deadline across calls; otherwise
each call receives a fresh timeout. Native millisecond granularity rounds a
positive submillisecond remainder up to one millisecond. An already expired
deadline refuses before opening a connection.

Current execution evidence covers Windows/MSVC only. The isolated Rust fixture
uses an installed static prefix and copied outside consumer, tests protocol
faults with a Go peer, and leaves the application directory empty. Generated typed job, logging and storage clients have separate focused fixtures.
This transport page does not qualify Linux/macOS execution.
