# Shared Rust framed transport contract

`abstraction-frame` is a pure Rust crate with one FrameTransport trait. It has no native linking, platform I/O, identity-provider dependency, codec or service implementation. Generated Rust services use `--shared-rust-transport` to re-export this same trait. The default generator output remains standalone; --no-ipc and record-only selections do not import the crate.

Implementors supply bounded complete-frame write/exchange operations and an associated error. They retain the caller's deadline/cancellation and required identity behavior. Transport errors leave service acceptance uncertain; the transport never retries or selects another provider. The identity/rust C ABI wrapper implements the trait once. Alternate backends can implement it directly without changing generated capability code. This trait does not itself prove an alternate backend's identity, cancellation or durability guarantees.

Source dependency paths stay the same in sibling public repositories and the private flat workspace. Version 0.0.0 denotes current development source, not a registry release. Pure trait consumers need only this crate; native IPC is selected by the connector package.
