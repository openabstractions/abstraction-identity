namespace * abstraction.identity.api

// Shared identity concepts; native binding supplements are explicit below.
encoding json {
 escape="minimal"
 indent="2"
 map_keys="utf8-bytes"
 numbers="integer-decimal"
 opaque="verbatim"
 terminator="newline"
 duplicate_keys="refuse"
 depth_limit="64"
}
refusal {
 1: malformed(stage="grammar")
 2: bad_string(stage="grammar")
 3: number_spelling(stage="grammar")
 4: wrong_type(stage="grammar")
 5: depth_exceeded(stage="grammar")
 6: duplicate_key(stage="grammar")
 7: duplicate_field(stage="structure")
 8: unknown_field(stage="structure")
 9: missing_field(stage="structure")
 10: bad_enum(stage="structure")
 11: trailing_bytes(stage="document")
}
// Order matches native Proof; names are shared, native comparisons retain ranks.
enum Proof {
 1: none
 2: claimed
 3: invalid
 4: unsigned
 5: unmet
 6: pid
 7: bound
 8: kernel
 9: signed
}(unknown="refuse",reader="act")
struct ProofRequirement {
 1: required Proof user
 2: required Proof process
 3: required Proof path
 4: required Proof package
 5: required Proof code
}(document="true",unknown_fields="refuse",doc="Minimum proof for each native Peer attribute. Policy comparison uses the declared native order. A serialized requirement or proof name never supplies caller identity; native bindings derive values from the accepted connection.")
struct ProofFailure {
 1: required string attribute
 2: required Proof have
 3: required Proof need
 4: required string why
}(unknown_fields="refuse",doc="Diagnostic refusal metadata. Underlying native attribute and connection evidence remain inseparable; this record cannot create authenticated evidence.")
// Core native API inventory, not wire-callable operations. BindXPCRequest and
// XPCRequest are available only on darwin with cgo; CeilingFor reports whether
// a selected transport is supported. Other native helpers live in Go's API.
const list<string> native_operations = ["OfHandle", "OfConn", "Bind", "BindConn", "BindXPCRequest", "Ceiling", "CeilingFor", "CanEver", "Check", "Get", "AtLeast", "Binding.Peer", "Binding.Check", "Binding.Alive", "Binding.Captured", "Binding.BoundAt", "Binding.EvidenceValidUntil", "Binding.Shared", "Binding.Close"]
const list<string> native_binding_types = ["Handle", "Peer", "Attr<T>", "User", "Process", "Code", "Options", "Binding", "Need", "Limits", "Transport", "XPCRequest"]
// Native OS handles, ownership, connect-time clocks and generic Attr<T> cannot
// cross a message as authority. This generates common vocabulary only; the
// native binding supplies these types, proof comparison and extraction methods.
// The shared transport's constants (openabstractions-flat/abstraction-ipc/CONTRACT.md):
// the C ABI status codes, whose transport class IPC-E1 names, in the values
// abstraction/ipc/client.h declares; the frame bounds of IPC-F1; and the
// default call budget of IPC-D1. The Go transport (listen) reads them from
// this definition's Go api package; the Python, C++, Rust and JavaScript IPC
// bindings read them from abstraction.ipc.constants (scripts/generate.targets).
// The 2 MiB client maximum is the largest frame limit those clients accepted
// before these constants; IPC-F1 does not state it yet (TODO.md, W1-23a
// follow-ups).
const i32 ipc_ok = 0
const i32 ipc_timeout = 1
const i32 ipc_disconnected = 2
const i32 ipc_io_error = 3
const i32 ipc_invalid_argument = 4
const i32 ipc_no_memory = 5
const i32 ipc_internal_error = 6
const i32 ipc_cancelled = 7
const i32 ipc_untrusted = 8
const i32 ipc_proof_unavailable = 9
// IPC-F1: the default maximum frame and the payload ceiling a four-byte
// header can carry; between them, the largest maximum a client binding accepts.
const i32 ipc_default_max_frame = 1048576
const i32 ipc_client_max_frame = 2097152
const i32 ipc_wire_max_frame = 1073741823
// IPC-D1: the budget of a call that names none, in milliseconds.
const i32 ipc_default_call_budget_ms = 5000
