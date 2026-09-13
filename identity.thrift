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
}(unknown="refuse")
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
const list<string> native_operations = ["OfHandle", "OfConn", "CanEver", "Check", "Get", "AtLeast"]
const list<string> native_binding_types = ["Handle", "Peer", "Attr<T>", "User", "Process", "Code", "Options"]
// Native OS handles, ownership, connect-time clocks and generic Attr<T> cannot
// cross a message as authority. This generates common vocabulary only; the
// native binding supplies these types, proof comparison and extraction methods.
