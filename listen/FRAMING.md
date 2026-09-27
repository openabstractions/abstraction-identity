# Explicit bounded frames

This is a separate byte-stream protocol from legacy newline-delimited endpoints. Providers opt into a distinct framed endpoint. Neither side guesses a format, retries a legacy endpoint, or silently falls back. The payload is opaque; schemas/generated bindings define its meaning.

Each frame is exactly a four-byte unsigned big-endian payload length followed by that many bytes. Length excludes the header. Zero length is valid. Multiline text, NUL and all other byte values are preserved. The wire payload ceiling is `0x3FFFFFFF` bytes; configured maxima above it use that ceiling. Limits apply independently to request and response. The default maximum is 1,048,576 bytes; zero-valued maximum options select that default. Outgoing oversize is refused before connecting or sending; incoming oversize is refused after its fixed header and before payload allocation. EOF inside either header or body is an error. No partial frame reaches a handler.

A single-exchange connection carries one request and at most one response. A client that does not ask for a session opens a fresh connection per call: response correlation is by that connection, not a request identifier. There is no multiplexing, automatic retry, or resending after partial failure. A session (below) carries several such exchanges in sequence on one connection.

## Sessions

Measured 2026-09-17 (`research/inference/MEASURED.txt`): opening and binding a connection is most of a call's cost, about 400 µs on Windows pipes against 34 µs for an exchange on a bound connection. A session keeps the connection for later calls.

Header bits: in a session every header's bit 31 is set. Bit 30 on a request marks a one-way frame. Bits 0–29 are the length. The value `0xFFFFFFFF` is the closing marker. Lengths are unchanged: every limit is below 2^30.

1. **Opening.** On a new connection the client sends only a request header with bit 31 set, then reads a four-byte answer before sending the body. `0x80000000` accepts a session. `0x00000000` declines it for now, and `0x40000000` says this endpoint serves one exchange per connection; after either the client sends the body and the exchange completes exactly as a single exchange, with a plain response header and EOF. A server built before sessions refuses the header as oversized and closes the connection before any body is sent, so nothing was dispatched: the client repeats the call as a single exchange on a new connection, and treats the endpoint as single-exchange for 30 seconds. A server that neither answers nor closes makes the first call wait for its deadline, so a client asks for sessions only where the server is known to answer: Go `FrameClient.Sessions`, which the runtime resolver client sets.
2. **Requests.** After acceptance the client sends the body. Later requests on the session are one header (bit 31 set) and body. Requests are sequential; bytes sent before the previous response are a protocol violation and end the session.
3. **Identity.** The server binds the connection once. For every request it rechecks that binding and checks the service's need against it, as `ReceiveFramed` does for a single exchange, before the body is read. An unmet caller-proof requirement produces the terminal refusal below and ends the connection. A request whose body finishes after the binding's maximum age is refused before dispatch. A client verifying its server rechecks the server's evidence before and after each read of every call, as today.
4. **Responses.** A response header's bit 31 says the session continues; clear, the server closes after the response. A one-way request completes with the header `0x80000000` (or `0x00000000`, closing) and no payload; a payload is an error. An exchange the server does not answer ends the connection, so its client sees EOF as it would on a single exchange.
5. **Retirement.** A server retires an idle session after `SessionOptions.Idle` (30 s), when its binding reaches `SessionOptions.MaxAge` (five minutes by default and at most five minutes), when captured evidence expires sooner, or to admit a new one beyond `MaxSessions` (64). A reused Windows Authenticode verdict retains its original five-minute deadline. The server sends the closing marker when it has read no byte of a next request. After the marker it dispatches nothing more from that connection. A request that has begun when retirement wins ends with the connection; it receives no marker that could authorize replay. A call accepted before binding expiry may finish its response, then the session retires. A client that reads the marker in place of an answer knows its request was not dispatched and repeats it on a new connection. A client discards a pooled connection that has bytes waiting or has ended, and keeps a connection idle at most 10 s, fewer than four per endpoint and server expectation.
6. **Waiting.** Each call keeps its own deadline and cancellation. A call cancelled or expired mid-exchange closes its connection; it is never returned to the pool. A failure after the complete request was written is reported, never retried: acceptance may be unknown, as on a single exchange. An incomplete request write can be retried on a new connection.

Go `Sessions(listener, SessionOptions)` wraps a listener: each exchange arrives from `Accept` as its own `Conn`, and `ReceiveFramed`, `Reply` and `Close` serve it unchanged. A connection whose first byte does not have bit 7 set is delivered unchanged, with that byte replayed. `ReceiveFramed` on a listener without sessions answers a session request with `0x40000000` and serves it once.

### Caller-proof refusal

After reading the request header, `ReceiveFramed` checks the receiver's caller-proof requirement before reading or interpreting the application body. An unmet requirement emits the response control word `0xFFFFFFFE`, followed by exactly two bytes, then closes the connection. The first byte is an attribute token: `0` unavailable, `1` user, `2` process, `3` path, `4` package, `5` code. The second is the required proof rung from identity's fixed ladder: `0` unavailable, `1` claimed, `2` invalid, `3` unsigned, `4` unmet, `5` pid, `6` bound, `7` kernel, `8` signed. The pair is either `0,0` or two recognized nonzero tokens. Observed proof, platform explanation and caller values never cross this boundary. The same control applies to single exchanges, session opening, later session calls and one-way calls. It is distinct from session retirement's `0xFFFFFFFF`: clients close after refusal and never replay that request.

Clients require all six bytes and validate both tokens before reporting caller-proof refusal. A truncated or malformed control is a transport/protocol failure; EOF alone remains unresolved transport loss. Go returns `ProofRefusal`, matching `ErrCallerProofUnmet` and `identity.ErrNotProven`. This describes a receiver's refusal, not independently verified caller evidence at the client. The native C transport maps it to `OA_IPC_PROOF_UNAVAILABLE`. An older stream client rejects the high header as oversized or treats one-way response bytes as unexpected; an older server still closes without a marker. XPC sends `status=refused, reason=unmet_proof` with the same fixed tokens for that request, including one-way calls. Older XPC clients treat the refusal as untrusted. Other identity errors and application failures retain their existing outcomes.

`WriteFrame` sends one frame and waits for the peer to close without sending response bytes, except the fixed caller-proof refusal above. Other response bytes are an error. Providers close the authenticated call after dispatch. Waiting for EOF prevents an immediate Windows close from discarding queued request bytes. Successful one-way completion means submission only: EOF can still follow an older server's identity refusal or application failure. It does not acknowledge acceptance, execution, durable storage, or remote success.

`ExchangeFrame` sends a request and reads exactly one response frame, then closes its connection. `FramedCall.Reply` sends exactly one response and waits for the client to close, draining Windows writes without an extra acknowledgement byte. The provider must then close the call. A repeated Reply call returns the first result and never emits a second response. Additional request/response frames are unsupported. Trailing bytes received while waiting for EOF are an error; clients do not promise to inspect bytes beyond the first complete exchange response.

## APIs and lifetime

### macOS message endpoints

An explicit `xpc:service-name` endpoint carries complete frame payloads in XPC
messages. Go listening requires cgo and a launchd Mach-service registration.
Client authentication uses public APIs available from macOS 12. Unsupported
builds refuse the endpoint. Current source can select an installed macOS runtime
from the current account's installation database and compose its registered XPC
service endpoints. The published 0.2.0 package contains earlier transport code.

The client supplies independent expected runtime executable and user evidence.
A bootstrap containing a protocol version and random challenge establishes a
verified reply, anonymous endpoint and generation before any capability payload
is sent. The configured executable supplies the code requirement and must come
from a trusted installation. Every operation carries its generation and receives
fresh sender validation. Ad-hoc code validity supplies no trusted-publisher claim.
For interpreted clients the process evidence identifies the interpreter. A
Python script does not acquire its own application identity from this transport.

`ReceiveFramed` checks a request-scoped binding before exposing the payload to a
handler. Disconnection invalidates that request. Capability authorization remains
the handler's responsibility. A cancelled call can have unknown acceptance and
must not be retried automatically. One-way completion acknowledges transport
handling; it makes no durability or execution promise.

Go `FrameClient` and native framed wrappers select this path by endpoint spelling.
The native C entry point is `oa_ipc_session_call`. Each call currently creates a
fresh authenticated session. Stream reads/writes, legacy line receivers and Go
process-instance server pins are unsupported on this path. Existing stream
framing and pooling retain the behavior described above.

Native wrappers require the XPC bit from `oa_ipc_features()` before routing this
endpoint. An absent feature query in an older ABI-1 library means unsupported;
the wrapper must not send a payload through that library's socket implementation.
Bun currently refuses XPC because its binding cannot enforce server expectations.

The bootstrap connection owns the anonymous session lifetime. A same-PID
`exec` replacement that recovers the endpoint and generation through an
external test broker receives `Connection invalid` before a frame reaches
`ReceiveFramed`; see `research/macos-xpc-exec-proof.md`. Separate executable
endpoint transfer is also refused. These checks were executed on macOS 26.6.2;
older supported releases have compile and availability coverage rather than
equivalent runtime evidence.

### Shared API

`ListenFramed(endpoint, need)` checks the selected transport's identity ceiling
before opening the listener. `CanEver(endpoint, need)` performs that check alone.
Both use the common `identity.Limits.CanEver` comparison. Unsupported transports
and unavailable evidence are explicit errors. Each received request still uses
`Binding.Check`; a startup check cannot establish an individual caller's identity.
Legacy `identity.CanEver(need)` continues to describe the default stream transport.

C++ `<abstraction/ipc/frame.hpp>` supplies `FrameTransport(endpoint, timeout_ms=5000, max_frame=1048576)`. `write_frame(std::string_view)` and `exchange_frame(std::string_view)` use the existing shared C ABI underneath; the former fits generated templated client transports. Errors throw `FrameError` with its transport `Status`; size failures use invalid_argument. A zero C++ timeout expires immediately. No C++ listener implementation is added.

Go `FrameClient{Endpoint, Timeout, MaxFrame}` has `WriteFrame`, `ExchangeFrame`, and context variants `WriteFrameContext`/`ExchangeFrameContext`. A zero Go Timeout selects five seconds; a negative duration expires immediately. Context and configured timeout share the earliest deadline. That one budget spans dialing, sending, response reading and EOF completion; it never restarts per read. Cancellation closes connections and unblocks platform I/O. The Windows framed dialer retries a busy pipe under that context; existing Dial retains its legacy behavior. Native endpoint spelling remains subject to the byte runtime's platform rules (C++ Windows ASCII local pipes; Go local Windows pipes).

`ReceiveFramed(ctx, conn, need, maxFrame)` takes ownership of an accepted identity connection. It returns either an authenticated `FramedCall` or nil plus an error, closing the connection on failure. It uses the context's deadline, or five seconds when absent. After reading only the fixed header (needed by Windows identity binding), it calls existing Bind and Check against the supplied need before allocating/reading the payload. It makes no stronger identity claim than those checks. Malformed, truncated, expired and identity-refused requests never expose a frame.

The call exposes immutable Frame and Caller, plus Recheck, Reply and Close. Close is idempotent and releases both binding and connection. A context cancellation closes the call; binding checks and resource release are serialized. A service that delays action should Recheck and honor its own context. Cancellation cannot preempt arbitrary application handler work. Callers must not mutate Frame/Caller or perform multiple concurrent Reply operations with different intended responses. The framing layer does not authorize capabilities or declare provider persistence.
