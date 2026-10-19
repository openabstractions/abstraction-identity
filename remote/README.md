# Authenticated remote frames

*For transport authors building remote hosts or clients.*

This page is for whoever builds a remote host or client transport for OA over
TLS. An application calling a capability resolves a local or remote binding
through the facade instead.

Install the runtime first: https://openabstractions.org/adopt.html

`remote.Client` and [`remote.Server`](https://openabstractions.github.io/reference.html#concept-identity.remote-server) carry the shared bounded frame protocol over
mutually authenticated TLS 1.3. Generated capability protocols retain their exact
payloads. The transport identifier is `oa-framed-mtls@1`; TLS negotiates the ALPN
name `oa-framed/1`.

The host supplies an address, expected server DNS name, explicit certificate
roots and client credential. Server construction supplies its certificate,
trusted client roots and a capability handler. Every call uses a fresh handshake.
An optional native Go `Server.ClientRoots` owner supplies a fresh immutable
client-root snapshot for each connection under the remaining handshake context.
The server clones that pool. A nil pool, error or expired context refuses the
connection. With this callback, the fixed `TLS.ClientCAs` pool supplies no
fallback; a non-nil empty initial pool is valid. A nil callback preserves the
fixed-root behavior. The callback must honor its context. It supplies roots
only; TLS verification, live admission and all transport limits remain owned by
the server. Adding roots preserves already accepted calls.
An endpoint returned by discovery requires a matching trusted registration before
connection. Changing a constructed client's endpoint refuses before dialing.

The server passes verified certificate evidence and a SHA-256 public-key identity
to its handler. Receiving policy maps that evidence to a stable caller namespace
and checks each capability/method. Certificate names and payload fields grant no
authority by themselves. Local PID/program proof and remote credential proof
have separate meanings. Credential provisioning, renewal and revocation policy
belong to the installing host and remain explicit dependencies.

The client reuses `listen.FrameClient`: one budget covers connection, handshake,
request and reply. Cancellation closes its owned TCP stream directly. Cleanup
cannot acquire an additional TLS close-notify timeout. Each call makes one
attempt. A dropped response preserves uncertainty; the capability's reconciliation
protocol decides how to recover.

The server defaults to 64 concurrent connections, 5 seconds per connection and
a 1 MiB frame, the same default as the local transport. It authenticates
before reading the request frame and checks its length before allocation.
Caller departure cancels a waiting handler. Accepted durable work keeps the
provider's independent lifetime. Handlers must honor their context; server
shutdown joins admitted handlers. Limits are host configuration and may be
narrowed for a capability. `MaxFrame` is an unbounded `uint32`, so a
capability can raise it past the local transport's 2 MiB client ceiling;
job acceptance declares 2 MiB. `MaxRequestFrame` supplies an independent inbound
bound. Its zero value keeps `MaxFrame` as the bound in both directions. A host
can keep requests at 1 MiB while permitting a larger contract-defined reply.

`HandshakeTimeout` separately bounds TLS to 5 seconds by default, capped by
the remaining total `Timeout`. A successful handshake restores the remaining
total deadline; it starts no fresh call budget. `MaxSourceConnections` defaults
to 4 pre-authentication connections per actual TCP source IP. Ports and
IPv4-mapped IPv6 spellings share that source. Unknown source address forms
are refused. Source slots are released after TLS or on every failure.

After live admission, `MaxPeerCalls` defaults to 8 concurrent connections per
verified public-key identity. `PeerRequestsPerSecond` and `PeerBurst` default
to 32 and 64 using a token bucket. A refused budget closes the connection
before an application frame is read. Certificate renewal with the same SPKI
shares the budget. New-key admission prunes entries idle for at least one minute
whose buckets have fully refilled, preserving rate debt across idle visits.
The key table has at most 1024 entries and refuses a new key when full. Active
entries are retained until their calls finish. Source accounting has at most one entry per
global connection slot. These are transport limits; capability rights remain
independently required. Negative limits fail `Validate`.

`Server.Validate` checks the existing TLS, handler, live-pin callback and limit
configuration before a host opens its listener. It performs no peer admission
or I/O. `Serve` repeats this validation for callers that supply a listener
directly; every handshake evaluates the current pin policy.

These additions preserve keyed Go struct literals and the framed protocol.
External unkeyed `Server` literals must name their fields when updating from
the published identity v0.5.1 source.

TLS keys and configuration callbacks remain immutable during use. Client roots
and server client roots are cloned. Dynamic server configuration replacement is
refused, preserving the required mutual authentication configuration.

This is an explicit Go transport/provider building block. Installed registration,
facade remote selection, credential distribution and C-ABI remote transport
remain integration work. Local-server verification remains independently required.

Run `go test -race ./remote` from this module. Tests use isolated credentials and
loopback listeners. [Go TLS configuration](https://pkg.go.dev/crypto/tls#Config)
defines the underlying certificate verification and handshake behavior.

## Single-attempt pairing candidates

This section normatively defines the /2 ceremony used by Facade's
[local machine pairing control](https://github.com/openabstractions/abstraction-facade/blob/main/CONTRACT.md#local-machine-pairing-control-planned-08).
Facade owns invitation encoding, proposal semantics, native consent and durable
activation/removal. The formulas below use byte concatenation, SHA256 and
HMAC-SHA256. Integers and framing lengths use big-endian encoding; strings are
the exact ASCII bytes shown, without a terminator. I is role1 and R is role2.

`PairInitiator` and `PairResponder` own a supplied stream for one bounded
`oa-pair/2` TLS1.3 ceremony. The unpublished /1 helper is replaced in place;
there is one supported ceremony major (`PairingVersion`) and no fallback.
Published identity v0.5.1 has no pairing helpers. Normal `Client`/`Server`,
`Peer`, live admission and `oa-framed/1` trust remain unchanged.
Each credential contains exactly one leaf certificate and its private key;
the caller keeps its bytes and key immutable for the call. Session tickets,
resumption, discovery and retry are disabled.

The runtime supplies a random nonzero32-byte secret. Required `Prepare` runs
after actual TLS keys are known and before commitments; its result is copied
and bounded to2048 opaque bytes per receiving direction. Identity interprets
no Rights semantics. `Validate` checks both ordered proposals after the bound
proof and before publication. Each Validate/Show/Confirm view and returned
candidate has independent proposal copies; callback mutation cannot alter the
frozen agreement or later views. The caller must keep Prepare's returned
buffer stable until its result has been copied.

`Show` returns after publishing the six-digit view; `Confirm` runs after both
publication acknowledgments and must persist local native answer/offer/final
transcript correlation before returning true. Callbacks honor the single
120-second context; the helper does not start timeout goroutines around them.
A true local answer is irreversible: later failure is `ErrPairingUncertain`.
The handshake uses at most5seconds of the remaining entry-time budget.

Each role commits its actual ordered keys,32-byte random nonce, proposal length
and SHA256 BEFORE either nonce is revealed. Revealed descriptors and payloads
must match those commitments. The final transcript binds both actual proposals
with length prefixes, commitments, nonces, actual keys and TLS exporter. All
proof/display/decision MACs and bounded unbiased six-digit comparison use /2
domains. A changed proposal requires a fresh ceremony and consent.

All exchanges run I then R: commitments(stage1), reveals(stage2), complete
proposals(stage3), proof(stage4), displayed(stage5), decision(stage6). Existing
framing limits each frame to512bytes; header is stage/version/role plus32-byte
transcript (zero before proof). Commitment payload is32bytes, reveal is nonce32
plus length4/hash32. Proposal chunks are index1/count1/length2 plus at most448
bytes, exactly ceil(precommitted length/448), at most5 per role. An empty opaque
proposal transfers zero chunks and still requires runtime Validate. Proof and
display MACs are32bytes; decision is0/1 plus MAC32. Unknown, extra, reordered,
oversized or mismatched frames refuse before advancement. Terminal closure
dispatches nothing further; later bytes cannot retroactively invalidate a
returned result.

The descriptor is uint32 proposal byte length followed by SHA256(proposal).
Let K be SHA256(I certificate's DER SubjectPublicKeyInfo) followed by
SHA256(R certificate's DER SubjectPublicKeyInfo). Each commitment is
SHA256(`OA-Pair/2/commit` || role-byte || version-byte2 || K || nonce32 ||
descriptor36). Let E be the32-byte TLS exporter for label
`EXPORTER-Channel-Binding` and an empty context. The final transcript T is
SHA256(`OA-Pair/2/transcript` || version-byte2 || K || I-commit || R-commit ||
I-nonce || R-nonce || E || uint32(I-proposal-length) || I-proposal ||
uint32(R-proposal-length) || R-proposal). Header transcript bytes remain zero
through proposal transfer; stages4–6 carry T.

For domain `proof`, `displayed` or `decision`, the MAC is HMAC-SHA256 keyed
by the invitation secret over `OA-Pair/2/` || domain || version-byte2 ||
role-byte || T || data. Data is empty for proof/displayed and one byte0/1
for decision. Both decisions must be1 for success. To derive the six digits,
for counters0 through15 hash `OA-Pair/2/check` || T || uint32(counter).
Scan each digest's eight uint32 words in order; accept the first less than
4294000000, reduce modulo1000000 and format as exactly six decimal digits.
Exhausting all counters refuses the ceremony.

The2048-byte cap accommodates the initial proposed three-rule subset: using
existing Rights action<=128 and resource<=1024 bounds, two fixed resources
`account`(7) and `abstraction.router/inventory`(28), and one variable host resource,
a proposed envelope67 plus three tuples(2+128+2+1+8+1) and resources totals1552.
This calculation is a capacity rationale, not an implemented runtime schema or
approval of conditions/defaults. Larger or future effect sets must refuse the
opaque bound;64effects/five bundles are not claimed to fit.

A successful `PairCandidate` contains frozen agreement/transcript and actual
certificate evidence. It establishes no pin, rights or reciprocal durable commit.
Public candidate data is not authority. The runtime owns one-attempt invitation
consumption, native person evidence, exact-effect recomputation and conditional
store/Rights reconciliation. Controller, offered/requested scope UX, canonical
runtime schema, Rights join and installed/platform pairing remain unqualified.
