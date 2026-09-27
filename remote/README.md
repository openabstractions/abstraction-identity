# Authenticated remote frames

This page is for whoever builds a remote host or client transport for OA over
TLS. An application calling a capability resolves a local or remote binding
through the facade instead.

Install the runtime first: https://openabstractions.org/adopt.html

`remote.Client` and `remote.Server` carry the shared bounded frame protocol over
mutually authenticated TLS 1.3. Generated capability protocols retain their exact
payloads. The transport identifier is `oa-framed-mtls@1`; TLS negotiates the ALPN
name `oa-framed/1`.

The host supplies an address, expected server DNS name, explicit certificate
roots and client credential. Server construction supplies its certificate,
trusted client roots and a capability handler. Every call uses a fresh handshake.
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
job acceptance declares 2 MiB.

TLS keys and configuration callbacks remain immutable during use. Client roots
and server client roots are cloned. Dynamic server configuration replacement is
refused, preserving the required mutual authentication configuration.

This is an explicit Go transport/provider building block. Installed registration,
facade remote selection, credential distribution and C-ABI remote transport
remain integration work. Local-server verification remains independently required.

Run `go test -race ./remote` from this module. Tests use isolated credentials and
loopback listeners. [Go TLS configuration](https://pkg.go.dev/crypto/tls#Config)
defines the underlying certificate verification and handshake behavior.
