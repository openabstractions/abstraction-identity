# Framed handler admission

`CallAdmission.Take` claims capacity before a host starts a handler. Refused
connections close immediately. The host defers the returned release until its
handler returns, including handshake failures, transport close and cancellation.
Session reuse and first-header waiting remain bounded separately by `Sessions`.

The current 18 consumers use one admission implementation. Their existing
limits are preserved; router and resource gain the default 64-handler bound.
Paths below are relative to the repository root.

| Consumer | Source | Limit |
|---|---|---:|
| Credentials | `openabstractions-flat/abstraction-credentials/go/service/host.go` | 32 |
| Config | `openabstractions-flat/abstraction-config/go/service/service.go` | 64 |
| Local stores | `openabstractions-flat/abstraction-storage-over-local-stores/go/service/host.go` | 16 |
| Model | `openabstractions-flat/abstraction-model/go/service/service.go` | 32 |
| Logging | `openabstractions-flat/abstraction-logging/go/service/service.go` | 64 |
| Resource | `openabstractions-flat/abstraction-resource/go/service/host.go` | 64 |
| Storage | `openabstractions-flat/abstraction-storage/go/service/service.go` | 32 |
| Asks | `openabstractions-flat/abstraction-asks/go/application/host.go` | 32 |
| Rights | `openabstractions-flat/abstraction-rights/go/authorization/host.go` | 32 |
| Router | `openabstractions-flat/abstraction-router/go/service/service.go` | 64 |
| Inference | `openabstractions-flat/abstraction-inference/go/service/host.go` | 64 |
| Modelbridge | `openabstractions-flat/abstraction-provider-modelbridge/go/service/host.go` | 8 |
| Facade resolution | `openabstractions-flat/abstraction-facade/go-core/resolution/host.go` | 64 |
| Jobs | `openabstractions-flat/abstraction-facade/go/runtime/jobs.go` | 64 |
| Applications | `serve/applications_host.go` | 64 |
| Registry | `serve/registry.go` | 64 |
| Lending | `serve/runtime_lending.go` | 16 |
| Paired resolution | `serve/runtime_pairing_resolution.go` | 16 |

This is an additive Go transport utility against the accounted published
`abstraction-identity` v0.5.1 source
`1267f150df094a372b29080fe110fe82c955c295`. Existing Go exports, capability
interfaces, wire framing, identity evidence and authority are unchanged.
All consumers already depend on Identity. Placing the utility in facade
go-core would introduce a Storage → go-core → Storage module cycle. The future
go-core `ServeFramed` can consume this same transport admission owner.
