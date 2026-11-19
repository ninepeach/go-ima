# go-ima Implementation Checklist

Tracks the repository against the design baseline in
[architecture-docs/projects/go-ima/design.md](https://github.com/ninepeach/architecture-docs/blob/main/projects/go-ima/design.md).
Section numbers refer to that document.

Status: **done** (implemented and tested), **partial**, **missing**, or **change** (exists but contradicts the baseline).
Assessed on branch `feat/email-verification-password-reset` at `3185bc2`. Only facts read from the code are recorded; nothing here is a performance claim.

## 0. Blockers outside this repository

| Item | Status | Notes |
| --- | --- | --- |
| go-base consumable as tagged modules | missing | go-base is private and its providers require `core v0.0.0` with local `replace`. `go.mod` omits go-base requirements and builds only through a local `go.work`. |
| go-ratelimit tagged | missing | Needed for the Redis limiter; `redis/go.mod` uses `replace ../`. |
| go-base/ratelimit adapter | missing | Thin adapter over go-ratelimit, registered as a go-base component. |
| `origin/main` contains the code | missing | `origin/main` holds only `AGENTS.md`; all code is on the feature branch. |

## 1. Architecture (§2, §7)

| Item | Status | Notes |
| --- | --- | --- |
| API-only: application service not a public library API | change | Root package `ima` and the domain packages are importable; move them under `internal/`. Commit messages and README still describe an embedded library. |
| One application service shared by all transports | done | `ima.Service`; `transport/http` only decodes and maps errors. |
| `/v1` REST routes for core flows | partial | Register, login, refresh, logout, me, sessions, revoke, revoke-others. Email verification and password reset exist in the service but have no routes. |
| Shared DTOs in the SDK module | missing | DTOs are private structs in `transport/http`. |
| OpenAPI 3.1 and contract tests | missing | |
| RFC 9457 Problem Details | change | Errors use `{"error":{"code","message"}}` with `application/json`. |
| Tokens rejected in URL query | done | Only the `Authorization` header and JSON bodies are read. |

## 2. Identity, sessions, devices (§5)

| Item | Status | Notes |
| --- | --- | --- |
| Registration, Argon2id, rehash on parameter change | done | |
| Login without account enumeration | done | Dummy hash for unknown accounts; one error for all failures. |
| Devices from random device tokens | done | |
| Session list, revoke one, revoke others, logout | done | |
| Email verification and password reset challenges | partial | Service and storage done (migration 2, single conditional consume, reset revokes sessions). No HTTP routes; tokens are returned to the caller instead of being mailed through an outbox. |
| Account deletion and retention policy | missing | Policy must be defined first. |
| First administrator bootstrap | missing | |

## 3. Tokens (§6)

| Item | Status | Notes |
| --- | --- | --- |
| Ed25519 JWT access tokens (`at+jwt`, `kid`, claims) | change | Access tokens are opaque and looked up by digest in `ima_sessions.access_hash`. Changing the format needs a migration and approval per `AGENTS.md`. |
| JWKS endpoint, key rotation with overlap | missing | |
| Token version per user | missing | |
| Opaque single-use refresh tokens with replay revocation | done | Concurrent refresh succeeds at most once (tested). |
| Introspection for confidential applications | missing | |
| Applications registry and `aud` | missing | |

## 4. HTTP protection (§8.2)

| Item | Status | Notes |
| --- | --- | --- |
| Server timeouts and `MaxHeaderBytes` | partial | `ReadHeaderTimeout` 5s, `ReadTimeout` 30s, `WriteTimeout` 30s, `IdleTimeout` 2m; `MaxHeaderBytes` not set. |
| Body size limit and strict JSON | done | 64 KiB, unknown fields and trailing data rejected. |
| Per-route context budgets | missing | |
| Panic recovery middleware | missing | |
| CORS allowlist | missing | |
| `Cache-Control: no-store` | done | |
| Trusted-proxy client IP | done | Right-most untrusted `X-Forwarded-For` entry. |

## 5. Overload protection and rate limiting (§8.3, §8.4)

| Item | Status | Notes |
| --- | --- | --- |
| Global in-flight limit with immediate `503` | missing | |
| Argon2id semaphore sized by CPU and memory | missing | |
| Rate-limit hook before hashing | done | `ima.Limiter` is called before verification; IPv6 aggregated to /64. |
| Production limiter (Redis) | missing | `ima-server` runs with a nil limiter and logs a warning. |
| Device-token exemption from account limits | missing | Account and IP keys are always checked together. |
| Application dimension | missing | Depends on applications. |
| `429` vs `503` distinction | partial | `429` for rate limits; no capacity rejection exists yet. |
| Explicit in-memory fallback when Redis fails | missing | |

## 6. Dependency isolation (§8.5)

| Item | Status | Notes |
| --- | --- | --- |
| Queries under request context | done | |
| Pool size, `statement_timeout`, `lock_timeout` | missing | Configurable through the DSN; not documented or set in the example config. |
| Email outbox and worker | missing | |
| Readiness only on PostgreSQL | partial | `/readyz` uses go-base health; only PostgreSQL is registered today. |

## 7. Operations (§9)

| Item | Status | Notes |
| --- | --- | --- |
| Separate internal listener | change | `/healthz` and `/readyz` are served on the public listener. |
| Prometheus metrics | missing | |
| OpenTelemetry tracing | missing | |
| pprof, build info, redacted config | missing | |
| Logs without secrets | done | Tokens and passwords are never logged. |
| Configurable logger | missing | go-base now provides `WithLogger`; `ima-server` does not use it. |
| Graceful shutdown | done | HTTP shutdown, then bounded go-base close. |
| `-migrate` one-shot mode and schema check | done | |

## 8. Acceptance tests (§12)

| Item | Status |
| --- | --- |
| Core flows, replay, concurrent refresh, isolation | done |
| Key rotation and verifier | missing |
| Login flood, slow clients, oversized requests, panics | missing |
| PostgreSQL slowdown, Redis outage, SMTP outage | missing |
| Restart under load | missing |
| Contract tests (routes, OpenAPI, SDK) | missing |
| Load tests calibrating §8 values | missing |
