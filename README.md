# go-ima

Go Identity Management & Authentication. One application service, two deployment modes:

- **Embedded** — a host Go application imports `github.com/ninepeach/go-ima` and calls `ima.Service` directly; identity tables live in the host's database (`ima_` prefix).
- **Standalone** — `cmd/ima-server` serves the same service as a versioned REST API (`/v1`) over its own database.

Both modes run the same `ima.Service`, so identity, session and authorization semantics are identical. The design baseline is [architecture-docs/projects/go-ima](https://github.com/ninepeach/architecture-docs/tree/main/projects/go-ima).

## Status: V1.0 skeleton

Implemented and tested against PostgreSQL:

- Registration (Argon2id, transparent rehash on parameter change), email normalization.
- Password login without account enumeration: unknown email, wrong password and disabled account return the same error at the same hashing cost; HTTP registration answers `202` whether or not the email was free.
- Opaque access tokens (default 15m) and single-use refresh tokens (idle 30d, absolute session lifetime 90d). Replaying a used refresh token revokes the whole session; concurrent refreshes succeed at most once.
- Devices identified by a random device token, never by IP or User-Agent. "Where you're logged in": session list with device, signed-in time, last active (throttled writes), last IP; sign out one session, all other sessions, or logout.
- Audit events committed in the same transaction as the use case; no secrets in events.
- Trusted-proxy aware client IP resolution in the HTTP transport.
- Explicit, versioned, forward-only migrations with an advisory lock and a startup schema check.
- Email verification and password reset as one-time challenges (Go library API only): `RequestEmailVerification`,
  `VerifyEmail`, `RequestPasswordReset`, `ResetPassword`. Tokens are stored as SHA-256 digests, expire (24h / 1h),
  are consumed at most once, and a new challenge supersedes earlier ones. A reset revokes every session.
  go-ima does not send mail: the host delivers `Issued.Token` and must hide `ErrNotFound` from public responses.

Not yet implemented (later versions): REST endpoints for verification and reset in `ima-server`, a production rate limiter (`ima.Limiter` is a hook; nil means unthrottled), account deletion and data retention, MFA, trusted-device approval, risk scoring, RBAC, tenants, admin API, JWT access tokens.

## Layout

```
ima (root)            application service: Register, Login, Refresh, Authenticate, sessions
identity/             users, email/name validation, repository port
auth/                 Argon2id hasher, password policy
session/              sessions, refresh-token state, opaque token generation
device/               devices, repository port
audit/                security events, recorder port
storage/postgres/     pgx repositories, transactions via context, migrations
transport/http/       /v1 REST handler (package imahttp)
cmd/ima-server/       standalone server on go-base Runtime
```

Domain packages depend on nothing but the standard library and uuid. The root service depends on domain ports only; `storage/postgres` and `transport/http` are adapters.

## Embedded use

```go
store, err := imapg.New(pool)          // pool is borrowed; go-ima never closes it
if err := imapg.Migrate(ctx, pool); err != nil { ... } // the host decides when
svc, err := ima.New(ima.Options{Repositories: store.Repositories(), Limiter: myLimiter})
res, err := svc.Login(ctx, ima.LoginRequest{Email: e, Password: p, Client: ima.ClientInfo{IP: ip}})
p, err := svc.Authenticate(ctx, res.AccessToken, client)
```

## Standalone server

```sh
cp config/ima-server.example.conf config/ima-server.conf
export IMA_DATABASE_URL=postgres://...
go run ./cmd/ima-server -config config/ima-server.conf -migrate   # apply schema, exit
go run ./cmd/ima-server -config config/ima-server.conf            # serve
```

`GET /healthz` is liveness; `GET /readyz` reflects go-base health (PostgreSQL). The server refuses to start on an outdated schema.

| Method | Path | Auth |
| --- | --- | --- |
| POST | `/v1/register` | – |
| POST | `/v1/login` | – |
| POST | `/v1/token/refresh` | – |
| POST | `/v1/logout` | Bearer |
| GET | `/v1/me` | Bearer |
| GET | `/v1/sessions` | Bearer |
| DELETE | `/v1/sessions/{id}` | Bearer |
| POST | `/v1/sessions/revoke-others` | Bearer |

## Development

go-base is not yet published as tagged modules, so develop with a local workspace next to a go-base checkout:

```sh
go work init . ../go-base/core ../go-base/postgres
IMA_TEST_DSN=postgres://user@localhost:5432/test?sslmode=disable go test -race ./...
```

Tests needing PostgreSQL are skipped without `IMA_TEST_DSN`; each test gets its own schema.
