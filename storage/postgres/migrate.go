package postgres

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

var (
	// ErrSchemaOutdated means the database is older than this code; run Migrate.
	ErrSchemaOutdated = errors.New("ima/postgres: database schema is outdated; run migrations")
	// ErrSchemaTooNew means a newer go-ima migrated this database; Migrate refuses to touch it.
	ErrSchemaTooNew = errors.New("ima/postgres: database schema is newer than this code")
)

// migrationLockID is the transaction-scoped advisory lock serializing migrators.
// It is a fixed go-ima constant ("ima" in ASCII) so it never collides with host locks by accident.
const migrationLockID int64 = 0x696d61

// migrations are forward-only and append-only. Never edit or reorder a step;
// use only transactional DDL.
var migrations = []string{
	// 1: identity, devices, sessions, refresh tokens, audit.
	`
CREATE TABLE ima_users (
    id                uuid PRIMARY KEY,
    email             text NOT NULL,
    email_normalized  text NOT NULL UNIQUE,
    display_name      text NOT NULL DEFAULT '',
    status            text NOT NULL CHECK (status IN ('active', 'disabled')),
    email_verified_at timestamptz,
    created_at        timestamptz NOT NULL,
    updated_at        timestamptz NOT NULL
);
CREATE TABLE ima_password_credentials (
    user_id    uuid PRIMARY KEY REFERENCES ima_users (id) ON DELETE CASCADE,
    hash       text NOT NULL,
    updated_at timestamptz NOT NULL
);
CREATE TABLE ima_devices (
    id           uuid PRIMARY KEY,
    user_id      uuid NOT NULL REFERENCES ima_users (id) ON DELETE CASCADE,
    token_hash   bytea NOT NULL UNIQUE,
    name         text NOT NULL DEFAULT '',
    created_at   timestamptz NOT NULL,
    last_seen_at timestamptz NOT NULL
);
CREATE INDEX ima_devices_user_idx ON ima_devices (user_id);
CREATE TABLE ima_sessions (
    id                uuid PRIMARY KEY,
    user_id           uuid NOT NULL REFERENCES ima_users (id) ON DELETE CASCADE,
    device_id         uuid NOT NULL REFERENCES ima_devices (id) ON DELETE CASCADE,
    access_hash       bytea NOT NULL UNIQUE,
    access_expires_at timestamptz NOT NULL,
    created_at        timestamptz NOT NULL,
    last_active_at    timestamptz NOT NULL,
    expires_at        timestamptz NOT NULL,
    revoked_at        timestamptz,
    revoke_reason     text,
    created_ip        inet,
    last_ip           inet,
    user_agent        text NOT NULL DEFAULT ''
);
CREATE INDEX ima_sessions_user_active_idx ON ima_sessions (user_id) WHERE revoked_at IS NULL;
CREATE TABLE ima_refresh_tokens (
    hash       bytea PRIMARY KEY,
    session_id uuid NOT NULL REFERENCES ima_sessions (id) ON DELETE CASCADE,
    created_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL,
    used_at    timestamptz
);
CREATE INDEX ima_refresh_tokens_session_idx ON ima_refresh_tokens (session_id);
-- Audit rows outlive users on purpose: no foreign keys.
CREATE TABLE ima_audit_events (
    id          bigserial PRIMARY KEY,
    type        text NOT NULL,
    user_id     uuid,
    session_id  uuid,
    ip          inet,
    occurred_at timestamptz NOT NULL,
    metadata    jsonb NOT NULL DEFAULT '{}'
);
CREATE INDEX ima_audit_events_user_idx ON ima_audit_events (user_id, occurred_at);
`,
}

// SchemaVersion is the schema version this code requires.
func SchemaVersion() int { return len(migrations) }

const versionsTable = `CREATE TABLE IF NOT EXISTS ima_schema_migrations (
    version    integer PRIMARY KEY,
    applied_at timestamptz NOT NULL DEFAULT now()
)`

// Migrate applies pending steps in one transaction under an advisory lock.
// It is safe to repeat and to run concurrently. go-ima never calls it on its
// own: the host (or ima-server's -migrate flag) decides when it runs.
func Migrate(ctx context.Context, pool *pgxpool.Pool) error {
	if pool == nil {
		return errors.New("ima/postgres: nil pool")
	}
	return pgx.BeginTxFunc(ctx, pool, pgx.TxOptions{}, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock($1)`, migrationLockID); err != nil {
			return fmt.Errorf("ima/postgres: migration lock: %w", err)
		}
		if _, err := tx.Exec(ctx, versionsTable); err != nil {
			return fmt.Errorf("ima/postgres: versions table: %w", err)
		}
		var current int
		if err := tx.QueryRow(ctx, `SELECT COALESCE(max(version), 0) FROM ima_schema_migrations`).Scan(&current); err != nil {
			return fmt.Errorf("ima/postgres: read version: %w", err)
		}
		if current > len(migrations) {
			return fmt.Errorf("%w: database=%d code=%d", ErrSchemaTooNew, current, len(migrations))
		}
		for v := current + 1; v <= len(migrations); v++ {
			if _, err := tx.Exec(ctx, migrations[v-1]); err != nil {
				return fmt.Errorf("ima/postgres: migration %d: %w", v, err)
			}
			if _, err := tx.Exec(ctx, `INSERT INTO ima_schema_migrations (version) VALUES ($1)`, v); err != nil {
				return fmt.Errorf("ima/postgres: record migration %d: %w", v, err)
			}
		}
		return nil
	})
}

// CurrentVersion returns the applied schema version, 0 when never migrated.
func CurrentVersion(ctx context.Context, pool *pgxpool.Pool) (int, error) {
	var exists bool
	if err := pool.QueryRow(ctx, `SELECT to_regclass('ima_schema_migrations') IS NOT NULL`).Scan(&exists); err != nil {
		return 0, fmt.Errorf("ima/postgres: read version: %w", err)
	}
	if !exists {
		return 0, nil
	}
	var v int
	if err := pool.QueryRow(ctx, `SELECT COALESCE(max(version), 0) FROM ima_schema_migrations`).Scan(&v); err != nil {
		return 0, fmt.Errorf("ima/postgres: read version: %w", err)
	}
	return v, nil
}

// CheckSchema fails with ErrSchemaOutdated when the database is behind this
// code. A newer database is accepted: steps must stay backward compatible so
// old instances keep running during rolling deployments.
func CheckSchema(ctx context.Context, pool *pgxpool.Pool) (int, error) {
	v, err := CurrentVersion(ctx, pool)
	if err != nil {
		return 0, err
	}
	if v < len(migrations) {
		return v, fmt.Errorf("%w: database=%d code=%d", ErrSchemaOutdated, v, len(migrations))
	}
	return v, nil
}
