package postgres

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/ninepeach/go-ima/session"
)

// Sessions implements session.Repository.
type Sessions struct{ s *Store }

var _ session.Repository = (*Sessions)(nil)

func (r *Sessions) Create(ctx context.Context, s session.Session, accessHash, refreshHash []byte, refreshExpiresAt time.Time) error {
	return r.s.InTx(ctx, func(ctx context.Context) error {
		q := r.s.q(ctx)
		if _, err := q.Exec(ctx, `INSERT INTO ima_sessions
            (id, user_id, device_id, access_hash, access_expires_at, created_at, last_active_at, expires_at, created_ip, last_ip, user_agent)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $9, $10)`,
			s.ID, s.UserID, s.DeviceID, accessHash, s.AccessExpiresAt, s.CreatedAt, s.LastActiveAt, s.ExpiresAt,
			ipArg(s.CreatedIP), s.UserAgent); err != nil {
			return fmt.Errorf("ima/postgres: insert session: %w", err)
		}
		if _, err := q.Exec(ctx, `INSERT INTO ima_refresh_tokens (hash, session_id, created_at, expires_at) VALUES ($1, $2, $3, $4)`,
			refreshHash, s.ID, s.CreatedAt, refreshExpiresAt); err != nil {
			return fmt.Errorf("ima/postgres: insert refresh token: %w", err)
		}
		return nil
	})
}

const sessionColumns = `id, user_id, device_id, created_at, last_active_at, expires_at, access_expires_at,
    revoked_at, COALESCE(revoke_reason, ''), created_ip, last_ip, user_agent`

func scanSession(row pgx.Row) (session.Session, error) {
	var s session.Session
	var created, last *netip.Prefix
	if err := row.Scan(&s.ID, &s.UserID, &s.DeviceID, &s.CreatedAt, &s.LastActiveAt, &s.ExpiresAt, &s.AccessExpiresAt,
		&s.RevokedAt, &s.RevokeReason, &created, &last, &s.UserAgent); err != nil {
		return session.Session{}, err
	}
	s.CreatedIP, s.LastIP = ipFrom(created), ipFrom(last)
	return s, nil
}

func (r *Sessions) one(ctx context.Context, sql string, args ...any) (session.Session, error) {
	s, err := scanSession(r.s.q(ctx).QueryRow(ctx, sql, args...))
	if errors.Is(err, pgx.ErrNoRows) {
		return session.Session{}, session.ErrNotFound
	}
	if err != nil {
		return session.Session{}, fmt.Errorf("ima/postgres: session: %w", err)
	}
	return s, nil
}

func (r *Sessions) ByAccessHash(ctx context.Context, accessHash []byte, now time.Time) (session.Session, error) {
	return r.one(ctx, `SELECT `+sessionColumns+` FROM ima_sessions
        WHERE access_hash = $1 AND revoked_at IS NULL AND access_expires_at > $2 AND expires_at > $2`, accessHash, now)
}

func (r *Sessions) Get(ctx context.Context, id uuid.UUID) (session.Session, error) {
	return r.one(ctx, `SELECT `+sessionColumns+` FROM ima_sessions WHERE id = $1`, id)
}

func (r *Sessions) ConsumeRefresh(ctx context.Context, refreshHash []byte, now time.Time) (session.RefreshState, error) {
	var st session.RefreshState
	err := r.s.InTx(ctx, func(ctx context.Context) error {
		q := r.s.q(ctx)
		var usedAt *time.Time
		err := q.QueryRow(ctx, `SELECT t.session_id, t.used_at, s.expires_at
            FROM ima_refresh_tokens t JOIN ima_sessions s ON s.id = t.session_id
            WHERE t.hash = $1 AND t.expires_at > $2
            FOR UPDATE OF t`, refreshHash, now).Scan(&st.SessionID, &usedAt, &st.ExpiresAt)
		if errors.Is(err, pgx.ErrNoRows) {
			return session.ErrNotFound
		}
		if err != nil {
			return fmt.Errorf("ima/postgres: refresh token: %w", err)
		}
		if usedAt != nil {
			st.AlreadyUsed = true
			return nil
		}
		if _, err := q.Exec(ctx, `UPDATE ima_refresh_tokens SET used_at = $2 WHERE hash = $1`, refreshHash, now); err != nil {
			return fmt.Errorf("ima/postgres: consume refresh token: %w", err)
		}
		return nil
	})
	return st, err
}

func (r *Sessions) Rotate(ctx context.Context, id uuid.UUID, accessHash []byte, accessExpiresAt time.Time,
	refreshHash []byte, refreshExpiresAt time.Time, now time.Time, ip netip.Addr) error {
	return r.s.InTx(ctx, func(ctx context.Context) error {
		q := r.s.q(ctx)
		tag, err := q.Exec(ctx, `UPDATE ima_sessions
            SET access_hash = $2, access_expires_at = $3, last_active_at = $4, last_ip = COALESCE($5, last_ip)
            WHERE id = $1 AND revoked_at IS NULL AND expires_at > $4`, id, accessHash, accessExpiresAt, now, ipArg(ip))
		if err != nil {
			return fmt.Errorf("ima/postgres: rotate session: %w", err)
		}
		if tag.RowsAffected() == 0 {
			return session.ErrNotFound
		}
		if _, err := q.Exec(ctx, `INSERT INTO ima_refresh_tokens (hash, session_id, created_at, expires_at) VALUES ($1, $2, $3, $4)`,
			refreshHash, id, now, refreshExpiresAt); err != nil {
			return fmt.Errorf("ima/postgres: insert refresh token: %w", err)
		}
		return nil
	})
}

func (r *Sessions) Touch(ctx context.Context, id uuid.UUID, now time.Time, ip netip.Addr, interval time.Duration) error {
	_, err := r.s.q(ctx).Exec(ctx, `UPDATE ima_sessions SET last_active_at = $2, last_ip = COALESCE($3, last_ip)
        WHERE id = $1 AND revoked_at IS NULL AND last_active_at < $4`, id, now, ipArg(ip), now.Add(-interval))
	if err != nil {
		return fmt.Errorf("ima/postgres: touch session: %w", err)
	}
	return nil
}

func (r *Sessions) Revoke(ctx context.Context, id uuid.UUID, now time.Time, reason string) error {
	var exists bool
	err := r.s.q(ctx).QueryRow(ctx, `WITH upd AS (
            UPDATE ima_sessions SET revoked_at = $2, revoke_reason = $3 WHERE id = $1 AND revoked_at IS NULL RETURNING 1)
        SELECT EXISTS (SELECT 1 FROM ima_sessions WHERE id = $1)`, id, now, reason).Scan(&exists)
	if err != nil {
		return fmt.Errorf("ima/postgres: revoke session: %w", err)
	}
	if !exists {
		return session.ErrNotFound
	}
	return nil
}

func (r *Sessions) RevokeOthers(ctx context.Context, userID, keep uuid.UUID, now time.Time, reason string) (int, error) {
	tag, err := r.s.q(ctx).Exec(ctx, `UPDATE ima_sessions SET revoked_at = $3, revoke_reason = $4
        WHERE user_id = $1 AND id <> $2 AND revoked_at IS NULL AND expires_at > $3`, userID, keep, now, reason)
	if err != nil {
		return 0, fmt.Errorf("ima/postgres: revoke other sessions: %w", err)
	}
	return int(tag.RowsAffected()), nil
}

func (r *Sessions) ListActive(ctx context.Context, userID uuid.UUID, now time.Time) ([]session.Session, error) {
	rows, err := r.s.q(ctx).Query(ctx, `SELECT `+sessionColumns+` FROM ima_sessions
        WHERE user_id = $1 AND revoked_at IS NULL AND expires_at > $2
        ORDER BY last_active_at DESC, id`, userID, now)
	if err != nil {
		return nil, fmt.Errorf("ima/postgres: list sessions: %w", err)
	}
	defer rows.Close()
	var out []session.Session
	for rows.Next() {
		s, err := scanSession(rows)
		if err != nil {
			return nil, fmt.Errorf("ima/postgres: list sessions: %w", err)
		}
		out = append(out, s)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("ima/postgres: list sessions: %w", err)
	}
	return out, nil
}
