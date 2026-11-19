package postgres

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/ninepeach/go-ima/identity"
)

// Users implements identity.Repository.
type Users struct{ s *Store }

var _ identity.Repository = (*Users)(nil)

const uniqueViolation = "23505"

func (r *Users) Create(ctx context.Context, u identity.User, normalizedEmail, passwordHash string) error {
	return r.s.InTx(ctx, func(ctx context.Context) error {
		q := r.s.q(ctx)
		_, err := q.Exec(ctx, `INSERT INTO ima_users
            (id, email, email_normalized, display_name, status, email_verified_at, created_at, updated_at)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
			u.ID, u.Email, normalizedEmail, u.DisplayName, string(u.Status), u.EmailVerifiedAt, u.CreatedAt, u.UpdatedAt)
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == uniqueViolation {
			return identity.ErrEmailTaken
		}
		if err != nil {
			return fmt.Errorf("ima/postgres: insert user: %w", err)
		}
		if _, err := q.Exec(ctx, `INSERT INTO ima_password_credentials (user_id, hash, updated_at) VALUES ($1, $2, $3)`,
			u.ID, passwordHash, u.CreatedAt); err != nil {
			return fmt.Errorf("ima/postgres: insert credential: %w", err)
		}
		return nil
	})
}

const userColumns = `u.id, u.email, u.display_name, u.status, u.email_verified_at, u.created_at, u.updated_at`

func scanUser(row pgx.Row, extra ...any) (identity.User, error) {
	var u identity.User
	var status string
	dest := append([]any{&u.ID, &u.Email, &u.DisplayName, &status, &u.EmailVerifiedAt, &u.CreatedAt, &u.UpdatedAt}, extra...)
	if err := row.Scan(dest...); err != nil {
		return identity.User{}, err
	}
	u.Status = identity.Status(status)
	return u, nil
}

func (r *Users) ByEmail(ctx context.Context, normalizedEmail string) (identity.User, string, error) {
	var hash string
	u, err := scanUser(r.s.q(ctx).QueryRow(ctx, `SELECT `+userColumns+`, c.hash
        FROM ima_users u JOIN ima_password_credentials c ON c.user_id = u.id
        WHERE u.email_normalized = $1`, normalizedEmail), &hash)
	if errors.Is(err, pgx.ErrNoRows) {
		return identity.User{}, "", identity.ErrNotFound
	}
	if err != nil {
		return identity.User{}, "", fmt.Errorf("ima/postgres: user by email: %w", err)
	}
	return u, hash, nil
}

func (r *Users) ByID(ctx context.Context, id uuid.UUID) (identity.User, error) {
	u, err := scanUser(r.s.q(ctx).QueryRow(ctx, `SELECT `+userColumns+` FROM ima_users u WHERE u.id = $1`, id))
	if errors.Is(err, pgx.ErrNoRows) {
		return identity.User{}, identity.ErrNotFound
	}
	if err != nil {
		return identity.User{}, fmt.Errorf("ima/postgres: user by id: %w", err)
	}
	return u, nil
}

// UpdatePasswordHash replaces a credential hash, used for transparent rehash after login.
func (r *Users) UpdatePasswordHash(ctx context.Context, id uuid.UUID, hash string, at time.Time) error {
	_, err := r.s.q(ctx).Exec(ctx, `UPDATE ima_password_credentials SET hash = $2, updated_at = $3 WHERE user_id = $1`, id, hash, at)
	if err != nil {
		return fmt.Errorf("ima/postgres: update credential: %w", err)
	}
	return nil
}

func (r *Users) MarkEmailVerified(ctx context.Context, id uuid.UUID, at time.Time) error {
	tag, err := r.s.q(ctx).Exec(ctx, `UPDATE ima_users
        SET email_verified_at = COALESCE(email_verified_at, $2), updated_at = $2 WHERE id = $1`, id, at)
	if err != nil {
		return fmt.Errorf("ima/postgres: mark email verified: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return identity.ErrNotFound
	}
	return nil
}
