package postgres

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/ninepeach/go-ima/challenge"
)

// Challenges implements challenge.Repository.
type Challenges struct{ s *Store }

var _ challenge.Repository = (*Challenges)(nil)

func (r *Challenges) Create(ctx context.Context, c challenge.Challenge, tokenHash []byte) error {
	return r.s.InTx(ctx, func(ctx context.Context) error {
		q := r.s.q(ctx)
		// Superseded links stop working; consumed_at records when.
		if _, err := q.Exec(ctx, `UPDATE ima_challenges SET consumed_at = $3
            WHERE user_id = $1 AND purpose = $2 AND consumed_at IS NULL`, c.UserID, string(c.Purpose), c.CreatedAt); err != nil {
			return fmt.Errorf("ima/postgres: invalidate challenges: %w", err)
		}
		if _, err := q.Exec(ctx, `INSERT INTO ima_challenges (id, user_id, purpose, token_hash, created_at, expires_at)
            VALUES ($1, $2, $3, $4, $5, $6)`, c.ID, c.UserID, string(c.Purpose), tokenHash, c.CreatedAt, c.ExpiresAt); err != nil {
			return fmt.Errorf("ima/postgres: insert challenge: %w", err)
		}
		return nil
	})
}

// Consume is a single conditional UPDATE, so concurrent consumers race on the
// row lock and at most one sees the row as open.
func (r *Challenges) Consume(ctx context.Context, purpose challenge.Purpose, tokenHash []byte, now time.Time) (challenge.Challenge, error) {
	var c challenge.Challenge
	var p string
	err := r.s.q(ctx).QueryRow(ctx, `UPDATE ima_challenges SET consumed_at = $3
        WHERE token_hash = $1 AND purpose = $2 AND consumed_at IS NULL AND expires_at > $3
        RETURNING id, user_id, purpose, created_at, expires_at`, tokenHash, string(purpose), now).
		Scan(&c.ID, &c.UserID, &p, &c.CreatedAt, &c.ExpiresAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return challenge.Challenge{}, challenge.ErrNotFound
	}
	if err != nil {
		return challenge.Challenge{}, fmt.Errorf("ima/postgres: consume challenge: %w", err)
	}
	c.Purpose = challenge.Purpose(p)
	return c, nil
}
