package postgres

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/ninepeach/go-ima/device"
)

// Devices implements device.Repository.
type Devices struct{ s *Store }

var _ device.Repository = (*Devices)(nil)

func (r *Devices) Create(ctx context.Context, d device.Device, tokenHash []byte) error {
	if _, err := r.s.q(ctx).Exec(ctx, `INSERT INTO ima_devices (id, user_id, token_hash, name, created_at, last_seen_at)
        VALUES ($1, $2, $3, $4, $5, $6)`, d.ID, d.UserID, tokenHash, d.Name, d.CreatedAt, d.LastSeenAt); err != nil {
		return fmt.Errorf("ima/postgres: insert device: %w", err)
	}
	return nil
}

func (r *Devices) ByToken(ctx context.Context, userID uuid.UUID, tokenHash []byte) (device.Device, error) {
	var d device.Device
	err := r.s.q(ctx).QueryRow(ctx, `SELECT id, user_id, name, created_at, last_seen_at FROM ima_devices
        WHERE user_id = $1 AND token_hash = $2`, userID, tokenHash).Scan(&d.ID, &d.UserID, &d.Name, &d.CreatedAt, &d.LastSeenAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return device.Device{}, device.ErrNotFound
	}
	if err != nil {
		return device.Device{}, fmt.Errorf("ima/postgres: device by token: %w", err)
	}
	return d, nil
}

func (r *Devices) Touch(ctx context.Context, id uuid.UUID, now time.Time) error {
	if _, err := r.s.q(ctx).Exec(ctx, `UPDATE ima_devices SET last_seen_at = $2 WHERE id = $1 AND last_seen_at < $2`, id, now); err != nil {
		return fmt.Errorf("ima/postgres: touch device: %w", err)
	}
	return nil
}

func (r *Devices) ListByUser(ctx context.Context, userID uuid.UUID) ([]device.Device, error) {
	rows, err := r.s.q(ctx).Query(ctx, `SELECT id, user_id, name, created_at, last_seen_at FROM ima_devices
        WHERE user_id = $1 ORDER BY last_seen_at DESC, id`, userID)
	if err != nil {
		return nil, fmt.Errorf("ima/postgres: list devices: %w", err)
	}
	defer rows.Close()
	var out []device.Device
	for rows.Next() {
		var d device.Device
		if err := rows.Scan(&d.ID, &d.UserID, &d.Name, &d.CreatedAt, &d.LastSeenAt); err != nil {
			return nil, fmt.Errorf("ima/postgres: list devices: %w", err)
		}
		out = append(out, d)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("ima/postgres: list devices: %w", err)
	}
	return out, nil
}
