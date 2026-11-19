// Package challenge defines one-time tokens delivered out of band, such as
// email verification and password reset links.
//
// Only a SHA-256 digest of each token is stored. A challenge is consumed at
// most once; issuing a new challenge for the same user and purpose
// invalidates the previous open ones, so only the latest link works.
package challenge

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
)

type Purpose string

const (
	PurposeVerifyEmail   Purpose = "verify_email"
	PurposePasswordReset Purpose = "password_reset"
)

// ErrNotFound covers unknown, expired, superseded and already consumed tokens alike.
var ErrNotFound = errors.New("challenge: not found")

type Challenge struct {
	ID        uuid.UUID
	UserID    uuid.UUID
	Purpose   Purpose
	CreatedAt time.Time
	ExpiresAt time.Time
}

type Repository interface {
	// Create stores c under tokenHash after invalidating every open challenge
	// of the same user and purpose.
	Create(ctx context.Context, c Challenge, tokenHash []byte) error
	// Consume marks the open, unexpired challenge with tokenHash and purpose as
	// consumed and returns it. Concurrent calls succeed at most once; every
	// other outcome is ErrNotFound.
	Consume(ctx context.Context, purpose Purpose, tokenHash []byte, now time.Time) (Challenge, error)
}
