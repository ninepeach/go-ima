package identity

import (
	"context"
	"time"

	"github.com/google/uuid"
)

// Repository persists users and password credentials.
// Implementations take the active transaction from ctx when one exists.
type Repository interface {
	// Create inserts a user and its password hash. It returns ErrEmailTaken
	// when normalizedEmail is already registered.
	Create(ctx context.Context, u User, normalizedEmail, passwordHash string) error
	// ByEmail returns the user and password hash, or ErrNotFound.
	ByEmail(ctx context.Context, normalizedEmail string) (User, string, error)
	// ByID returns the user, or ErrNotFound.
	ByID(ctx context.Context, id uuid.UUID) (User, error)
	// UpdatePasswordHash replaces the stored hash, e.g. to upgrade parameters.
	UpdatePasswordHash(ctx context.Context, id uuid.UUID, hash string, at time.Time) error
}
