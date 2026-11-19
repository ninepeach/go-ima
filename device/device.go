// Package device defines the devices a user signs in from.
//
// A device is identified by a random device token the client stores and
// presents on later logins. Device identity is never derived from IP
// addresses, User-Agent strings or client-chosen names.
package device

import (
	"context"
	"errors"
	"strings"
	"time"
	"unicode"

	"github.com/google/uuid"
)

var ErrNotFound = errors.New("device: not found")

const maxNameRunes = 64

type Device struct {
	ID         uuid.UUID
	UserID     uuid.UUID
	Name       string // client-supplied label, display only
	CreatedAt  time.Time
	LastSeenAt time.Time
}

// SanitizeName trims, strips control characters and truncates a display label.
func SanitizeName(name string) string {
	name = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) || r == '�' {
			return -1
		}
		return r
	}, strings.TrimSpace(name))
	if r := []rune(name); len(r) > maxNameRunes {
		name = string(r[:maxNameRunes])
	}
	return name
}

// Repository persists devices.
// Implementations take the active transaction from ctx when one exists.
type Repository interface {
	Create(ctx context.Context, d Device, tokenHash []byte) error
	// ByToken returns the device owned by userID with tokenHash, or ErrNotFound.
	ByToken(ctx context.Context, userID uuid.UUID, tokenHash []byte) (Device, error)
	Touch(ctx context.Context, id uuid.UUID, now time.Time) error
	ListByUser(ctx context.Context, userID uuid.UUID) ([]Device, error)
}
