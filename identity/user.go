// Package identity defines users and their password credentials.
//
// Identity knows nothing about sessions, devices or transports. Repositories
// are implemented by storage adapters and receive the transaction through ctx.
package identity

import (
	"errors"
	"net/mail"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/google/uuid"
)

var (
	ErrNotFound    = errors.New("identity: user not found")
	ErrEmailTaken  = errors.New("identity: email already registered")
	ErrInvalidUser = errors.New("identity: invalid user data")
)

// Status is the account state. Only active users can authenticate.
type Status string

const (
	StatusActive   Status = "active"
	StatusDisabled Status = "disabled"
)

const (
	maxEmailBytes       = 254
	maxDisplayNameBytes = 100
)

type User struct {
	ID              uuid.UUID
	Email           string // as entered, trimmed
	DisplayName     string
	Status          Status
	EmailVerifiedAt *time.Time
	CreatedAt       time.Time
	UpdatedAt       time.Time
}

// NormalizeEmail trims and lower-cases an address and rejects anything that is
// not a single bare address. The normalized form is the uniqueness key.
func NormalizeEmail(raw string) (string, error) {
	email := strings.TrimSpace(raw)
	if email == "" || len(email) > maxEmailBytes {
		return "", ErrInvalidUser
	}
	addr, err := mail.ParseAddress(email)
	if err != nil || addr.Name != "" || addr.Address != email {
		return "", ErrInvalidUser
	}
	return strings.ToLower(email), nil
}

// ValidateDisplayName accepts an optional, printable, bounded name.
func ValidateDisplayName(name string) (string, error) {
	name = strings.TrimSpace(name)
	if len(name) > maxDisplayNameBytes || !utf8.ValidString(name) {
		return "", ErrInvalidUser
	}
	for _, r := range name {
		if unicode.IsControl(r) {
			return "", ErrInvalidUser
		}
	}
	return name, nil
}
