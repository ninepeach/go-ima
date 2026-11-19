// Package session defines login sessions and their token lifecycle.
//
// A session is one login on one device. It carries one live access token and
// a chain of single-use refresh tokens; presenting a refresh token twice is
// treated as theft and revokes the whole session.
package session

import (
	"context"
	"errors"
	"net/netip"
	"time"

	"github.com/google/uuid"
)

var ErrNotFound = errors.New("session: not found")

// Revocation reasons recorded on the session.
const (
	ReasonLogout        = "logout"
	ReasonUserRevoked   = "user_revoked"
	ReasonOtherRevoked  = "signed_out_elsewhere"
	ReasonReuse         = "refresh_reuse"
	ReasonPasswordReset = "password_reset"
)

type Session struct {
	ID              uuid.UUID
	UserID          uuid.UUID
	DeviceID        uuid.UUID
	CreatedAt       time.Time // "signed in"
	LastActiveAt    time.Time // "last active"; updated at most once per touch interval
	ExpiresAt       time.Time // absolute lifetime; refresh never extends it
	AccessExpiresAt time.Time
	RevokedAt       *time.Time
	RevokeReason    string
	CreatedIP       netip.Addr
	LastIP          netip.Addr
	UserAgent       string // display only; never a trust signal
}

// Active reports whether the session can still be used at now.
func (s Session) Active(now time.Time) bool {
	return s.RevokedAt == nil && now.Before(s.ExpiresAt)
}

// RefreshState is the result of consuming a refresh token.
type RefreshState struct {
	SessionID   uuid.UUID
	ExpiresAt   time.Time
	AlreadyUsed bool // true means replay: the caller must revoke the session
}

// Repository persists sessions and refresh tokens.
// Implementations take the active transaction from ctx when one exists.
type Repository interface {
	Create(ctx context.Context, s Session, accessHash, refreshHash []byte, refreshExpiresAt time.Time) error
	// ByAccessHash returns an unrevoked session whose access token and session
	// lifetime are both unexpired at now, or ErrNotFound.
	ByAccessHash(ctx context.Context, accessHash []byte, now time.Time) (Session, error)
	Get(ctx context.Context, id uuid.UUID) (Session, error)
	// ConsumeRefresh locks the token row, marks it used and reports whether it
	// had been used before. Unknown or expired tokens return ErrNotFound.
	ConsumeRefresh(ctx context.Context, refreshHash []byte, now time.Time) (RefreshState, error)
	// Rotate installs a new access token and a new refresh token for an active session.
	Rotate(ctx context.Context, id uuid.UUID, accessHash []byte, accessExpiresAt time.Time,
		refreshHash []byte, refreshExpiresAt time.Time, now time.Time, ip netip.Addr) error
	// Touch updates LastActiveAt and LastIP when the last update is older than interval.
	Touch(ctx context.Context, id uuid.UUID, now time.Time, ip netip.Addr, interval time.Duration) error
	// Revoke is idempotent; an already revoked session keeps its first reason.
	Revoke(ctx context.Context, id uuid.UUID, now time.Time, reason string) error
	// RevokeOthers revokes every active session of userID except keep.
	RevokeOthers(ctx context.Context, userID, keep uuid.UUID, now time.Time, reason string) (int, error)
	// ListActive returns active sessions ordered by LastActiveAt descending.
	ListActive(ctx context.Context, userID uuid.UUID, now time.Time) ([]Session, error)
}
