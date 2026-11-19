// Package audit defines security events. Events never contain passwords,
// verification codes or tokens; metadata values must be non-secret.
package audit

import (
	"context"
	"net/netip"
	"time"

	"github.com/google/uuid"
)

type Type string

const (
	UserRegistered      Type = "user.registered"
	LoginSucceeded      Type = "login.succeeded"
	LoginFailed         Type = "login.failed"
	TokenRefreshed      Type = "token.refreshed"
	RefreshReuseBlocked Type = "token.refresh_reuse"
	SessionRevoked      Type = "session.revoked"
	DeviceRegistered    Type = "device.registered"
	EmailVerifyIssued   Type = "email.verification_issued"
	EmailVerified       Type = "email.verified"
	PasswordResetIssued Type = "password.reset_issued"
	PasswordReset       Type = "password.reset"
)

type Event struct {
	Type       Type
	UserID     uuid.UUID // uuid.Nil when unknown (e.g. failed login for unknown email)
	SessionID  uuid.UUID
	IP         netip.Addr
	OccurredAt time.Time
	Metadata   map[string]string
}

// Recorder writes events. Implementations take the active transaction from
// ctx so that an event commits or rolls back with the use case it describes.
type Recorder interface {
	Record(ctx context.Context, e Event) error
}
