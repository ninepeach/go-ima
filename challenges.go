package ima

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/ninepeach/go-ima/audit"
	"github.com/ninepeach/go-ima/auth"
	"github.com/ninepeach/go-ima/challenge"
	"github.com/ninepeach/go-ima/identity"
	"github.com/ninepeach/go-ima/session"
)

// Issued is a newly created one-time challenge. go-ima does not deliver it:
// the host sends Token to User.Email (for example as a link) and must not log it.
type Issued struct {
	User      identity.User
	Token     string
	ExpiresAt time.Time
}

// RequestEmailVerification issues an email verification token for an active,
// unverified account. Unknown, disabled and already verified accounts return
// ErrNotFound, which public transports must not reveal.
func (s *Service) RequestEmailVerification(ctx context.Context, email string, c ClientInfo) (Issued, error) {
	return s.issue(ctx, email, c, ActionVerifyEmailRequest, challenge.PurposeVerifyEmail,
		session.KindVerifyEmail, s.o.VerifyEmailTTL, audit.EmailVerifyIssued,
		func(u identity.User) bool { return u.EmailVerifiedAt == nil })
}

// RequestPasswordReset issues a password reset token for an active account.
// Unknown and disabled accounts return ErrNotFound, which public transports
// must not reveal.
func (s *Service) RequestPasswordReset(ctx context.Context, email string, c ClientInfo) (Issued, error) {
	return s.issue(ctx, email, c, ActionPasswordResetRequest, challenge.PurposePasswordReset,
		session.KindPasswordReset, s.o.PasswordResetTTL, audit.PasswordResetIssued,
		func(identity.User) bool { return true })
}

func (s *Service) issue(ctx context.Context, rawEmail string, c ClientInfo, action string, purpose challenge.Purpose,
	kind string, ttl time.Duration, ev audit.Type, eligible func(identity.User) bool) (Issued, error) {
	email, err := identity.NormalizeEmail(rawEmail)
	if err != nil {
		return Issued{}, fmt.Errorf("%w: email", ErrInvalidInput)
	}
	if err := s.allow(ctx, action, ipKey(c), "email:"+email); err != nil {
		return Issued{}, err
	}
	u, _, err := s.o.Users.ByEmail(ctx, email)
	if errors.Is(err, identity.ErrNotFound) {
		return Issued{}, ErrNotFound
	}
	if err != nil {
		return Issued{}, err
	}
	if u.Status != identity.StatusActive || !eligible(u) {
		return Issued{}, ErrNotFound
	}
	token, hash, err := session.NewToken(kind)
	if err != nil {
		return Issued{}, err
	}
	now := s.now()
	ch := challenge.Challenge{ID: uuid.New(), UserID: u.ID, Purpose: purpose, CreatedAt: now, ExpiresAt: now.Add(ttl)}
	err = s.o.Tx.InTx(ctx, func(ctx context.Context) error {
		if err := s.o.Challenges.Create(ctx, ch, hash); err != nil {
			return err
		}
		return s.o.Audit.Record(ctx, audit.Event{Type: ev, UserID: u.ID, IP: c.IP, OccurredAt: now})
	})
	if err != nil {
		return Issued{}, err
	}
	return Issued{User: u, Token: token, ExpiresAt: ch.ExpiresAt}, nil
}

// VerifyEmail consumes a verification token and marks the account's email as
// verified. Invalid, expired, superseded or reused tokens return ErrInvalidToken.
// It does not open a session.
func (s *Service) VerifyEmail(ctx context.Context, token string, c ClientInfo) (identity.User, error) {
	var u identity.User
	err := s.consume(ctx, token, c, challenge.PurposeVerifyEmail, session.KindVerifyEmail,
		func(ctx context.Context, ch challenge.Challenge, now time.Time) error {
			var err error
			if u, err = s.activeUser(ctx, ch.UserID); err != nil {
				return err
			}
			if err := s.o.Users.MarkEmailVerified(ctx, u.ID, now); err != nil {
				return err
			}
			if u.EmailVerifiedAt == nil {
				u.EmailVerifiedAt = &now
			}
			return s.o.Audit.Record(ctx, audit.Event{Type: audit.EmailVerified, UserID: u.ID, IP: c.IP, OccurredAt: now})
		})
	if err != nil {
		return identity.User{}, err
	}
	return u, nil
}

// ResetPassword consumes a reset token, replaces the password and revokes
// every session of the account. Because the token proves control of the
// mailbox, it also marks the email as verified.
func (s *Service) ResetPassword(ctx context.Context, token, newPassword string, c ClientInfo) error {
	if err := auth.ValidatePassword(newPassword); err != nil {
		return fmt.Errorf("%w: password", ErrInvalidInput)
	}
	// Hash before the transaction: Argon2id is deliberately slow.
	hash, err := s.o.Hasher.Hash(newPassword)
	if err != nil {
		return fmt.Errorf("ima: hash password: %w", err)
	}
	return s.consume(ctx, token, c, challenge.PurposePasswordReset, session.KindPasswordReset,
		func(ctx context.Context, ch challenge.Challenge, now time.Time) error {
			u, err := s.activeUser(ctx, ch.UserID)
			if err != nil {
				return err
			}
			if err := s.o.Users.UpdatePasswordHash(ctx, u.ID, hash, now); err != nil {
				return err
			}
			if err := s.o.Users.MarkEmailVerified(ctx, u.ID, now); err != nil {
				return err
			}
			n, err := s.o.Sessions.RevokeOthers(ctx, u.ID, uuid.Nil, now, session.ReasonPasswordReset)
			if err != nil {
				return err
			}
			return s.o.Audit.Record(ctx, audit.Event{Type: audit.PasswordReset, UserID: u.ID, IP: c.IP, OccurredAt: now,
				Metadata: map[string]string{"revoked_sessions": fmt.Sprint(n)}})
		})
}

func (s *Service) consume(ctx context.Context, token string, c ClientInfo, purpose challenge.Purpose, kind string,
	apply func(ctx context.Context, ch challenge.Challenge, now time.Time) error) error {
	if err := s.allow(ctx, ActionChallengeConsume, ipKey(c)); err != nil {
		return err
	}
	hash, err := session.HashToken(kind, strings.TrimSpace(token))
	if err != nil {
		return ErrInvalidToken
	}
	now := s.now()
	return s.o.Tx.InTx(ctx, func(ctx context.Context) error {
		ch, err := s.o.Challenges.Consume(ctx, purpose, hash, now)
		if errors.Is(err, challenge.ErrNotFound) {
			return ErrInvalidToken
		}
		if err != nil {
			return err
		}
		return apply(ctx, ch, now)
	})
}

// activeUser treats a disabled or deleted account like an invalid token.
func (s *Service) activeUser(ctx context.Context, id uuid.UUID) (identity.User, error) {
	u, err := s.o.Users.ByID(ctx, id)
	if errors.Is(err, identity.ErrNotFound) {
		return identity.User{}, ErrInvalidToken
	}
	if err != nil {
		return identity.User{}, err
	}
	if u.Status != identity.StatusActive {
		return identity.User{}, ErrInvalidToken
	}
	return u, nil
}
