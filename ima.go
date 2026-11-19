// Package ima is the go-ima application service: the single implementation of
// registration, login, token refresh and session management used by both the
// embedded Go library and the ima-server HTTP transport.
//
// V1.0 scope: password accounts, opaque access/refresh tokens with rotation
// and replay detection, devices, session listing and revocation, audit events,
// email verification and password reset challenges (challenges.go).
// MFA, RBAC and tenants are later versions.
package ima

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/ninepeach/go-ima/audit"
	"github.com/ninepeach/go-ima/auth"
	"github.com/ninepeach/go-ima/device"
	"github.com/ninepeach/go-ima/identity"
	"github.com/ninepeach/go-ima/session"
)

const maxUserAgentBytes = 512

// ClientInfo describes the caller as seen by the transport. IP must already be
// resolved under the trusted-proxy policy; it is a risk signal, not identity.
type ClientInfo struct {
	IP        netip.Addr
	UserAgent string
}

// Principal is an authenticated caller.
type Principal struct {
	UserID    uuid.UUID
	SessionID uuid.UUID
	DeviceID  uuid.UUID
}

type RegisterRequest struct {
	Email       string
	Password    string
	DisplayName string
	Client      ClientInfo
}

type LoginRequest struct {
	Email    string
	Password string
	// DeviceToken is the token returned by an earlier login on this device; empty for a new device.
	DeviceToken string
	// DeviceName is an optional display label, used only when a new device is created.
	DeviceName string
	Client     ClientInfo
}

// AuthResult carries newly issued secrets. Return them to the client once;
// go-ima stores only their digests.
type AuthResult struct {
	User             identity.User
	SessionID        uuid.UUID
	AccessToken      string
	AccessExpiresAt  time.Time
	RefreshToken     string
	RefreshExpiresAt time.Time
	// DeviceToken is set only when a new device was registered by this login.
	DeviceToken string
}

// SessionInfo is one entry of "where you're logged in".
type SessionInfo struct {
	session.Session
	DeviceName string
	Current    bool
}

type Service struct {
	o         Options
	dummyHash string
}

func New(opts Options) (*Service, error) {
	if err := opts.normalize(); err != nil {
		return nil, err
	}
	// A hash of a random secret lets unknown-email logins cost the same as real ones.
	secret := make([]byte, 16)
	if _, err := rand.Read(secret); err != nil {
		return nil, err
	}
	dummy, err := opts.Hasher.Hash(hex.EncodeToString(secret))
	if err != nil {
		return nil, fmt.Errorf("ima: dummy hash: %w", err)
	}
	return &Service{o: opts, dummyHash: dummy}, nil
}

func (s *Service) now() time.Time { return s.o.Now().UTC().Truncate(time.Microsecond) }

func (s *Service) allow(ctx context.Context, action string, keys ...string) error {
	if s.o.Limiter == nil {
		return nil
	}
	if err := s.o.Limiter.Allow(ctx, action, keys...); err != nil {
		if errors.Is(err, ErrRateLimited) {
			return ErrRateLimited
		}
		return fmt.Errorf("ima: rate limiter: %w", err)
	}
	return nil
}

func ipKey(c ClientInfo) string {
	if !c.IP.IsValid() {
		return "ip:unknown"
	}
	if c.IP.Is4() || c.IP.Is4In6() {
		return "ip:" + c.IP.Unmap().String()
	}
	p, _ := c.IP.Prefix(64) // IPv6 clients control their /64
	return "ip:" + p.String()
}

func truncateUA(ua string) string {
	if len(ua) <= maxUserAgentBytes {
		return ua
	}
	return strings.ToValidUTF8(ua[:maxUserAgentBytes], "")
}

// Register creates an active password account.
func (s *Service) Register(ctx context.Context, req RegisterRequest) (identity.User, error) {
	email, err := identity.NormalizeEmail(req.Email)
	if err != nil {
		return identity.User{}, fmt.Errorf("%w: email", ErrInvalidInput)
	}
	name, err := identity.ValidateDisplayName(req.DisplayName)
	if err != nil {
		return identity.User{}, fmt.Errorf("%w: display name", ErrInvalidInput)
	}
	if err := auth.ValidatePassword(req.Password); err != nil {
		return identity.User{}, fmt.Errorf("%w: password", ErrInvalidInput)
	}
	if err := s.allow(ctx, ActionRegister, ipKey(req.Client)); err != nil {
		return identity.User{}, err
	}
	hash, err := s.o.Hasher.Hash(req.Password)
	if err != nil {
		return identity.User{}, fmt.Errorf("ima: hash password: %w", err)
	}
	now := s.now()
	u := identity.User{ID: uuid.New(), Email: strings.TrimSpace(req.Email), DisplayName: name,
		Status: identity.StatusActive, CreatedAt: now, UpdatedAt: now}
	err = s.o.Tx.InTx(ctx, func(ctx context.Context) error {
		if err := s.o.Users.Create(ctx, u, email, hash); err != nil {
			return err
		}
		return s.o.Audit.Record(ctx, audit.Event{Type: audit.UserRegistered, UserID: u.ID, IP: req.Client.IP, OccurredAt: now})
	})
	if errors.Is(err, identity.ErrEmailTaken) {
		return identity.User{}, ErrEmailUnavailable
	}
	if err != nil {
		return identity.User{}, err
	}
	return u, nil
}

// Login verifies a password and opens a session on a new or known device.
func (s *Service) Login(ctx context.Context, req LoginRequest) (AuthResult, error) {
	email, emailErr := identity.NormalizeEmail(req.Email)
	keys := []string{ipKey(req.Client)}
	if emailErr == nil {
		keys = append(keys, "email:"+email)
	}
	if err := s.allow(ctx, ActionLogin, keys...); err != nil {
		return AuthResult{}, err
	}
	var (
		u    identity.User
		hash = s.dummyHash
		err  error
	)
	found := false
	if emailErr == nil && len(req.Password) <= auth.MaxPasswordBytes {
		u, hash, err = s.o.Users.ByEmail(ctx, email)
		switch {
		case err == nil:
			found = true
		case errors.Is(err, identity.ErrNotFound):
			hash = s.dummyHash
		default:
			return AuthResult{}, err
		}
	}
	ok, verr := s.o.Hasher.Verify(truncatePassword(req.Password), hash)
	if verr != nil && found {
		s.o.Logger.ErrorContext(ctx, "stored password hash is malformed", "user_id", u.ID)
	}
	now := s.now()
	if !found || !ok || verr != nil || u.Status != identity.StatusActive {
		reason := "bad_password"
		switch {
		case !found:
			reason = "unknown_account"
		case ok && u.Status != identity.StatusActive:
			reason = "account_disabled"
		}
		if err := s.o.Audit.Record(ctx, audit.Event{Type: audit.LoginFailed, UserID: u.ID, IP: req.Client.IP,
			OccurredAt: now, Metadata: map[string]string{"reason": reason}}); err != nil {
			return AuthResult{}, err
		}
		return AuthResult{}, ErrInvalidCredentials
	}

	var res AuthResult
	err = s.o.Tx.InTx(ctx, func(ctx context.Context) error {
		dev, newToken, err := s.resolveDevice(ctx, u.ID, req, now)
		if err != nil {
			return err
		}
		res, err = s.openSession(ctx, u, dev.ID, req.Client, now)
		if err != nil {
			return err
		}
		res.DeviceToken = newToken
		if s.o.Hasher.NeedsRehash(hash) {
			if h, err := s.o.Hasher.Hash(req.Password); err == nil {
				if err := s.o.Users.UpdatePasswordHash(ctx, u.ID, h, now); err != nil {
					return err
				}
			}
		}
		return s.o.Audit.Record(ctx, audit.Event{Type: audit.LoginSucceeded, UserID: u.ID, SessionID: res.SessionID,
			IP: req.Client.IP, OccurredAt: now, Metadata: map[string]string{"device_id": dev.ID.String()}})
	})
	if err != nil {
		return AuthResult{}, err
	}
	return res, nil
}

// truncatePassword keeps oversized input from reaching the hasher at full size;
// such input can never match because ValidatePassword rejects it at registration.
func truncatePassword(pw string) string {
	if len(pw) > auth.MaxPasswordBytes {
		return pw[:auth.MaxPasswordBytes]
	}
	return pw
}

func (s *Service) resolveDevice(ctx context.Context, userID uuid.UUID, req LoginRequest, now time.Time) (device.Device, string, error) {
	if req.DeviceToken != "" {
		if h, err := session.HashToken(session.KindDevice, req.DeviceToken); err == nil {
			d, err := s.o.Devices.ByToken(ctx, userID, h)
			if err == nil {
				return d, "", s.o.Devices.Touch(ctx, d.ID, now)
			}
			if !errors.Is(err, device.ErrNotFound) {
				return device.Device{}, "", err
			}
		}
	}
	plain, h, err := session.NewToken(session.KindDevice)
	if err != nil {
		return device.Device{}, "", err
	}
	d := device.Device{ID: uuid.New(), UserID: userID, Name: device.SanitizeName(req.DeviceName), CreatedAt: now, LastSeenAt: now}
	if err := s.o.Devices.Create(ctx, d, h); err != nil {
		return device.Device{}, "", err
	}
	if err := s.o.Audit.Record(ctx, audit.Event{Type: audit.DeviceRegistered, UserID: userID, IP: req.Client.IP, OccurredAt: now,
		Metadata: map[string]string{"device_id": d.ID.String()}}); err != nil {
		return device.Device{}, "", err
	}
	return d, plain, nil
}

func minTime(a, b time.Time) time.Time {
	if a.Before(b) {
		return a
	}
	return b
}

func (s *Service) openSession(ctx context.Context, u identity.User, deviceID uuid.UUID, c ClientInfo, now time.Time) (AuthResult, error) {
	access, accessHash, err := session.NewToken(session.KindAccess)
	if err != nil {
		return AuthResult{}, err
	}
	refresh, refreshHash, err := session.NewToken(session.KindRefresh)
	if err != nil {
		return AuthResult{}, err
	}
	expires := now.Add(s.o.SessionMaxAge)
	sess := session.Session{ID: uuid.New(), UserID: u.ID, DeviceID: deviceID, CreatedAt: now, LastActiveAt: now,
		ExpiresAt: expires, AccessExpiresAt: minTime(now.Add(s.o.AccessTTL), expires), CreatedIP: c.IP, LastIP: c.IP,
		UserAgent: truncateUA(c.UserAgent)}
	refreshExp := minTime(now.Add(s.o.RefreshTTL), expires)
	if err := s.o.Sessions.Create(ctx, sess, accessHash, refreshHash, refreshExp); err != nil {
		return AuthResult{}, err
	}
	return AuthResult{User: u, SessionID: sess.ID, AccessToken: access, AccessExpiresAt: sess.AccessExpiresAt,
		RefreshToken: refresh, RefreshExpiresAt: refreshExp}, nil
}

// Refresh exchanges a refresh token for a new access/refresh pair. Each refresh
// token works once; presenting a used one revokes the whole session.
func (s *Service) Refresh(ctx context.Context, refreshToken string, c ClientInfo) (AuthResult, error) {
	h, err := session.HashToken(session.KindRefresh, refreshToken)
	if err != nil {
		return AuthResult{}, ErrUnauthenticated
	}
	if err := s.allow(ctx, ActionRefresh, ipKey(c)); err != nil {
		return AuthResult{}, err
	}
	now := s.now()
	var (
		res    AuthResult
		replay bool
	)
	err = s.o.Tx.InTx(ctx, func(ctx context.Context) error {
		st, err := s.o.Sessions.ConsumeRefresh(ctx, h, now)
		if errors.Is(err, session.ErrNotFound) {
			return ErrUnauthenticated
		}
		if err != nil {
			return err
		}
		sess, err := s.o.Sessions.Get(ctx, st.SessionID)
		if err != nil {
			return err
		}
		if st.AlreadyUsed {
			replay = true
			if !sess.Active(now) {
				return nil
			}
			if err := s.o.Sessions.Revoke(ctx, sess.ID, now, session.ReasonReuse); err != nil {
				return err
			}
			// Commit the revocation; the caller still receives ErrUnauthenticated.
			return s.o.Audit.Record(ctx, audit.Event{Type: audit.RefreshReuseBlocked, UserID: sess.UserID, SessionID: sess.ID, IP: c.IP, OccurredAt: now})
		}
		if !sess.Active(now) {
			return ErrUnauthenticated
		}
		u, err := s.o.Users.ByID(ctx, sess.UserID)
		if err != nil {
			return err
		}
		if u.Status != identity.StatusActive {
			return ErrUnauthenticated
		}
		access, accessHash, err := session.NewToken(session.KindAccess)
		if err != nil {
			return err
		}
		refresh, refreshHash, err := session.NewToken(session.KindRefresh)
		if err != nil {
			return err
		}
		accessExp := minTime(now.Add(s.o.AccessTTL), sess.ExpiresAt)
		refreshExp := minTime(now.Add(s.o.RefreshTTL), sess.ExpiresAt)
		if err := s.o.Sessions.Rotate(ctx, sess.ID, accessHash, accessExp, refreshHash, refreshExp, now, c.IP); err != nil {
			if errors.Is(err, session.ErrNotFound) {
				return ErrUnauthenticated
			}
			return err
		}
		res = AuthResult{User: u, SessionID: sess.ID, AccessToken: access, AccessExpiresAt: accessExp,
			RefreshToken: refresh, RefreshExpiresAt: refreshExp}
		return s.o.Audit.Record(ctx, audit.Event{Type: audit.TokenRefreshed, UserID: u.ID, SessionID: sess.ID, IP: c.IP, OccurredAt: now})
	})
	if err != nil {
		return AuthResult{}, err
	}
	if replay {
		return AuthResult{}, ErrUnauthenticated
	}
	return res, nil
}

// Authenticate resolves an access token to a Principal and records activity.
func (s *Service) Authenticate(ctx context.Context, accessToken string, c ClientInfo) (Principal, error) {
	h, err := session.HashToken(session.KindAccess, accessToken)
	if err != nil {
		return Principal{}, ErrUnauthenticated
	}
	now := s.now()
	sess, err := s.o.Sessions.ByAccessHash(ctx, h, now)
	if errors.Is(err, session.ErrNotFound) {
		return Principal{}, ErrUnauthenticated
	}
	if err != nil {
		return Principal{}, err
	}
	u, err := s.o.Users.ByID(ctx, sess.UserID)
	if errors.Is(err, identity.ErrNotFound) || (err == nil && u.Status != identity.StatusActive) {
		return Principal{}, ErrUnauthenticated
	}
	if err != nil {
		return Principal{}, err
	}
	if err := s.o.Sessions.Touch(ctx, sess.ID, now, c.IP, s.o.TouchInterval); err != nil {
		return Principal{}, err
	}
	return Principal{UserID: sess.UserID, SessionID: sess.ID, DeviceID: sess.DeviceID}, nil
}

// CurrentUser returns the principal's account.
func (s *Service) CurrentUser(ctx context.Context, p Principal) (identity.User, error) {
	u, err := s.o.Users.ByID(ctx, p.UserID)
	if errors.Is(err, identity.ErrNotFound) {
		return identity.User{}, ErrUnauthenticated
	}
	return u, err
}

// Logout revokes the principal's current session.
func (s *Service) Logout(ctx context.Context, p Principal, c ClientInfo) error {
	return s.revoke(ctx, p, p.SessionID, session.ReasonLogout, c)
}

// RevokeSession signs out one of the principal's own sessions.
func (s *Service) RevokeSession(ctx context.Context, p Principal, id uuid.UUID, c ClientInfo) error {
	return s.revoke(ctx, p, id, session.ReasonUserRevoked, c)
}

func (s *Service) revoke(ctx context.Context, p Principal, id uuid.UUID, reason string, c ClientInfo) error {
	now := s.now()
	return s.o.Tx.InTx(ctx, func(ctx context.Context) error {
		sess, err := s.o.Sessions.Get(ctx, id)
		if errors.Is(err, session.ErrNotFound) || (err == nil && sess.UserID != p.UserID) {
			return ErrNotFound // never reveal other users' sessions
		}
		if err != nil {
			return err
		}
		if sess.RevokedAt != nil {
			return nil
		}
		if err := s.o.Sessions.Revoke(ctx, id, now, reason); err != nil {
			return err
		}
		return s.o.Audit.Record(ctx, audit.Event{Type: audit.SessionRevoked, UserID: p.UserID, SessionID: id, IP: c.IP,
			OccurredAt: now, Metadata: map[string]string{"reason": reason}})
	})
}

// RevokeOtherSessions signs out every session except the current one.
func (s *Service) RevokeOtherSessions(ctx context.Context, p Principal, c ClientInfo) (int, error) {
	now := s.now()
	var n int
	err := s.o.Tx.InTx(ctx, func(ctx context.Context) error {
		var err error
		n, err = s.o.Sessions.RevokeOthers(ctx, p.UserID, p.SessionID, now, session.ReasonOtherRevoked)
		if err != nil || n == 0 {
			return err
		}
		return s.o.Audit.Record(ctx, audit.Event{Type: audit.SessionRevoked, UserID: p.UserID, SessionID: p.SessionID, IP: c.IP,
			OccurredAt: now, Metadata: map[string]string{"reason": session.ReasonOtherRevoked, "count": fmt.Sprint(n)}})
	})
	return n, err
}

// ListSessions returns the principal's active sessions with device labels.
func (s *Service) ListSessions(ctx context.Context, p Principal) ([]SessionInfo, error) {
	now := s.now()
	sessions, err := s.o.Sessions.ListActive(ctx, p.UserID, now)
	if err != nil {
		return nil, err
	}
	devices, err := s.o.Devices.ListByUser(ctx, p.UserID)
	if err != nil {
		return nil, err
	}
	names := make(map[uuid.UUID]string, len(devices))
	for _, d := range devices {
		names[d.ID] = d.Name
	}
	out := make([]SessionInfo, 0, len(sessions))
	for _, sess := range sessions {
		out = append(out, SessionInfo{Session: sess, DeviceName: names[sess.DeviceID], Current: sess.ID == p.SessionID})
	}
	return out, nil
}
