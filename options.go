package ima

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"github.com/ninepeach/go-ima/audit"
	"github.com/ninepeach/go-ima/auth"
	"github.com/ninepeach/go-ima/device"
	"github.com/ninepeach/go-ima/identity"
	"github.com/ninepeach/go-ima/session"
)

// TxRunner runs fn in one transaction; repositories called with fn's ctx join it.
type TxRunner interface {
	InTx(ctx context.Context, fn func(ctx context.Context) error) error
}

// Repositories is the storage a Service needs. storage/postgres.Store provides all of them.
type Repositories struct {
	Tx       TxRunner
	Users    identity.Repository
	Sessions session.Repository
	Devices  device.Repository
	Audit    audit.Recorder
}

// PasswordHasher is satisfied by *auth.Hasher.
type PasswordHasher interface {
	Hash(password string) (string, error)
	Verify(password, encoded string) (bool, error)
	NeedsRehash(encoded string) bool
}

// Limiter throttles an action for a set of keys (for example "ip:203.0.113.7",
// "email:<normalized>"). It returns ErrRateLimited (or an error wrapping it)
// when any key is over its limit. A nil Limiter disables throttling, which is
// acceptable only in tests: production deployments must provide one backed by
// shared state when running more than one instance.
type Limiter interface {
	Allow(ctx context.Context, action string, keys ...string) error
}

// Rate-limited actions.
const (
	ActionRegister = "register"
	ActionLogin    = "login"
	ActionRefresh  = "refresh"
)

type Options struct {
	Repositories
	// Hasher defaults to auth.DefaultParams Argon2id.
	Hasher  PasswordHasher
	Limiter Limiter
	// Now defaults to time.Now.
	Now    func() time.Time
	Logger *slog.Logger

	AccessTTL     time.Duration // default 15m
	RefreshTTL    time.Duration // idle refresh lifetime, default 30 days
	SessionMaxAge time.Duration // absolute session lifetime, default 90 days
	TouchInterval time.Duration // min interval between last-active writes, default 1m
}

func (o *Options) normalize() error {
	if o.Tx == nil || o.Users == nil || o.Sessions == nil || o.Devices == nil || o.Audit == nil {
		return errors.New("ima: all repositories are required")
	}
	if o.Hasher == nil {
		h, err := auth.NewHasher(auth.DefaultParams)
		if err != nil {
			return err
		}
		o.Hasher = h
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	if o.Logger == nil {
		o.Logger = slog.New(slog.DiscardHandler)
	}
	def := func(d *time.Duration, v time.Duration) {
		if *d == 0 {
			*d = v
		}
	}
	def(&o.AccessTTL, 15*time.Minute)
	def(&o.RefreshTTL, 30*24*time.Hour)
	def(&o.SessionMaxAge, 90*24*time.Hour)
	def(&o.TouchInterval, time.Minute)
	if o.AccessTTL < 0 || o.RefreshTTL < 0 || o.SessionMaxAge < 0 || o.TouchInterval < 0 {
		return errors.New("ima: durations must not be negative")
	}
	if o.AccessTTL > o.RefreshTTL || o.RefreshTTL > o.SessionMaxAge {
		return errors.New("ima: require AccessTTL <= RefreshTTL <= SessionMaxAge")
	}
	return nil
}
