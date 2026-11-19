package ima_test

import (
	"context"
	"errors"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	ima "github.com/ninepeach/go-ima"
	"github.com/ninepeach/go-ima/auth"
	"github.com/ninepeach/go-ima/internal/testdb"
	imapg "github.com/ninepeach/go-ima/storage/postgres"
)

type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) Now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *clock) Add(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

type recordingLimiter struct {
	mu    sync.Mutex
	calls []string
	deny  atomic.Bool
}

func (l *recordingLimiter) Allow(_ context.Context, action string, keys ...string) error {
	l.mu.Lock()
	l.calls = append(l.calls, action+"|"+join(keys))
	l.mu.Unlock()
	if l.deny.Load() {
		return ima.ErrRateLimited
	}
	return nil
}

func join(s []string) string {
	out := ""
	for i, k := range s {
		if i > 0 {
			out += ","
		}
		out += k
	}
	return out
}

type env struct {
	svc   *ima.Service
	pool  *pgxpool.Pool
	clock *clock
	lim   *recordingLimiter
}

var fastHash = auth.Params{Memory: 64, Time: 1, Threads: 1, SaltLen: 16, KeyLen: 32}

func newEnv(t *testing.T) *env {
	t.Helper()
	pool := testdb.New(t, false)
	store, err := imapg.New(pool)
	if err != nil {
		t.Fatal(err)
	}
	h, _ := auth.NewHasher(fastHash)
	c := &clock{t: time.Date(2026, 11, 19, 8, 0, 0, 0, time.UTC)}
	lim := &recordingLimiter{}
	svc, err := ima.New(ima.Options{Repositories: store.Repositories(), Hasher: h, Now: c.Now, Limiter: lim,
		AccessTTL: 15 * time.Minute, RefreshTTL: 24 * time.Hour, SessionMaxAge: 72 * time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	return &env{svc: svc, pool: pool, clock: c, lim: lim}
}

var client = ima.ClientInfo{IP: netip.MustParseAddr("203.0.113.7"), UserAgent: "test-agent"}

const password = "correct horse battery"

func (e *env) register(t *testing.T, email string) {
	t.Helper()
	if _, err := e.svc.Register(context.Background(), ima.RegisterRequest{Email: email, Password: password, Client: client}); err != nil {
		t.Fatal(err)
	}
}

func (e *env) login(t *testing.T, email, deviceToken string) ima.AuthResult {
	t.Helper()
	res, err := e.svc.Login(context.Background(), ima.LoginRequest{Email: email, Password: password, DeviceToken: deviceToken, DeviceName: "Laptop", Client: client})
	if err != nil {
		t.Fatal(err)
	}
	return res
}

func (e *env) auditCount(t *testing.T, typ string) int {
	t.Helper()
	var n int
	if err := e.pool.QueryRow(context.Background(), `SELECT count(*) FROM ima_audit_events WHERE type = $1`, typ).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func TestRegisterLoginAuthenticate(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	e.register(t, "Alice@Example.com")
	if _, err := e.svc.Register(ctx, ima.RegisterRequest{Email: "alice@example.COM", Password: password, Client: client}); !errors.Is(err, ima.ErrEmailUnavailable) {
		t.Fatalf("duplicate: %v", err)
	}
	res := e.login(t, "  alice@example.com", "")
	if res.DeviceToken == "" || res.AccessToken == "" || res.RefreshToken == "" {
		t.Fatal("login must issue access, refresh and device tokens")
	}
	if !res.AccessExpiresAt.Equal(e.clock.Now().Add(15 * time.Minute)) {
		t.Fatalf("access expiry %v", res.AccessExpiresAt)
	}
	p, err := e.svc.Authenticate(ctx, res.AccessToken, client)
	if err != nil || p.SessionID != res.SessionID {
		t.Fatalf("authenticate: %+v %v", p, err)
	}
	u, err := e.svc.CurrentUser(ctx, p)
	if err != nil || u.Email != "Alice@Example.com" {
		t.Fatalf("current user: %+v %v", u, err)
	}
	if e.auditCount(t, "user.registered") != 1 || e.auditCount(t, "login.succeeded") != 1 || e.auditCount(t, "device.registered") != 1 {
		t.Fatal("missing audit events")
	}
}

func TestRegisterValidation(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	for _, req := range []ima.RegisterRequest{
		{Email: "not-an-email", Password: password},
		{Email: "a@example.com", Password: "short"},
		{Email: "a@example.com", Password: password, DisplayName: "bad\nname"},
	} {
		if _, err := e.svc.Register(ctx, req); !errors.Is(err, ima.ErrInvalidInput) {
			t.Errorf("%+v: want ErrInvalidInput, got %v", req, err)
		}
	}
}

func TestLoginFailuresAreIndistinguishable(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	e.register(t, "bob@example.com")
	if _, err := e.pool.Exec(ctx, `INSERT INTO ima_users (id, email, email_normalized, status, created_at, updated_at)
        VALUES ($1, 'off@example.com', 'off@example.com', 'disabled', now(), now())`, uuid.New()); err != nil {
		t.Fatal(err)
	}
	for _, req := range []ima.LoginRequest{
		{Email: "bob@example.com", Password: "wrong password here"},
		{Email: "nobody@example.com", Password: password},
		{Email: "garbage", Password: password},
		{Email: "bob@example.com", Password: string(make([]byte, 10_000))},
	} {
		req.Client = client
		if _, err := e.svc.Login(ctx, req); !errors.Is(err, ima.ErrInvalidCredentials) {
			t.Errorf("%s: want ErrInvalidCredentials, got %v", req.Email, err)
		}
	}
	if n := e.auditCount(t, "login.failed"); n != 4 {
		t.Fatalf("want 4 login.failed events, got %d", n)
	}
}

func TestDisabledAccountCannotLogin(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	e.register(t, "carol@example.com")
	res := e.login(t, "carol@example.com", "")
	if _, err := e.pool.Exec(ctx, `UPDATE ima_users SET status = 'disabled'`); err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.Login(ctx, ima.LoginRequest{Email: "carol@example.com", Password: password, Client: client}); !errors.Is(err, ima.ErrInvalidCredentials) {
		t.Fatalf("disabled login: %v", err)
	}
	if _, err := e.svc.Authenticate(ctx, res.AccessToken, client); !errors.Is(err, ima.ErrUnauthenticated) {
		t.Fatalf("disabled access token: %v", err)
	}
	if _, err := e.svc.Refresh(ctx, res.RefreshToken, client); !errors.Is(err, ima.ErrUnauthenticated) {
		t.Fatalf("disabled refresh: %v", err)
	}
}

func TestRefreshRotationAndReplayRevokesSession(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	e.register(t, "dave@example.com")
	first := e.login(t, "dave@example.com", "")
	e.clock.Add(time.Minute)
	second, err := e.svc.Refresh(ctx, first.RefreshToken, client)
	if err != nil {
		t.Fatal(err)
	}
	if second.SessionID != first.SessionID || second.RefreshToken == first.RefreshToken || second.AccessToken == first.AccessToken {
		t.Fatal("refresh must rotate both tokens within the same session")
	}
	if _, err := e.svc.Authenticate(ctx, first.AccessToken, client); !errors.Is(err, ima.ErrUnauthenticated) {
		t.Fatal("previous access token must stop working after rotation")
	}
	// Replaying the consumed refresh token is treated as theft.
	if _, err := e.svc.Refresh(ctx, first.RefreshToken, client); !errors.Is(err, ima.ErrUnauthenticated) {
		t.Fatalf("replay: %v", err)
	}
	if _, err := e.svc.Authenticate(ctx, second.AccessToken, client); !errors.Is(err, ima.ErrUnauthenticated) {
		t.Fatal("replay must revoke the whole session")
	}
	if _, err := e.svc.Refresh(ctx, second.RefreshToken, client); !errors.Is(err, ima.ErrUnauthenticated) {
		t.Fatal("tokens of a revoked session must not refresh")
	}
	if e.auditCount(t, "token.refresh_reuse") != 1 {
		t.Fatal("reuse must be audited")
	}
	for _, bad := range []string{"", "ima_rt_short", first.AccessToken} {
		if _, err := e.svc.Refresh(ctx, bad, client); !errors.Is(err, ima.ErrUnauthenticated) {
			t.Errorf("%q: %v", bad, err)
		}
	}
}

func TestConcurrentRefreshSucceedsAtMostOnce(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	e.register(t, "erin@example.com")
	res := e.login(t, "erin@example.com", "")
	const n = 8
	var wins atomic.Int32
	var wg sync.WaitGroup
	for range n {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := e.svc.Refresh(ctx, res.RefreshToken, client)
			if err == nil {
				wins.Add(1)
			} else if !errors.Is(err, ima.ErrUnauthenticated) {
				t.Errorf("unexpected error: %v", err)
			}
		}()
	}
	wg.Wait()
	if wins.Load() > 1 {
		t.Fatalf("%d concurrent refreshes succeeded", wins.Load())
	}
	var revoked bool
	if err := e.pool.QueryRow(ctx, `SELECT revoked_at IS NOT NULL FROM ima_sessions WHERE id = $1`, res.SessionID).Scan(&revoked); err != nil {
		t.Fatal(err)
	}
	if !revoked {
		t.Fatal("concurrent reuse must revoke the session")
	}
}

func TestExpiry(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	e.register(t, "frank@example.com")
	res := e.login(t, "frank@example.com", "")
	e.clock.Add(16 * time.Minute)
	if _, err := e.svc.Authenticate(ctx, res.AccessToken, client); !errors.Is(err, ima.ErrUnauthenticated) {
		t.Fatal("expired access token accepted")
	}
	cur := res
	// Refresh every 20h: idle limit (24h) is respected, but the 72h absolute lifetime still ends the session.
	for i := 0; ; i++ {
		next, err := e.svc.Refresh(ctx, cur.RefreshToken, client)
		if err != nil {
			if !errors.Is(err, ima.ErrUnauthenticated) {
				t.Fatal(err)
			}
			if i < 3 {
				t.Fatalf("session ended too early after %d refreshes", i)
			}
			break
		}
		if next.RefreshExpiresAt.After(res.AccessExpiresAt.Add(-15 * time.Minute).Add(72 * time.Hour)) {
			t.Fatal("refresh token outlives the session")
		}
		cur = next
		e.clock.Add(20 * time.Hour)
		if i > 5 {
			t.Fatal("session never expired")
		}
	}
	// An idle refresh token expires on its own.
	res2 := e.login(t, "frank@example.com", "")
	e.clock.Add(25 * time.Hour)
	if _, err := e.svc.Refresh(ctx, res2.RefreshToken, client); !errors.Is(err, ima.ErrUnauthenticated) {
		t.Fatal("idle refresh token accepted")
	}
}

func TestDevicesAndSessionManagement(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	e.register(t, "gina@example.com")
	e.register(t, "hank@example.com")
	a := e.login(t, "gina@example.com", "")
	b := e.login(t, "gina@example.com", a.DeviceToken)
	if b.DeviceToken != "" {
		t.Fatal("known device must not get a new device token")
	}
	c := e.login(t, "gina@example.com", "ima_dt_forged")
	if c.DeviceToken == "" {
		t.Fatal("unknown device token must create a new device")
	}
	other := e.login(t, "hank@example.com", "")
	// Another user's device token never binds to this account.
	d := e.login(t, "gina@example.com", other.DeviceToken)
	if d.DeviceToken == "" {
		t.Fatal("foreign device token must not be accepted")
	}

	pa, _ := e.svc.Authenticate(ctx, a.AccessToken, client)
	list, err := e.svc.ListSessions(ctx, pa)
	if err != nil || len(list) != 4 { // a, b (same device), c, d
		t.Fatalf("sessions: %d %v", len(list), err)
	}
	current, sameDevice := 0, 0
	for _, s := range list {
		if s.Current {
			current++
		}
		if s.DeviceID == pa.DeviceID {
			sameDevice++
			if s.DeviceName != "Laptop" {
				t.Fatalf("device name %q", s.DeviceName)
			}
		}
		if s.CreatedIP != client.IP {
			t.Fatalf("ip %v", s.CreatedIP)
		}
	}
	if current != 1 || sameDevice != 2 {
		t.Fatalf("current=%d sameDevice=%d", current, sameDevice)
	}

	ph, _ := e.svc.Authenticate(ctx, other.AccessToken, client)
	if err := e.svc.RevokeSession(ctx, ph, b.SessionID, client); !errors.Is(err, ima.ErrNotFound) {
		t.Fatalf("revoking another user's session: %v", err)
	}
	if err := e.svc.RevokeSession(ctx, pa, b.SessionID, client); err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.Authenticate(ctx, b.AccessToken, client); !errors.Is(err, ima.ErrUnauthenticated) {
		t.Fatal("revoked session still authenticates")
	}
	n, err := e.svc.RevokeOtherSessions(ctx, pa, client)
	if err != nil || n != 2 { // c and d; b is already revoked
		t.Fatalf("revoke others: %d %v", n, err)
	}
	if _, err := e.svc.Authenticate(ctx, a.AccessToken, client); err != nil {
		t.Fatal("current session must survive revoke-others")
	}
	if _, err := e.svc.Authenticate(ctx, other.AccessToken, client); err != nil {
		t.Fatal("other users must be unaffected")
	}
	if err := e.svc.Logout(ctx, pa, client); err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.Authenticate(ctx, a.AccessToken, client); !errors.Is(err, ima.ErrUnauthenticated) {
		t.Fatal("logged out session still authenticates")
	}
	if err := e.svc.Logout(ctx, pa, client); err != nil {
		t.Fatalf("logout must be idempotent: %v", err)
	}
}

func TestLastActiveIsThrottled(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	e.register(t, "ivy@example.com")
	res := e.login(t, "ivy@example.com", "")
	read := func() time.Time {
		var at time.Time
		if err := e.pool.QueryRow(ctx, `SELECT last_active_at FROM ima_sessions WHERE id = $1`, res.SessionID).Scan(&at); err != nil {
			t.Fatal(err)
		}
		return at.UTC()
	}
	start := read()
	e.clock.Add(30 * time.Second)
	_, _ = e.svc.Authenticate(ctx, res.AccessToken, client)
	if !read().Equal(start) {
		t.Fatal("touch within interval must not write")
	}
	e.clock.Add(time.Minute)
	_, _ = e.svc.Authenticate(ctx, res.AccessToken, client)
	if !read().Equal(e.clock.Now()) {
		t.Fatal("touch after interval must update last_active_at")
	}
}

func TestRateLimiterHook(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	e.register(t, "jill@example.com")
	v6 := ima.ClientInfo{IP: netip.MustParseAddr("2001:db8:1:2:3:4:5:6")}
	_, _ = e.svc.Login(ctx, ima.LoginRequest{Email: "Jill@example.com", Password: password, Client: v6})
	e.lim.mu.Lock()
	last := e.lim.calls[len(e.lim.calls)-1]
	e.lim.mu.Unlock()
	if last != "login|ip:2001:db8:1:2::/64,email:jill@example.com" {
		t.Fatalf("limiter keys: %s", last)
	}
	e.lim.deny.Store(true)
	if _, err := e.svc.Login(ctx, ima.LoginRequest{Email: "jill@example.com", Password: password, Client: client}); !errors.Is(err, ima.ErrRateLimited) {
		t.Fatalf("want ErrRateLimited, got %v", err)
	}
	if n := e.auditCount(t, "login.succeeded"); n != 1 {
		t.Fatalf("rate-limited login must not authenticate (succeeded=%d)", n)
	}
}

func TestNewValidatesOptions(t *testing.T) {
	if _, err := ima.New(ima.Options{}); err == nil {
		t.Fatal("missing repositories accepted")
	}
}
