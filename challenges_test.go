package ima_test

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	ima "github.com/ninepeach/go-ima"
)

func TestEmailVerificationLifecycle(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	e.register(t, "ann@example.com")

	first, err := e.svc.RequestEmailVerification(ctx, "Ann@Example.com", client)
	if err != nil {
		t.Fatal(err)
	}
	second, err := e.svc.RequestEmailVerification(ctx, "ann@example.com", client)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.VerifyEmail(ctx, first.Token, client); !errors.Is(err, ima.ErrInvalidToken) {
		t.Fatalf("superseded token: want ErrInvalidToken, got %v", err)
	}
	u, err := e.svc.VerifyEmail(ctx, second.Token, client)
	if err != nil {
		t.Fatal(err)
	}
	if u.EmailVerifiedAt == nil {
		t.Fatal("email not marked verified")
	}
	if _, err := e.svc.VerifyEmail(ctx, second.Token, client); !errors.Is(err, ima.ErrInvalidToken) {
		t.Fatalf("reused token: want ErrInvalidToken, got %v", err)
	}
	// Verified accounts get no new challenge; the transport must hide this.
	if _, err := e.svc.RequestEmailVerification(ctx, "ann@example.com", client); !errors.Is(err, ima.ErrNotFound) {
		t.Fatalf("verified account: want ErrNotFound, got %v", err)
	}
	if res := e.login(t, "ann@example.com", ""); res.User.EmailVerifiedAt == nil {
		t.Fatal("login does not report verified email")
	}
	if n := e.auditCount(t, "email.verified"); n != 1 {
		t.Fatalf("email.verified events = %d", n)
	}
}

func TestChallengeRejectsUnknownMalformedExpiredAndWrongPurpose(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	e.register(t, "bo@example.com")
	if _, err := e.svc.RequestEmailVerification(ctx, "nobody@example.com", client); !errors.Is(err, ima.ErrNotFound) {
		t.Fatalf("unknown email: want ErrNotFound, got %v", err)
	}
	if _, err := e.svc.RequestPasswordReset(ctx, "not an email", client); !errors.Is(err, ima.ErrInvalidInput) {
		t.Fatalf("malformed email: want ErrInvalidInput, got %v", err)
	}
	for _, tok := range []string{"", "garbage", "ima_ve_short"} {
		if _, err := e.svc.VerifyEmail(ctx, tok, client); !errors.Is(err, ima.ErrInvalidToken) {
			t.Fatalf("token %q: want ErrInvalidToken, got %v", tok, err)
		}
	}
	reset, err := e.svc.RequestPasswordReset(ctx, "bo@example.com", client)
	if err != nil {
		t.Fatal(err)
	}
	// A reset token must not verify an email, even though both are challenges.
	if _, err := e.svc.VerifyEmail(ctx, reset.Token, client); !errors.Is(err, ima.ErrInvalidToken) {
		t.Fatalf("wrong purpose: want ErrInvalidToken, got %v", err)
	}
	ver, err := e.svc.RequestEmailVerification(ctx, "bo@example.com", client)
	if err != nil {
		t.Fatal(err)
	}
	e.clock.Add(24*time.Hour + time.Second)
	if _, err := e.svc.VerifyEmail(ctx, ver.Token, client); !errors.Is(err, ima.ErrInvalidToken) {
		t.Fatalf("expired verification: want ErrInvalidToken, got %v", err)
	}
	if err := e.svc.ResetPassword(ctx, reset.Token, "another long password", client); !errors.Is(err, ima.ErrInvalidToken) {
		t.Fatalf("expired reset: want ErrInvalidToken, got %v", err)
	}
}

func TestPasswordResetRevokesSessionsAndVerifiesEmail(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	e.register(t, "cy@example.com")
	old := e.login(t, "cy@example.com", "")

	reset, err := e.svc.RequestPasswordReset(ctx, "cy@example.com", client)
	if err != nil {
		t.Fatal(err)
	}
	if err := e.svc.ResetPassword(ctx, reset.Token, "short", client); !errors.Is(err, ima.ErrInvalidInput) {
		t.Fatalf("weak password: want ErrInvalidInput, got %v", err)
	}
	const newPassword = "a brand new passphrase"
	if err := e.svc.ResetPassword(ctx, reset.Token, newPassword, client); err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.Authenticate(ctx, old.AccessToken, client); !errors.Is(err, ima.ErrUnauthenticated) {
		t.Fatalf("session survived reset: %v", err)
	}
	if _, err := e.svc.Login(ctx, ima.LoginRequest{Email: "cy@example.com", Password: password, Client: client}); !errors.Is(err, ima.ErrInvalidCredentials) {
		t.Fatalf("old password still works: %v", err)
	}
	res, err := e.svc.Login(ctx, ima.LoginRequest{Email: "cy@example.com", Password: newPassword, Client: client})
	if err != nil {
		t.Fatal(err)
	}
	if res.User.EmailVerifiedAt == nil {
		t.Fatal("reset did not verify email")
	}
	if err := e.svc.ResetPassword(ctx, reset.Token, "yet another passphrase", client); !errors.Is(err, ima.ErrInvalidToken) {
		t.Fatalf("reused reset token: want ErrInvalidToken, got %v", err)
	}
}

func TestConcurrentChallengeConsumeSucceedsAtMostOnce(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	e.register(t, "di@example.com")
	ver, err := e.svc.RequestEmailVerification(ctx, "di@example.com", client)
	if err != nil {
		t.Fatal(err)
	}
	var ok atomic.Int32
	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := e.svc.VerifyEmail(ctx, ver.Token, client)
			switch {
			case err == nil:
				ok.Add(1)
			case !errors.Is(err, ima.ErrInvalidToken):
				t.Errorf("unexpected error: %v", err)
			}
		}()
	}
	wg.Wait()
	if ok.Load() != 1 {
		t.Fatalf("successful consumes = %d, want 1", ok.Load())
	}
}

func TestChallengeRequestsAreRateLimited(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	e.register(t, "ed@example.com")
	e.lim.deny.Store(true)
	if _, err := e.svc.RequestPasswordReset(ctx, "ed@example.com", client); !errors.Is(err, ima.ErrRateLimited) {
		t.Fatalf("want ErrRateLimited, got %v", err)
	}
	if _, err := e.svc.VerifyEmail(ctx, "ima_ve_x", client); !errors.Is(err, ima.ErrRateLimited) {
		t.Fatalf("consume: want ErrRateLimited, got %v", err)
	}
	if n := e.auditCount(t, "password.reset_issued"); n != 0 {
		t.Fatalf("rate-limited request issued a challenge")
	}
}
