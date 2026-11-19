// Package imahttp is the versioned REST transport (/v1) over ima.Service.
// It only decodes input, resolves the caller and maps errors; every rule lives
// in the Service so that embedded and standalone modes behave identically.
package imahttp

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/netip"
	"strings"
	"time"

	"github.com/google/uuid"
	ima "github.com/ninepeach/go-ima"
	"github.com/ninepeach/go-ima/identity"
)

const maxBodyBytes = 64 << 10

type Options struct {
	// TrustedProxies are the networks whose X-Forwarded-For is honored.
	TrustedProxies []netip.Prefix
	Logger         *slog.Logger
}

type handler struct {
	svc  *ima.Service
	opts Options
}

// New returns the /v1 API handler.
func New(svc *ima.Service, opts Options) http.Handler {
	if opts.Logger == nil {
		opts.Logger = slog.New(slog.DiscardHandler)
	}
	h := &handler{svc: svc, opts: opts}
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/register", h.register)
	mux.HandleFunc("POST /v1/login", h.login)
	mux.HandleFunc("POST /v1/token/refresh", h.refresh)
	mux.HandleFunc("POST /v1/logout", h.authed(h.logout))
	mux.HandleFunc("GET /v1/me", h.authed(h.me))
	mux.HandleFunc("GET /v1/sessions", h.authed(h.sessions))
	mux.HandleFunc("DELETE /v1/sessions/{id}", h.authed(h.revokeSession))
	mux.HandleFunc("POST /v1/sessions/revoke-others", h.authed(h.revokeOthers))
	mux.HandleFunc("/v1/", func(w http.ResponseWriter, r *http.Request) {
		writeError(w, http.StatusNotFound, "not_found", "resource not found")
	})
	return noStore(mux)
}

// noStore keeps tokens and account data out of shared caches.
func noStore(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		next.ServeHTTP(w, r)
	})
}

func (h *handler) client(r *http.Request) ima.ClientInfo {
	return ima.ClientInfo{IP: clientIP(r, h.opts.TrustedProxies), UserAgent: r.UserAgent()}
}

type principalKey struct{}

func (h *handler) authed(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		token, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
		if !ok || token == "" {
			w.Header().Set("WWW-Authenticate", `Bearer realm="ima"`)
			writeError(w, http.StatusUnauthorized, "unauthenticated", "authentication required")
			return
		}
		p, err := h.svc.Authenticate(r.Context(), token, h.client(r))
		if err != nil {
			if errors.Is(err, ima.ErrUnauthenticated) {
				w.Header().Set("WWW-Authenticate", `Bearer realm="ima", error="invalid_token"`)
			}
			h.fail(w, r, err)
			return
		}
		next(w, r.WithContext(context.WithValue(r.Context(), principalKey{}, p)))
	}
}

func principal(r *http.Request) ima.Principal {
	return r.Context().Value(principalKey{}).(ima.Principal)
}

func decode(w http.ResponseWriter, r *http.Request, dst any) bool {
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxBodyBytes))
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil || dec.More() {
		writeError(w, http.StatusBadRequest, "invalid_request", "malformed JSON body")
		return false
	}
	return true
}

type registerBody struct {
	Email       string `json:"email"`
	Password    string `json:"password"`
	DisplayName string `json:"display_name"`
}

func (h *handler) register(w http.ResponseWriter, r *http.Request) {
	var b registerBody
	if !decode(w, r, &b) {
		return
	}
	_, err := h.svc.Register(r.Context(), ima.RegisterRequest{Email: b.Email, Password: b.Password, DisplayName: b.DisplayName, Client: h.client(r)})
	// A taken email is answered exactly like a success to prevent enumeration.
	if err != nil && !errors.Is(err, ima.ErrEmailUnavailable) {
		h.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusAccepted, map[string]string{"status": "accepted"})
}

type loginBody struct {
	Email       string `json:"email"`
	Password    string `json:"password"`
	DeviceToken string `json:"device_token,omitempty"`
	DeviceName  string `json:"device_name,omitempty"`
}

type userJSON struct {
	ID            uuid.UUID `json:"id"`
	Email         string    `json:"email"`
	DisplayName   string    `json:"display_name"`
	EmailVerified bool      `json:"email_verified"`
	CreatedAt     time.Time `json:"created_at"`
}

func toUser(u identity.User) userJSON {
	return userJSON{ID: u.ID, Email: u.Email, DisplayName: u.DisplayName, EmailVerified: u.EmailVerifiedAt != nil, CreatedAt: u.CreatedAt}
}

type authJSON struct {
	User             userJSON  `json:"user"`
	SessionID        uuid.UUID `json:"session_id"`
	TokenType        string    `json:"token_type"`
	AccessToken      string    `json:"access_token"`
	AccessExpiresAt  time.Time `json:"access_expires_at"`
	RefreshToken     string    `json:"refresh_token"`
	RefreshExpiresAt time.Time `json:"refresh_expires_at"`
	DeviceToken      string    `json:"device_token,omitempty"`
}

func toAuth(a ima.AuthResult) authJSON {
	return authJSON{User: toUser(a.User), SessionID: a.SessionID, TokenType: "Bearer", AccessToken: a.AccessToken,
		AccessExpiresAt: a.AccessExpiresAt, RefreshToken: a.RefreshToken, RefreshExpiresAt: a.RefreshExpiresAt, DeviceToken: a.DeviceToken}
}

func (h *handler) login(w http.ResponseWriter, r *http.Request) {
	var b loginBody
	if !decode(w, r, &b) {
		return
	}
	res, err := h.svc.Login(r.Context(), ima.LoginRequest{Email: b.Email, Password: b.Password, DeviceToken: b.DeviceToken,
		DeviceName: b.DeviceName, Client: h.client(r)})
	if err != nil {
		h.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, toAuth(res))
}

func (h *handler) refresh(w http.ResponseWriter, r *http.Request) {
	var b struct {
		RefreshToken string `json:"refresh_token"`
	}
	if !decode(w, r, &b) {
		return
	}
	res, err := h.svc.Refresh(r.Context(), b.RefreshToken, h.client(r))
	if err != nil {
		h.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, toAuth(res))
}

func (h *handler) logout(w http.ResponseWriter, r *http.Request) {
	if err := h.svc.Logout(r.Context(), principal(r), h.client(r)); err != nil {
		h.fail(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *handler) me(w http.ResponseWriter, r *http.Request) {
	u, err := h.svc.CurrentUser(r.Context(), principal(r))
	if err != nil {
		h.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, toUser(u))
}

type sessionJSON struct {
	ID           uuid.UUID `json:"id"`
	DeviceID     uuid.UUID `json:"device_id"`
	DeviceName   string    `json:"device_name"`
	UserAgent    string    `json:"user_agent"`
	LastIP       string    `json:"last_ip,omitempty"`
	SignedInAt   time.Time `json:"signed_in_at"`
	LastActiveAt time.Time `json:"last_active_at"`
	ExpiresAt    time.Time `json:"expires_at"`
	Current      bool      `json:"current"`
}

func (h *handler) sessions(w http.ResponseWriter, r *http.Request) {
	list, err := h.svc.ListSessions(r.Context(), principal(r))
	if err != nil {
		h.fail(w, r, err)
		return
	}
	out := make([]sessionJSON, 0, len(list))
	for _, s := range list {
		ip := ""
		if s.LastIP.IsValid() {
			ip = s.LastIP.String()
		}
		out = append(out, sessionJSON{ID: s.ID, DeviceID: s.DeviceID, DeviceName: s.DeviceName, UserAgent: s.UserAgent, LastIP: ip,
			SignedInAt: s.CreatedAt, LastActiveAt: s.LastActiveAt, ExpiresAt: s.ExpiresAt, Current: s.Current})
	}
	writeJSON(w, http.StatusOK, map[string]any{"sessions": out})
}

func (h *handler) revokeSession(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusNotFound, "not_found", "resource not found")
		return
	}
	if err := h.svc.RevokeSession(r.Context(), principal(r), id, h.client(r)); err != nil {
		h.fail(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *handler) revokeOthers(w http.ResponseWriter, r *http.Request) {
	n, err := h.svc.RevokeOtherSessions(r.Context(), principal(r), h.client(r))
	if err != nil {
		h.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]int{"revoked": n})
}

func (h *handler) fail(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, ima.ErrInvalidInput):
		writeError(w, http.StatusBadRequest, "invalid_request", "invalid input")
	case errors.Is(err, ima.ErrInvalidCredentials):
		writeError(w, http.StatusUnauthorized, "invalid_credentials", "invalid email or password")
	case errors.Is(err, ima.ErrUnauthenticated):
		writeError(w, http.StatusUnauthorized, "unauthenticated", "authentication required")
	case errors.Is(err, ima.ErrRateLimited):
		writeError(w, http.StatusTooManyRequests, "rate_limited", "too many requests")
	case errors.Is(err, ima.ErrNotFound):
		writeError(w, http.StatusNotFound, "not_found", "resource not found")
	case errors.Is(err, context.Canceled):
		// client went away; nothing useful to send
	default:
		h.opts.Logger.ErrorContext(r.Context(), "request failed", "method", r.Method, "path", r.URL.Path, "error", err)
		writeError(w, http.StatusInternalServerError, "internal", "internal error")
	}
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, code, msg string) {
	writeJSON(w, status, map[string]any{"error": map[string]string{"code": code, "message": msg}})
}
