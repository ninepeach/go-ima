package ima

import "errors"

// Errors returned by Service. Transports map them to responses; messages never
// reveal whether an account exists.
var (
	ErrInvalidInput = errors.New("ima: invalid input")
	// ErrInvalidCredentials covers unknown email, wrong password and disabled accounts alike.
	ErrInvalidCredentials = errors.New("ima: invalid credentials")
	// ErrUnauthenticated covers missing, malformed, expired, revoked or replayed tokens.
	ErrUnauthenticated = errors.New("ima: unauthenticated")
	ErrRateLimited     = errors.New("ima: rate limited")
	ErrNotFound        = errors.New("ima: not found")
	// ErrEmailUnavailable is returned to the embedding host only. Public
	// transports must answer registration identically whether or not it occurred.
	ErrEmailUnavailable = errors.New("ima: email unavailable")
)
