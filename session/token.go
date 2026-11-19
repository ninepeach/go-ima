package session

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"strings"
)

// Token kinds are visible prefixes so leaked tokens are recognizable by
// secret scanners and cannot be confused with one another.
const (
	KindAccess  = "ima_at_"
	KindRefresh = "ima_rt_"
	KindDevice  = "ima_dt_"
	// One-time challenge tokens delivered out of band (email links).
	KindVerifyEmail   = "ima_ve_"
	KindPasswordReset = "ima_pr_"
)

var ErrMalformedToken = errors.New("session: malformed token")

const tokenBytes = 32

// NewToken returns a random opaque token and the SHA-256 digest to store.
// Only the digest is persisted; the plain token is returned to the client once.
func NewToken(kind string) (string, []byte, error) {
	raw := make([]byte, tokenBytes)
	if _, err := rand.Read(raw); err != nil {
		return "", nil, err
	}
	plain := kind + base64.RawURLEncoding.EncodeToString(raw)
	sum := sha256.Sum256([]byte(plain))
	return plain, sum[:], nil
}

// HashToken validates the kind and shape of plain and returns its digest.
func HashToken(kind, plain string) ([]byte, error) {
	body, ok := strings.CutPrefix(plain, kind)
	if !ok || base64.RawURLEncoding.DecodedLen(len(body)) != tokenBytes {
		return nil, ErrMalformedToken
	}
	if _, err := base64.RawURLEncoding.DecodeString(body); err != nil {
		return nil, ErrMalformedToken
	}
	sum := sha256.Sum256([]byte(plain))
	return sum[:], nil
}
