// Package auth holds credential primitives: password hashing and policy.
// Login orchestration lives in the root ima package so that the embedded
// library and the HTTP transport share one implementation.
package auth

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"unicode/utf8"

	"golang.org/x/crypto/argon2"
)

var (
	ErrWeakPassword  = errors.New("auth: password does not meet policy")
	ErrMalformedHash = errors.New("auth: malformed password hash")
)

const (
	MinPasswordRunes = 10
	// MaxPasswordBytes bounds hashing cost per request.
	MaxPasswordBytes = 256
)

// ValidatePassword enforces length bounds only; composition rules are not
// required (NIST SP 800-63B).
func ValidatePassword(pw string) error {
	if !utf8.ValidString(pw) || len(pw) > MaxPasswordBytes || utf8.RuneCountInString(pw) < MinPasswordRunes {
		return ErrWeakPassword
	}
	return nil
}

// Params are Argon2id cost parameters.
type Params struct {
	Memory  uint32 // KiB
	Time    uint32
	Threads uint8
	SaltLen uint32
	KeyLen  uint32
}

// DefaultParams follow the OWASP Argon2id recommendation (m=19 MiB, t=2, p=1).
var DefaultParams = Params{Memory: 19 * 1024, Time: 2, Threads: 1, SaltLen: 16, KeyLen: 32}

// Upper bounds accepted when verifying stored hashes, so a tampered row
// cannot make verification arbitrarily expensive.
const (
	maxMemory  = 256 * 1024
	maxTime    = 10
	maxThreads = 16
	maxKeyLen  = 64
	maxSaltLen = 64
)

// Hasher produces and verifies PHC-formatted Argon2id hashes:
// $argon2id$v=19$m=19456,t=2,p=1$<salt>$<key>
type Hasher struct{ params Params }

func NewHasher(p Params) (*Hasher, error) {
	if p.Memory < 8*uint32(p.Threads) || p.Memory > maxMemory || p.Time == 0 || p.Time > maxTime ||
		p.Threads == 0 || p.Threads > maxThreads || p.SaltLen < 16 || p.SaltLen > maxSaltLen || p.KeyLen < 16 || p.KeyLen > maxKeyLen {
		return nil, errors.New("auth: invalid argon2id parameters")
	}
	return &Hasher{params: p}, nil
}

func (h *Hasher) Hash(password string) (string, error) {
	salt := make([]byte, h.params.SaltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("auth: salt: %w", err)
	}
	key := argon2.IDKey([]byte(password), salt, h.params.Time, h.params.Memory, h.params.Threads, h.params.KeyLen)
	b64 := base64.RawStdEncoding
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s", argon2.Version,
		h.params.Memory, h.params.Time, h.params.Threads, b64.EncodeToString(salt), b64.EncodeToString(key)), nil
}

// Verify reports whether password matches encoded. A malformed hash returns
// ErrMalformedHash, never a match.
func (h *Hasher) Verify(password, encoded string) (bool, error) {
	p, salt, key, err := decode(encoded)
	if err != nil {
		return false, err
	}
	got := argon2.IDKey([]byte(password), salt, p.Time, p.Memory, p.Threads, uint32(len(key)))
	return subtle.ConstantTimeCompare(got, key) == 1, nil
}

// NeedsRehash reports whether encoded was produced with different parameters.
func (h *Hasher) NeedsRehash(encoded string) bool {
	p, salt, key, err := decode(encoded)
	if err != nil {
		return true
	}
	return p.Memory != h.params.Memory || p.Time != h.params.Time || p.Threads != h.params.Threads ||
		uint32(len(salt)) != h.params.SaltLen || uint32(len(key)) != h.params.KeyLen
}

func decode(encoded string) (Params, []byte, []byte, error) {
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 || parts[0] != "" || parts[1] != "argon2id" {
		return Params{}, nil, nil, ErrMalformedHash
	}
	var version int
	if _, err := fmt.Sscanf(parts[2], "v=%d", &version); err != nil || version != argon2.Version {
		return Params{}, nil, nil, ErrMalformedHash
	}
	var p Params
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &p.Memory, &p.Time, &p.Threads); err != nil {
		return Params{}, nil, nil, ErrMalformedHash
	}
	if p.Memory == 0 || p.Memory > maxMemory || p.Time == 0 || p.Time > maxTime || p.Threads == 0 || p.Threads > maxThreads {
		return Params{}, nil, nil, ErrMalformedHash
	}
	b64 := base64.RawStdEncoding
	salt, err := b64.DecodeString(parts[4])
	if err != nil || len(salt) < 8 || len(salt) > maxSaltLen {
		return Params{}, nil, nil, ErrMalformedHash
	}
	key, err := b64.DecodeString(parts[5])
	if err != nil || len(key) < 16 || len(key) > maxKeyLen {
		return Params{}, nil, nil, ErrMalformedHash
	}
	return p, salt, key, nil
}
