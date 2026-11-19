package auth

import (
	"errors"
	"strings"
	"testing"
)

var fast = Params{Memory: 64, Time: 1, Threads: 1, SaltLen: 16, KeyLen: 32}

func TestHashAndVerify(t *testing.T) {
	h, err := NewHasher(fast)
	if err != nil {
		t.Fatal(err)
	}
	enc, err := h.Hash("correct horse battery")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(enc, "$argon2id$v=19$m=64,t=1,p=1$") {
		t.Fatalf("unexpected encoding %q", enc)
	}
	if ok, err := h.Verify("correct horse battery", enc); err != nil || !ok {
		t.Fatalf("verify: %v %v", ok, err)
	}
	if ok, _ := h.Verify("wrong password!!", enc); ok {
		t.Fatal("wrong password verified")
	}
	other, _ := h.Hash("correct horse battery")
	if other == enc {
		t.Fatal("salt must differ per hash")
	}
	if h.NeedsRehash(enc) {
		t.Fatal("same params must not need rehash")
	}
	strong, _ := NewHasher(DefaultParams)
	if !strong.NeedsRehash(enc) {
		t.Fatal("different params must need rehash")
	}
}

func TestVerifyRejectsMalformedAndExpensiveHashes(t *testing.T) {
	h, _ := NewHasher(fast)
	for _, enc := range []string{
		"", "plain", "$argon2i$v=19$m=64,t=1,p=1$c2FsdHNhbHRzYWx0$a2V5a2V5a2V5a2V5a2V5",
		"$argon2id$v=19$m=999999999,t=1,p=1$c2FsdHNhbHRzYWx0$a2V5a2V5a2V5a2V5a2V5a2V5",
		"$argon2id$v=19$m=64,t=1,p=1$!!$a2V5",
	} {
		if ok, err := h.Verify("whatever-password", enc); ok || !errors.Is(err, ErrMalformedHash) {
			t.Errorf("%q: ok=%v err=%v", enc, ok, err)
		}
	}
}

func TestValidatePassword(t *testing.T) {
	if err := ValidatePassword("短密码"); !errors.Is(err, ErrWeakPassword) {
		t.Fatal("short password accepted")
	}
	if err := ValidatePassword(strings.Repeat("a", MaxPasswordBytes+1)); !errors.Is(err, ErrWeakPassword) {
		t.Fatal("oversized password accepted")
	}
	if err := ValidatePassword("密码密码密码密码密码"); err != nil {
		t.Fatalf("10 runes must pass: %v", err)
	}
}

func TestNewHasherRejectsWeakParams(t *testing.T) {
	for _, p := range []Params{{}, {Memory: 64, Time: 1, Threads: 1, SaltLen: 4, KeyLen: 32}, {Memory: 1 << 30, Time: 1, Threads: 1, SaltLen: 16, KeyLen: 32}} {
		if _, err := NewHasher(p); err == nil {
			t.Errorf("%+v accepted", p)
		}
	}
}
