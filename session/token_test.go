package session

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

func TestTokenRoundTrip(t *testing.T) {
	plain, hash, err := NewToken(KindRefresh)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(plain, KindRefresh) || len(hash) != 32 {
		t.Fatalf("unexpected token %q", plain)
	}
	got, err := HashToken(KindRefresh, plain)
	if err != nil || !bytes.Equal(got, hash) {
		t.Fatalf("hash mismatch: %v", err)
	}
	if _, err := HashToken(KindAccess, plain); !errors.Is(err, ErrMalformedToken) {
		t.Fatal("kind confusion must be rejected")
	}
	for _, bad := range []string{"", KindRefresh, KindRefresh + "short", KindRefresh + strings.Repeat("!", 43)} {
		if _, err := HashToken(KindRefresh, bad); !errors.Is(err, ErrMalformedToken) {
			t.Errorf("%q accepted", bad)
		}
	}
}
