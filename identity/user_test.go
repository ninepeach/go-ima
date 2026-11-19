package identity

import (
	"errors"
	"strings"
	"testing"
)

func TestNormalizeEmail(t *testing.T) {
	got, err := NormalizeEmail("  Alice@Example.COM ")
	if err != nil || got != "alice@example.com" {
		t.Fatalf("got %q, %v", got, err)
	}
	for _, bad := range []string{"", "alice", "Alice <alice@example.com>", "a@b, c@d", strings.Repeat("a", 250) + "@x.io"} {
		if _, err := NormalizeEmail(bad); !errors.Is(err, ErrInvalidUser) {
			t.Errorf("%q: want ErrInvalidUser, got %v", bad, err)
		}
	}
}

func TestValidateDisplayName(t *testing.T) {
	if got, err := ValidateDisplayName("  张三 "); err != nil || got != "张三" {
		t.Fatalf("got %q, %v", got, err)
	}
	for _, bad := range []string{"a\nb", strings.Repeat("x", 101), "\xff"} {
		if _, err := ValidateDisplayName(bad); !errors.Is(err, ErrInvalidUser) {
			t.Errorf("%q: want ErrInvalidUser", bad)
		}
	}
}
