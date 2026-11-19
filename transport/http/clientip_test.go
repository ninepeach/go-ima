package imahttp

import (
	"net/http/httptest"
	"net/netip"
	"testing"
)

func TestClientIP(t *testing.T) {
	trusted := []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}
	cases := []struct {
		remote, xff, want string
	}{
		{"203.0.113.9:1234", "", "203.0.113.9"},
		{"203.0.113.9:1234", "1.2.3.4", "203.0.113.9"},                     // untrusted peer: header ignored
		{"10.0.0.2:80", "198.51.100.7", "198.51.100.7"},                    // via trusted proxy
		{"10.0.0.2:80", "6.6.6.6, 198.51.100.7, 10.0.0.3", "198.51.100.7"}, // spoofed left entry ignored
		{"10.0.0.2:80", "not-an-ip", "10.0.0.2"},
		{"10.0.0.2:80", "10.0.0.5", "10.0.0.2"},
		{"[::ffff:203.0.113.9]:1", "", "203.0.113.9"},
	}
	for _, c := range cases {
		r := httptest.NewRequest("GET", "/", nil)
		r.RemoteAddr = c.remote
		if c.xff != "" {
			r.Header.Set("X-Forwarded-For", c.xff)
		}
		if got := clientIP(r, trusted).String(); got != c.want {
			t.Errorf("remote=%s xff=%q: got %s want %s", c.remote, c.xff, got, c.want)
		}
	}
}
