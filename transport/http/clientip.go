package imahttp

import (
	"net"
	"net/http"
	"net/netip"
	"strings"
)

// clientIP returns the caller address. X-Forwarded-For is honored only when
// the direct peer is a trusted proxy; then the right-most address that is not
// itself a trusted proxy wins, so client-supplied entries cannot spoof it.
func clientIP(r *http.Request, trusted []netip.Prefix) netip.Addr {
	peer := parseAddr(r.RemoteAddr)
	if !peer.IsValid() || !isTrusted(peer, trusted) {
		return peer
	}
	hops := r.Header.Values("X-Forwarded-For")
	var all []string
	for _, h := range hops {
		all = append(all, strings.Split(h, ",")...)
	}
	for i := len(all) - 1; i >= 0; i-- {
		a, err := netip.ParseAddr(strings.TrimSpace(all[i]))
		if err != nil {
			return peer // malformed chain: fall back to the proxy itself
		}
		a = a.Unmap()
		if !isTrusted(a, trusted) {
			return a
		}
	}
	return peer
}

func parseAddr(hostport string) netip.Addr {
	host, _, err := net.SplitHostPort(hostport)
	if err != nil {
		host = hostport
	}
	a, err := netip.ParseAddr(host)
	if err != nil {
		return netip.Addr{}
	}
	return a.Unmap()
}

func isTrusted(a netip.Addr, trusted []netip.Prefix) bool {
	for _, p := range trusted {
		if p.Contains(a) {
			return true
		}
	}
	return false
}
