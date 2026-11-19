package postgres

import "net/netip"

// ipArg maps an invalid (unknown) address to NULL.
func ipArg(a netip.Addr) any {
	if !a.IsValid() {
		return nil
	}
	return netip.PrefixFrom(a, a.BitLen())
}

func ipFrom(p *netip.Prefix) netip.Addr {
	if p == nil {
		return netip.Addr{}
	}
	return p.Addr()
}
