// Package netguard owns the product-wide address scope boundary for outbound
// fetches and extension traffic.
package netguard

import "net/netip"

// Audited against the IANA IPv4 and IPv6 Special-Purpose Address Registries on
// 2026-08-09. The broader protocol-assignment containers are intentionally
// conservative: a few globally reachable anycast exceptions are not ordinary
// extension or fetch destinations and remain refused.
var nonPublicIPv4Prefixes = [...]netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),
	netip.MustParsePrefix("10.0.0.0/8"),
	netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("127.0.0.0/8"),
	netip.MustParsePrefix("169.254.0.0/16"),
	netip.MustParsePrefix("172.16.0.0/12"),
	netip.MustParsePrefix("192.0.0.0/24"),
	netip.MustParsePrefix("192.0.2.0/24"),
	netip.MustParsePrefix("192.88.99.0/24"),
	netip.MustParsePrefix("192.168.0.0/16"),
	netip.MustParsePrefix("198.18.0.0/15"),
	netip.MustParsePrefix("198.51.100.0/24"),
	netip.MustParsePrefix("203.0.113.0/24"),
	netip.MustParsePrefix("224.0.0.0/4"),
	netip.MustParsePrefix("240.0.0.0/4"),
}

var (
	ianaIPv6GlobalUnicast = netip.MustParsePrefix("2000::/3")
	nonPublicIPv6Prefixes = [...]netip.Prefix{
		netip.MustParsePrefix("2001::/23"),
		netip.MustParsePrefix("2001:db8::/32"),
		netip.MustParsePrefix("2002::/16"),
		netip.MustParsePrefix("3fff::/20"),
	}
)

// IsPubliclyRoutable reports whether address is an ordinary, globally
// routable unicast address suitable for an outbound security boundary.
//
// This is deliberately narrower than netip.Addr.IsGlobalUnicast. IPv4 denies
// the IANA special-purpose blocks that are not normal Internet destinations.
// IPv6 allows only the currently allocated 2000::/3 global-unicast space and
// removes its protocol-assignment, documentation, and transition exceptions.
// IPv4-mapped, NAT64, 6to4, Teredo, discard-only, and zoned addresses are
// refused even when a translator could make one reachable. This is an IANA
// scope decision, not a claim that an allowed address currently has a BGP
// route.
func IsPubliclyRoutable(address netip.Addr) bool {
	if !address.IsValid() || address.Zone() != "" || address.Is4In6() || !address.IsGlobalUnicast() {
		return false
	}
	if address.Is4() {
		for _, prefix := range nonPublicIPv4Prefixes {
			if prefix.Contains(address) {
				return false
			}
		}
		return true
	}
	if !ianaIPv6GlobalUnicast.Contains(address) {
		return false
	}
	for _, prefix := range nonPublicIPv6Prefixes {
		if prefix.Contains(address) {
			return false
		}
	}
	return true
}
