package dns

import (
	"net/netip"

	D "github.com/miekg/dns"
)

// This file holds the answers 5gpn synthesises rather than forwards. They are
// small, and they are the product: what the resolver *invents* is what steers
// traffic, and every one of these has a reason that is not obvious from the
// bytes.

// SyntheticNODATA is NOERROR with a synthetic SOA: the name exists, but this
// resolver has no record of the requested type for it.
//
// The SOA rather than a bare empty NOERROR is the point. Without it the asker
// cannot negatively cache the answer and re-queries on every single connection,
// which for AAAA means doubling query volume forever.
//
// Both resolver boundaries 5gpn owns must answer with these exact bytes — the
// client-facing DoT listener and the origin lookup mihomo performs after
// sniffing. If only the first withheld AAAA, egress would still acquire IPv6
// addresses and the IPv4-only invariant would hold on paper and not in traffic.
func SyntheticNODATA(r *D.Msg) *D.Msg {
	m := new(D.Msg)
	m.SetReply(r)
	m.RecursionAvailable = true
	m.Ns = []D.RR{&D.SOA{
		Hdr: D.RR_Header{
			Name:   ".",
			Rrtype: D.TypeSOA,
			Class:  D.ClassINET,
			Ttl:    300,
		},
		Ns:      "ns.5gpn.",
		Mbox:    "hostmaster.5gpn.",
		Serial:  1,
		Refresh: 3600,
		Retry:   600,
		Expire:  86400,
		Minttl:  300,
	}}
	return m
}

// WithholdsType reports whether a query type is answered with SyntheticNODATA
// instead of being resolved.
//
// AAAA because egress is IPv4-only.
//
// HTTPS and SVCB (RFC 9460) because serving them breaks the data plane in two
// independent ways. The `ech` SvcParam lets a client encrypt the TLS
// ClientHello SNI, and the SNI in cleartext is exactly what recovers the real
// destination after a connection arrives at the gateway — an encrypted one is
// unroutable and gets black-holed. And `ipv4hint`/`ipv6hint` hand the client
// the origin's real addresses directly, which bypasses the A-record rewrite
// that steered it to the gateway in the first place.
//
// Withholding degrades cleanly: the client falls back to plain A, and picks up
// HTTP/3 through Alt-Svc if the origin offers it.
func WithholdsType(qtype uint16) bool {
	switch qtype {
	case D.TypeAAAA, D.TypeHTTPS, D.TypeSVCB:
		return true
	default:
		return false
	}
}

// GatewayReply answers with a single A record pointing at the gateway, which is
// how a name gets steered: the client connects here, and the sniffer recovers
// where it actually meant to go.
//
// With no gateway configured it returns NXDOMAIN rather than 0.0.0.0. A name
// the operator explicitly marked for proxying should fail closed and visibly,
// not resolve to an unroutable address that fails later and somewhere else.
func GatewayReply(r *D.Msg, gateway netip.Addr) *D.Msg {
	m := new(D.Msg)
	m.SetReply(r)
	m.RecursionAvailable = true

	gateway = gateway.Unmap()
	if !gateway.Is4() || gateway.IsUnspecified() {
		m.SetRcode(r, D.RcodeNameError)
		return m
	}
	if len(r.Question) == 0 {
		m.SetRcode(r, D.RcodeFormatError)
		return m
	}

	m.Answer = []D.RR{&D.A{
		Hdr: D.RR_Header{
			Name:   r.Question[0].Name,
			Rrtype: D.TypeA,
			Class:  D.ClassINET,
			// Short, because the mapping is a policy decision rather than a
			// property of the origin: an operator changing a rule should see it
			// take effect in a minute, not in whatever the origin published.
			Ttl: 60,
		},
		A: gateway.AsSlice(),
	}}
	return m
}
