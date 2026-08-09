package dns

import (
	D "github.com/miekg/dns"
)

// A client that obtains the origin's real address, or a key that hides the SNI,
// has walked around the steering entirely. Two record types do that, and
// WithholdsType refuses them when they are the question. This file closes the
// same hole for every query type that is not the question.
//
// It is not a redundant belt: an ANY query returns both RRsets outright, and an
// MX, NS, SRV, or PTR reply carries the target's AAAA as additional-section
// glue. An address is exactly as usable to a client from the additional section
// as it is from the answer, so all three sections are filtered. IPv4 A records
// remain valid for direct decisions and are removed separately below only when
// the current decision has already committed the name to the gateway.

// filterSteeringBypass returns a copy of m with the bypass records removed from
// every section.
func filterSteeringBypass(m *D.Msg) *D.Msg {
	cp := m.Copy()
	cp.Answer = dropBypassRRs(cp.Answer)
	cp.Ns = dropBypassRRs(cp.Ns)
	cp.Extra = dropBypassRRs(cp.Extra)
	if len(cp.Answer) != len(m.Answer) || len(cp.Ns) != len(m.Ns) || len(cp.Extra) != len(m.Extra) {
		cp.AuthenticatedData = false
	}
	return cp
}

// filterGatewayAddressDisclosure removes every address a client could use to
// bypass an already-selected gateway decision. Unlike filterSteeringBypass it
// also removes A: explicit direct decisions may legitimately return IPv4 glue,
// but gateway decisions may not disclose it, and auto decisions must force a
// separate A lookup so the address can be arbitrated first.
func filterGatewayAddressDisclosure(m *D.Msg) *D.Msg {
	cp := m.Copy()
	cp.Answer = dropGatewayAddressRRs(cp.Answer)
	cp.Ns = dropGatewayAddressRRs(cp.Ns)
	cp.Extra = dropGatewayAddressRRs(cp.Extra)
	if len(cp.Answer) != len(m.Answer) || len(cp.Ns) != len(m.Ns) || len(cp.Extra) != len(m.Extra) {
		cp.AuthenticatedData = false
	}
	return cp
}

func dropGatewayAddressRRs(rrs []D.RR) []D.RR {
	removed := false
	for _, rr := range rrs {
		if _, ok := rr.(*D.A); ok || isBypassRR(rr) {
			removed = true
			break
		}
	}
	if !removed {
		return rrs
	}
	kept := make([]D.RR, 0, len(rrs))
	for _, rr := range rrs {
		if _, ok := rr.(*D.A); ok || isBypassRR(rr) {
			continue
		}
		kept = append(kept, rr)
	}
	return stripDNSSEC(kept)
}

// isBypassRR reports whether rr can defeat A-record steering.
//
// Deliberately narrow. APL, IPSECKEY and HIP can also encode addresses, but
// none of them is used to open an ordinary client connection, so removing them
// would cost correctness without closing anything.
func isBypassRR(rr D.RR) bool {
	switch rr.(type) {
	case *D.AAAA, *D.HTTPS, *D.SVCB:
		return true
	}
	return false
}

// dropBypassRRs filters one section, returning the input untouched when there
// was nothing to remove -- signatures and all.
//
// When a section does lose a record its DNSSEC RRs go too, for the same reason
// rewriteA strips them: a signature that no longer covers the data it was
// computed over makes a validating stub fail, and it fails on exactly the
// subset of names this gateway touched.
func dropBypassRRs(rrs []D.RR) []D.RR {
	removed := false
	for _, rr := range rrs {
		if isBypassRR(rr) {
			removed = true
			break
		}
	}
	if !removed {
		return rrs
	}
	kept := make([]D.RR, 0, len(rrs))
	for _, rr := range rrs {
		if !isBypassRR(rr) {
			kept = append(kept, rr)
		}
	}
	return stripDNSSEC(kept)
}

// stripDNSSEC removes signature and denial-of-existence records from a section
// whose data was rewritten.
//
// OPT is deliberately absent from the list: it is the EDNS pseudo-record, owned
// by the transport, and removing it would drop the client's advertised buffer
// size along with it.
func stripDNSSEC(rrs []D.RR) []D.RR {
	out := make([]D.RR, 0, len(rrs))
	for _, rr := range rrs {
		switch rr.(type) {
		case *D.RRSIG, *D.NSEC, *D.NSEC3, *D.NSEC3PARAM, *D.DNSKEY, *D.DS, *D.CDS, *D.CDNSKEY, *D.DLV:
			continue
		}
		out = append(out, rr)
	}
	return out
}
