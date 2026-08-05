package dns

import (
	"fmt"
	"net"
	"net/netip"
	"strings"

	D "github.com/miekg/dns"
)

// EDNS Client Subnet (RFC 7871), for the china group only.
//
// The gateway queries domestic resolvers from its own egress address, which is
// usually in a different province and on a different ISP than the phones it
// serves. Without ECS a CN CDN schedules answers near the GATEWAY, and every
// client is then sent to a node chosen for a machine it is nowhere near.
// Attaching the clients' real egress /24 puts the scheduling back where it
// belongs.
//
// Trust never gets one. Foreign answers are rewritten to the gateway address
// anyway, so the client subnet would change nothing about what the client
// receives -- it would only hand a foreign resolver a fact about the operator's
// users that it had no way to learn otherwise.
//
// The default cut is a /24 rather than a full address, which is precise enough
// for CDN scheduling and stops short of shipping one identifiable host upstream.

// parseECS turns an operator-supplied value into the prefix to attach:
//
//	""            disabled
//	IPv4          its /24   ("122.96.30.5" -> 122.96.30.0/24)
//	IPv6          its /56   (v6 assignments are per-site; the same privacy cut)
//	CIDR          honoured as written, masked to its own prefix
func parseECS(raw string) (netip.Prefix, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return netip.Prefix{}, nil
	}
	if strings.Contains(raw, "/") {
		p, err := netip.ParsePrefix(raw)
		if err != nil {
			return netip.Prefix{}, fmt.Errorf("5gpn/dns: ecs %q is not a valid CIDR: %w", raw, err)
		}
		return p.Masked(), nil
	}
	addr, err := netip.ParseAddr(raw)
	if err != nil {
		return netip.Prefix{}, fmt.Errorf("5gpn/dns: ecs %q is not an address or CIDR: %w", raw, err)
	}
	addr = addr.Unmap()
	bits := 56
	if addr.Is4() {
		bits = 24
	}
	return netip.PrefixFrom(addr, bits).Masked(), nil
}

// ecsString renders a prefix for display and persistence; a zero prefix, which
// means disabled, renders empty.
func ecsString(p netip.Prefix) string {
	if !p.IsValid() {
		return ""
	}
	return p.String()
}

// setECS attaches subnet to m, creating the OPT record if the query carries
// none and REPLACING any client-supplied subnet.
//
// The replacement is the point. On the china path the operator's value is
// authoritative, and a client that sent its own subnet must not be able to
// steer a CN CDN with it -- nor to vary a response that another client will
// read out of the shared cache. m must already be a private copy.
func setECS(m *D.Msg, subnet netip.Prefix) {
	opt := m.IsEdns0()
	if opt == nil {
		m.SetEdns0(1232, false)
		opt = m.IsEdns0()
	}
	stripECSFromOpt(opt)

	family := uint16(1)
	addr := subnet.Addr().Unmap()
	if !addr.Is4() {
		family = 2
	}
	opt.Option = append(opt.Option, &D.EDNS0_SUBNET{
		Code:          D.EDNS0SUBNET,
		Family:        family,
		SourceNetmask: uint8(subnet.Bits()),
		SourceScope:   0,
		Address:       net.IP(addr.AsSlice()),
	})
}

// stripECS removes any client subnet option from m.
//
// Called on the way out so a client's value never reaches an upstream, and on
// the way back so the operator's value is not echoed to a client that never
// asked for it.
func stripECS(m *D.Msg) {
	if m == nil {
		return
	}
	if opt := m.IsEdns0(); opt != nil {
		stripECSFromOpt(opt)
	}
}

func stripECSFromOpt(opt *D.OPT) {
	kept := opt.Option[:0]
	for _, o := range opt.Option {
		if o.Option() != D.EDNS0SUBNET {
			kept = append(kept, o)
		}
	}
	opt.Option = kept
}
