package dns

import (
	"net/netip"
	"testing"

	D "github.com/miekg/dns"
)

func query(name string, qtype uint16) *D.Msg {
	m := new(D.Msg)
	m.SetQuestion(D.Fqdn(name), qtype)
	return m
}

// The SOA is the whole reason this is not a bare empty NOERROR: without it the
// asker cannot negatively cache, and re-asks on every connection.
func TestSyntheticNODATACarriesASOA(t *testing.T) {
	reply := SyntheticNODATA(query("example.com", D.TypeAAAA))

	if reply.Rcode != D.RcodeSuccess {
		t.Errorf("Rcode = %v, want NOERROR", D.RcodeToString[reply.Rcode])
	}
	if len(reply.Answer) != 0 {
		t.Errorf("got %d answers, want none", len(reply.Answer))
	}
	if len(reply.Ns) != 1 {
		t.Fatalf("got %d authority records, want 1 SOA", len(reply.Ns))
	}
	soa, ok := reply.Ns[0].(*D.SOA)
	if !ok {
		t.Fatalf("authority record is %T, want *dns.SOA", reply.Ns[0])
	}
	if soa.Minttl == 0 {
		t.Error("SOA minimum TTL is zero, so the answer cannot be negatively cached")
	}
	if !reply.RecursionAvailable {
		t.Error("RecursionAvailable is false on a recursive resolver's reply")
	}
}

func TestWithheldTypes(t *testing.T) {
	withheld := []uint16{D.TypeAAAA, D.TypeHTTPS, D.TypeSVCB}
	for _, qt := range withheld {
		if !WithholdsType(qt) {
			t.Errorf("WithholdsType(%s) = false", D.TypeToString[qt])
		}
	}
	// A must be resolved; withholding it would answer nothing at all. TXT and
	// MX are ordinary types with no bearing on steering.
	for _, qt := range []uint16{D.TypeA, D.TypeTXT, D.TypeMX, D.TypeCNAME} {
		if WithholdsType(qt) {
			t.Errorf("WithholdsType(%s) = true", D.TypeToString[qt])
		}
	}
}

func TestGatewayReplyAnswersWithTheGateway(t *testing.T) {
	gw := netip.MustParseAddr("198.51.100.7")
	reply := GatewayReply(query("steered.example", D.TypeA), gw)

	if reply.Rcode != D.RcodeSuccess {
		t.Fatalf("Rcode = %v, want NOERROR", D.RcodeToString[reply.Rcode])
	}
	if len(reply.Answer) != 1 {
		t.Fatalf("got %d answers, want exactly 1", len(reply.Answer))
	}
	a, ok := reply.Answer[0].(*D.A)
	if !ok {
		t.Fatalf("answer is %T, want *dns.A", reply.Answer[0])
	}
	if got, _ := netip.AddrFromSlice(a.A); got.Unmap() != gw {
		t.Errorf("answer = %v, want %v", got, gw)
	}
	if a.Hdr.Name != "steered.example." {
		t.Errorf("answer name = %q", a.Hdr.Name)
	}
	if a.Hdr.Ttl == 0 || a.Hdr.Ttl > 300 {
		t.Errorf("TTL = %d; the mapping is a policy decision and should expire quickly", a.Hdr.Ttl)
	}
}

// Failing closed matters here. 0.0.0.0 would be accepted by the client and fail
// later, somewhere else, with nothing connecting the failure to the missing
// configuration.
func TestGatewayReplyFailsClosedWithoutAGateway(t *testing.T) {
	for _, gw := range []netip.Addr{
		{},                                 // never configured
		netip.MustParseAddr("0.0.0.0"),     // configured to the unspecified address
		netip.MustParseAddr("127.0.0.1"),   // unreachable from clients
		netip.MustParseAddr("169.254.1.1"), // link-local rather than a gateway coordinate
		netip.MustParseAddr("224.0.0.1"),   // multicast is not a dial target
		netip.MustParseAddr("2001:db8::1"), // v6: egress is IPv4-only
	} {
		reply := GatewayReply(query("steered.example", D.TypeA), gw)
		if reply.Rcode != D.RcodeNameError {
			t.Errorf("gateway %v: Rcode = %v, want NXDOMAIN", gw, D.RcodeToString[reply.Rcode])
		}
		if len(reply.Answer) != 0 {
			t.Errorf("gateway %v: returned %d answers", gw, len(reply.Answer))
		}
	}
}

// A v4-mapped v6 address is still IPv4 and must be usable as the gateway;
// rejecting it would refuse a perfectly valid configuration.
func TestGatewayReplyAcceptsAV4MappedAddress(t *testing.T) {
	mapped := netip.AddrFrom16(netip.MustParseAddr("198.51.100.7").As16())
	reply := GatewayReply(query("steered.example", D.TypeA), mapped)
	if reply.Rcode != D.RcodeSuccess || len(reply.Answer) != 1 {
		t.Fatalf("a v4-mapped gateway was refused: rcode=%v answers=%d",
			D.RcodeToString[reply.Rcode], len(reply.Answer))
	}
}

func TestGatewayReplyRefusesAQuestionlessMessage(t *testing.T) {
	reply := GatewayReply(new(D.Msg), netip.MustParseAddr("198.51.100.7"))
	if reply.Rcode != D.RcodeFormatError {
		t.Errorf("Rcode = %v, want FORMERR", D.RcodeToString[reply.Rcode])
	}
}
