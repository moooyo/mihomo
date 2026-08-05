package engine

import (
	"net"
	"net/netip"
	"testing"

	C "github.com/metacubex/mihomo/constant"
)

// The dormant datagram bridge still has precise addressing tests so removing
// HTTP/3 support does not hide unrelated packet-routing regressions. The
// interceptor contract below proves the bridge is unreachable from traffic.

func testAssociation(t *testing.T, bridge *quicBridge, client, origin string) *quicAssociation {
	t.Helper()
	clientAddr, err := netip.ParseAddrPort(client)
	if err != nil {
		t.Fatal(err)
	}
	originAddr, err := netip.ParseAddrPort(origin)
	if err != nil {
		t.Fatal(err)
	}
	return &quicAssociation{
		bridge: bridge,
		client: clientAddr,
		origin: net.UDPAddrFromAddrPort(originAddr),
		host:   "leaf.test",
		out:    make(chan []byte, quicAssociationQueue),
		done:   make(chan struct{}),
	}
}

func TestTheBridgeAddressesDatagramsByClientAndAnswersFromTheGateway(t *testing.T) {
	bridge := newQUICBridge()
	defer bridge.Close()

	first := testAssociation(t, bridge, "203.0.113.7:44001", "10.0.1.20:443")
	second := testAssociation(t, bridge, "203.0.113.8:44002", "10.0.1.20:443")
	for _, association := range []*quicAssociation{first, second} {
		if err := bridge.registerAssociation(association); err != nil {
			t.Fatalf("registerAssociation: %v", err)
		}
	}

	// Client to listener: what the core wrote arrives addressed as the client
	// that sent it, which is the identity quic-go demultiplexes on.
	if _, err := second.WriteTo([]byte("from-second"), second.origin); err != nil {
		t.Fatalf("WriteTo: %v", err)
	}
	buffer := make([]byte, 64)
	n, from, err := bridge.ReadFrom(buffer)
	if err != nil {
		t.Fatalf("bridge.ReadFrom: %v", err)
	}
	if got := string(buffer[:n]); got != "from-second" {
		t.Errorf("bridge read %q, want %q", got, "from-second")
	}
	if from.String() != "203.0.113.8:44002" {
		t.Errorf("bridge attributed the datagram to %s, want the sending client", from)
	}

	// Listener to client: the reply reaches the right association and reports
	// the gateway address as its source, because that is the address the client
	// is talking to and the only one it will accept a reply from.
	if _, err := bridge.WriteTo([]byte("to-first"), net.UDPAddrFromAddrPort(first.client)); err != nil {
		t.Fatalf("bridge.WriteTo: %v", err)
	}
	payload, _, source, err := first.WaitReadFrom()
	if err != nil {
		t.Fatalf("WaitReadFrom: %v", err)
	}
	if string(payload) != "to-first" {
		t.Errorf("first association read %q", payload)
	}
	if source.String() != "10.0.1.20:443" {
		t.Errorf("reply source %s, want the gateway address the client sent to", source)
	}

	// Nothing leaked into the other association.
	select {
	case stray := <-second.out:
		t.Fatalf("second association received %q, which was addressed to the first", stray)
	default:
	}
}

// A datagram for an association that has gone is dropped, not failed. A QUIC
// server that saw a write error would tear the connection down over a packet it
// would otherwise simply retransmit.
func TestAWriteToADepartedAssociationIsNotAnError(t *testing.T) {
	bridge := newQUICBridge()
	defer bridge.Close()

	association := testAssociation(t, bridge, "203.0.113.7:44001", "10.0.1.20:443")
	if err := bridge.registerAssociation(association); err != nil {
		t.Fatal(err)
	}
	if err := association.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := bridge.WriteTo([]byte("orphan"), net.UDPAddrFromAddrPort(association.client)); err != nil {
		t.Fatalf("writing to a departed association reported %v, want it dropped", err)
	}
}

// Two live associations from one client address to two different gateway
// addresses cannot both be routed back, because a write carries only the
// address it is addressed to. Refusing the second is what keeps the first from
// receiving its traffic; the refused one falls through to ordinary routing,
// where the fixed UDP/443 reject turns it into a captured TCP connection.
func TestASecondGatewayAddressForOneClientIsRefusedRatherThanMisrouted(t *testing.T) {
	bridge := newQUICBridge()
	defer bridge.Close()

	first := testAssociation(t, bridge, "203.0.113.7:44001", "10.0.1.20:443")
	if err := bridge.registerAssociation(first); err != nil {
		t.Fatal(err)
	}
	elsewhere := testAssociation(t, bridge, "203.0.113.7:44001", "10.0.2.30:443")
	if err := bridge.registerAssociation(elsewhere); err == nil {
		t.Fatal("a second gateway address for one client was accepted")
	}

	// The same client returning to the same gateway is the ordinary case -- the
	// core timed the association out and the client kept its connection. That
	// one replaces rather than being refused, or a returning client could never
	// be captured again.
	returning := testAssociation(t, bridge, "203.0.113.7:44001", "10.0.1.20:443")
	if err := bridge.registerAssociation(returning); err != nil {
		t.Fatalf("a returning client was refused: %v", err)
	}
	select {
	case <-first.done:
	default:
		t.Error("the replaced association was left open")
	}
}

// MatchUDP is the defensive boundary that keeps extension interception on TCP.
// Even metadata that would have been eligible for QUIC capture must fall
// through to the gateway's fixed UDP/443 reject rule.
func TestMatchUDPNeverCapturesHTTP3(t *testing.T) {
	interceptor := NewInterceptor(nil)
	metadata := &C.Metadata{
		NetWork: C.UDP,
		Host:    "leaf.test",
		SrcIP:   netip.MustParseAddr("203.0.113.7"),
		SrcPort: 44001,
		DstIP:   netip.MustParseAddr("10.0.1.20"),
		DstPort: 443,
	}
	if interceptor.MatchUDP(metadata) {
		t.Fatal("extension interception captured HTTP/3 instead of leaving UDP/443 to the gateway block")
	}
}
