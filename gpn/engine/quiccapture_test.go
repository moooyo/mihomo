package engine

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/metacubex/http"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/quic-go"
	"github.com/metacubex/quic-go/http3"
	"github.com/metacubex/tls"
)

// The datagram capture path, tested at the two levels that can actually be
// wrong: the bridge's addressing, and whether a real QUIC client gets a real
// HTTP/3 response through it.
//
// The second test is the one that matters. A bridge that routes buffers
// correctly and a listener that never completes a handshake would pass every
// unit assertion and capture nothing.

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

// captureQUICTestProxy assembles a proxy with a published leaf and one enabled
// extension capturing leaf.test.
func captureQUICTestProxy(t *testing.T) *interceptProxy {
	t.Helper()
	dir := t.TempDir()
	tlsDir := filepath.Join(dir, "tls")
	if err := os.MkdirAll(tlsDir, 0o755); err != nil {
		t.Fatal(err)
	}
	certPath := filepath.Join(tlsDir, "fullchain.pem")
	keyPath := filepath.Join(tlsDir, "privkey.pem")
	writeTestLeaf(t, certPath, keyPath)

	document := fmt.Sprintf(`{
  "version": 6,
  "execution_order": ["capture"],
  "tls_cert": %q,
  "tls_key": %q,
  "mitm": {"enabled": true, "http2": true, "http3": true},
  "modules": [
    {
      "id": "capture",
      "extension_version": "1.0.0",
      "name": "Capture",
      "enabled": true,
      "imported_at": "2026-08-01T00:00:00Z",
      "source": {"digest": "44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a", "body": "{}"},
      "capture_hosts": ["leaf.test"],
      "capture_dns": "trust",
      "upstream_mappings": [{"host": "leaf.test", "target": "origin.example.net"}],
      "persistent_storage": false,
      "egress_group_required": false
    }
  ]
}`, certPath, keyPath)

	path := filepath.Join(dir, "intercept.json")
	if err := os.WriteFile(path, []byte(document), 0o600); err != nil {
		t.Fatal(err)
	}
	store, err := newConfigStore(path)
	if err != nil {
		t.Fatalf("newConfigStore: %v", err)
	}
	proxy := newInterceptProxy(store, newCertificateStore(store), dir)
	proxy.setEngineLogPublisher(newEngineLogHub(engineLogRingCapacity))
	return proxy
}

// The whole datagram path, end to end: a real QUIC client handshakes against
// the engine's own leaf through the capture bridge, sends an HTTP/3 request,
// and gets the interception proxy's answer back.
//
// The request names a host the document does not capture, so the assertion is
// on the proxy's own refusal rather than on an upstream this test does not
// have. That is deliberate -- what is under test is that an H3 request reaches
// ServeHTTP and its response reaches the client, and a status the proxy decides
// by itself proves both ends without a network.
func TestAnHTTP3RequestSurvivesTheCaptureBridge(t *testing.T) {
	proxy := captureQUICTestProxy(t)
	defer proxy.closeQUICCapture()

	gateway := netip.MustParseAddrPort("10.0.1.20:443")
	metadata := &C.Metadata{
		NetWork: C.UDP,
		Host:    "leaf.test",
		SrcIP:   netip.MustParseAddr("203.0.113.7"),
		SrcPort: 44001,
		DstIP:   gateway.Addr(),
		DstPort: gateway.Port(),
	}
	captured, err := proxy.captureQUIC(metadata)
	if err != nil {
		t.Fatalf("captureQUIC: %v", err)
	}

	// The conn the core drives is, from the client's side, exactly a socket:
	// writes carry the client's datagrams and reads carry the gateway's. So the
	// client dials over it directly rather than through another adapter.
	transport := &quic.Transport{Conn: captured}
	// Ordering, not tidiness: a Transport handed a conn it did not create does
	// not close it, and Close waits for its own read loop to return. Closing
	// the association first is what lets that read fail and the wait finish.
	defer func() {
		_ = captured.Close()
		_ = transport.Close()
	}()

	roundTripper := &http3.Transport{
		// The leaf is self-signed and is not its own issuer, so it cannot be
		// verified as a chain. What is under test is the transport, and the
		// certificate's contents already have their own coverage in cert_test.go.
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true, ServerName: "leaf.test"},
		Dial: func(ctx context.Context, _ string, tlsCfg *tls.Config, quicCfg *quic.Config) (*quic.Conn, error) {
			return transport.DialEarly(ctx, net.UDPAddrFromAddrPort(gateway), tlsCfg, quicCfg)
		},
	}
	defer roundTripper.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://elsewhere.test/probe", nil)
	if err != nil {
		t.Fatal(err)
	}
	response, err := roundTripper.RoundTrip(request)
	if err != nil {
		t.Fatalf("no HTTP/3 response came back through the capture bridge: %v", err)
	}
	defer response.Body.Close()
	_, _ = io.Copy(io.Discard, response.Body)

	if response.StatusCode != http.StatusMisdirectedRequest {
		t.Errorf("status %d, want %d from the proxy's own host check", response.StatusCode, http.StatusMisdirectedRequest)
	}
	if response.ProtoMajor != 3 {
		t.Errorf("response arrived over HTTP/%d, want HTTP/3", response.ProtoMajor)
	}
}

// MatchUDP is the whole of the decision to capture a datagram association, so
// each thing it refuses is a way gateway QUIC could silently bypass
// interception -- or be black holed by claiming an association the engine
// would not serve.
func TestMatchUDPCapturesOnlyEnabledHTTP3ForKnownHosts(t *testing.T) {
	proxy := captureQUICTestProxy(t)
	defer proxy.closeQUICCapture()
	interceptor := NewInterceptor(proxy)

	base := func() *C.Metadata {
		return &C.Metadata{
			NetWork: C.UDP,
			Host:    "leaf.test",
			SrcIP:   netip.MustParseAddr("203.0.113.7"),
			SrcPort: 44001,
			DstIP:   netip.MustParseAddr("10.0.1.20"),
			DstPort: 443,
		}
	}
	if !interceptor.MatchUDP(base()) {
		t.Fatal("a captured host on :443 with http3 enabled was not matched")
	}

	noHost := base()
	noHost.Host = ""
	if interceptor.MatchUDP(noHost) {
		t.Error("an association with no sniffed host was captured")
	}

	otherPort := base()
	otherPort.DstPort = 8443
	if interceptor.MatchUDP(otherPort) {
		t.Error("a datagram association off :443 was captured")
	}

	unknownHost := base()
	unknownHost.Host = "elsewhere.test"
	if interceptor.MatchUDP(unknownHost) {
		t.Error("a host no enabled extension declared was captured")
	}

	// With HTTP/3 off the answer must be false even for a captured host: that
	// is what leaves the association to the fixed UDP/443 reject and the TCP
	// fallback which is captured properly.
	if _, _, err := proxy.config.Update(proxy.config.Revision(), func(cfg Config) (Config, error) {
		cfg.MITM.HTTP3 = false
		return cfg, nil
	}); err != nil {
		t.Fatalf("rewriting the document with http3 off: %v", err)
	}
	if interceptor.MatchUDP(base()) {
		t.Error("a captured host was matched with http3 disabled")
	}
}
