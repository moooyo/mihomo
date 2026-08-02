package ingress

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"testing"
	"time"

	stdtls "crypto/tls"

	"github.com/metacubex/tls"

	D "github.com/miekg/dns"
)

func leaf(t *testing.T) *tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "dot.test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		DNSNames:     []string{"dot.test"},
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	parsed, _ := x509.ParseCertificate(der)
	return &tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: parsed}
}

// answering is a handler that proves a query reached the engine.
type answering struct{ seen chan string }

func (a *answering) ServeDNS(w D.ResponseWriter, r *D.Msg) {
	if len(r.Question) > 0 {
		select {
		case a.seen <- r.Question[0].Name:
		default:
		}
	}
	m := new(D.Msg)
	m.SetReply(r)
	m.Answer = append(m.Answer, &D.A{
		Hdr: D.RR_Header{Name: r.Question[0].Name, Rrtype: D.TypeA, Class: D.ClassINET, Ttl: 60},
		A:   net.IPv4(203, 0, 113, 1),
	})
	_ = w.WriteMsg(m)
}

func TestDoTServesQueries(t *testing.T) {
	h := &answering{seen: make(chan string, 1)}
	ing := &Ingress{}
	cert := leaf(t)

	if err := ing.Start(Config{
		DoT:         "127.0.0.1:0",
		Certificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) { return cert, nil },
	}, h, nil); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer ing.Shutdown(context.Background())

	addr := ing.servers[0].Listener.Addr().String()

	// miekg/dns takes a stdlib *crypto/tls.Config, while the listener is built
	// from metacubex/tls -- the fork mihomo speaks everywhere else. The two only
	// have to agree on the wire, which is the point of it being TLS, and
	// D.Server needs nothing more than a net.Listener from our side.
	client := &D.Client{
		Net:       "tcp-tls",
		TLSConfig: &stdtls.Config{ServerName: "dot.test", InsecureSkipVerify: true},
		Timeout:   10 * time.Second,
	}
	msg := new(D.Msg)
	msg.SetQuestion("example.com.", D.TypeA)

	reply, _, err := client.Exchange(msg, addr)
	if err != nil {
		t.Fatalf("exchange: %v", err)
	}
	if len(reply.Answer) != 1 {
		t.Fatalf("got %d answers, want 1", len(reply.Answer))
	}
	select {
	case name := <-h.seen:
		if name != "example.com." {
			t.Errorf("handler saw %q", name)
		}
	default:
		t.Error("handler never saw the query")
	}
}

// The reason Start returns an error instead of logging one: a process that comes
// up healthy with :853 dead has silently taken DNS away from every client, and
// nothing observes it until the complaints start.
func TestStartFailsLoudlyOnABusyPort(t *testing.T) {
	busy, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer busy.Close()

	cert := leaf(t)
	ing := &Ingress{}
	err = ing.Start(Config{
		DoT:         busy.Addr().String(),
		Certificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) { return cert, nil },
	}, &answering{seen: make(chan string, 1)}, nil)
	if err == nil {
		ing.Shutdown(context.Background())
		t.Fatal("Start accepted a port already in use")
	}
}

// A debug listener answers the same policy with no TLS and no client identity.
// On a public address that is an open resolver, so the bind is refused rather
// than logged.
func TestDebugListenerMustBeLoopback(t *testing.T) {
	refused := []string{
		"0.0.0.0:5353",   // every interface
		"192.0.2.1:5353", // a routable address
		"127.0.0.1:0",    // loopback, but names no port
		"127.0.0.1",      // no port at all
	}
	for _, addr := range refused {
		if err := requireLoopback("debug", addr); err == nil {
			t.Errorf("requireLoopback(%q) accepted it", addr)
		}
	}
	for _, addr := range []string{"127.0.0.1:5353", "[::1]:5353"} {
		if err := requireLoopback("debug", addr); err != nil {
			t.Errorf("requireLoopback(%q) rejected a loopback address: %v", addr, err)
		}
	}
}

// A later bind failing must not leave an earlier one serving behind an error the
// caller will read as "nothing came up".
func TestPartialStartLeavesNothingBound(t *testing.T) {
	cert := leaf(t)
	ing := &Ingress{}
	err := ing.Start(Config{
		DoT:         "127.0.0.1:0",
		Debug:       "0.0.0.0:5353", // refused: not loopback
		Certificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) { return cert, nil },
	}, &answering{seen: make(chan string, 1)}, nil)
	if err == nil {
		ing.Shutdown(context.Background())
		t.Fatal("Start accepted a non-loopback debug address")
	}
	if len(ing.servers) != 0 {
		t.Errorf("%d listener(s) left bound after a failed Start", len(ing.servers))
	}
}
