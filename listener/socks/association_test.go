package socks

import (
	"net"
	"testing"

	"github.com/metacubex/mihomo/transport/socks5"
)

func udpAddr(t *testing.T, s string) net.Addr {
	t.Helper()
	a, err := net.ResolveUDPAddr("udp", s)
	if err != nil {
		t.Fatalf("resolve %q: %v", s, err)
	}
	return a
}

func tcpAddr(t *testing.T, s string) net.Addr {
	t.Helper()
	a, err := net.ResolveTCPAddr("tcp", s)
	if err != nil {
		t.Fatalf("resolve %q: %v", s, err)
	}
	return a
}

// A client that commits to an exact source address gets exactly that address
// authorized — not its whole host, and not everyone.
func TestAssociationBindsExactSource(t *testing.T) {
	const listen = "127.0.0.1:11080"
	release, err := registerAssociation(listen, tcpAddr(t, "127.0.0.1:50000"), socks5.ParseAddr("127.0.0.1:40000"), "cap-1")
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	defer release()

	if user, ok := lookupAssociation(listen, udpAddr(t, "127.0.0.1:40000")); !ok || user != "cap-1" {
		t.Fatalf("exact source: user=%q ok=%v", user, ok)
	}
	if _, ok := lookupAssociation(listen, udpAddr(t, "127.0.0.1:40001")); ok {
		t.Fatal("a different source port was accepted")
	}
	if _, ok := lookupAssociation(listen, udpAddr(t, "127.0.0.2:40000")); ok {
		t.Fatal("a different source address was accepted")
	}
}

// The wildcard address means "I have not bound a port yet", so the association
// falls back to the control connection's own host with any port. It must not
// degrade to accepting every host.
func TestAssociationWildcardFallsBackToControlPeer(t *testing.T) {
	const listen = "127.0.0.1:11081"
	release, err := registerAssociation(listen, tcpAddr(t, "10.0.0.5:50000"), socks5.ParseAddr("0.0.0.0:0"), "cap-2")
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	defer release()

	if user, ok := lookupAssociation(listen, udpAddr(t, "10.0.0.5:12345")); !ok || user != "cap-2" {
		t.Fatalf("control peer host: user=%q ok=%v", user, ok)
	}
	if _, ok := lookupAssociation(listen, udpAddr(t, "10.0.0.6:12345")); ok {
		t.Fatal("wildcard association accepted a different host")
	}
}

// The association's lifetime is the control connection's lifetime. Releasing it
// must immediately stop authorizing datagrams.
func TestAssociationReleaseRevokes(t *testing.T) {
	const listen = "127.0.0.1:11082"
	release, err := registerAssociation(listen, tcpAddr(t, "127.0.0.1:50000"), socks5.ParseAddr("127.0.0.1:40000"), "cap-3")
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	if _, ok := lookupAssociation(listen, udpAddr(t, "127.0.0.1:40000")); !ok {
		t.Fatal("association did not authorize its own source")
	}
	release()
	if _, ok := lookupAssociation(listen, udpAddr(t, "127.0.0.1:40000")); ok {
		t.Fatal("a released association still authorized traffic")
	}
}

// Associations are scoped to the listener that created them; one listener's
// credential must not authorize traffic arriving on another.
func TestAssociationIsScopedToListener(t *testing.T) {
	release, err := registerAssociation("127.0.0.1:11083", tcpAddr(t, "127.0.0.1:50000"), socks5.ParseAddr("127.0.0.1:40000"), "cap-4")
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	defer release()

	if _, ok := lookupAssociation("127.0.0.1:11084", udpAddr(t, "127.0.0.1:40000")); ok {
		t.Fatal("an association leaked across listeners")
	}
}

func TestAssociationLimitIsEnforced(t *testing.T) {
	const listen = "127.0.0.1:11085"
	releases := make([]func(), 0, maxAssociationsPerListener)
	defer func() {
		for _, r := range releases {
			r()
		}
	}()

	for i := 0; i < maxAssociationsPerListener; i++ {
		r, err := registerAssociation(listen, tcpAddr(t, "127.0.0.1:50000"), socks5.ParseAddr("127.0.0.1:40000"), "cap")
		if err != nil {
			t.Fatalf("register %d: %v", i, err)
		}
		releases = append(releases, r)
	}
	if _, err := registerAssociation(listen, tcpAddr(t, "127.0.0.1:50000"), socks5.ParseAddr("127.0.0.1:40000"), "cap"); err == nil {
		t.Fatal("the association limit was not enforced")
	}
}

// An unassociated source must resolve to nothing at all, which is what makes
// the UDP handler drop it.
func TestLookupWithoutAssociationFails(t *testing.T) {
	if _, ok := lookupAssociation("127.0.0.1:11086", udpAddr(t, "127.0.0.1:40000")); ok {
		t.Fatal("an unassociated source resolved")
	}
}
