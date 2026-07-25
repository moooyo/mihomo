package socks

import (
	"errors"
	"net"
	"net/netip"
	"sync"

	"github.com/metacubex/mihomo/log"
	"github.com/metacubex/mihomo/transport/socks5"
)

// maxAssociationsPerListener bounds how many concurrent UDP associations one
// SOCKS listener will hold. The table is keyed by client address, so without a
// bound a peer that can open control connections can grow it without limit.
const maxAssociationsPerListener = 512

var errTooManyAssociations = errors.New("socks: too many concurrent UDP associations")

// association records that one authenticated TCP control connection authorized
// UDP traffic from one client address.
//
// RFC 1928 makes UDP ASSOCIATE a request on the control connection, and the
// association's lifetime is the control connection's lifetime. mihomo
// historically honoured neither half: the ASSOCIATE branch discarded both the
// authenticated user and the client address the client committed to, and the
// UDP listener accepted datagrams from anyone. That is the gap this closes.
type association struct {
	user string
	// port 0 means the client sent the wildcard address in its ASSOCIATE
	// request and has not committed to a source port, so any port from ip is
	// accepted — but still only from ip, and still only while its control
	// connection is open.
	ip   netip.Addr
	port uint16
}

func (a *association) matches(from netip.AddrPort) bool {
	if a.ip != from.Addr().Unmap() {
		return false
	}
	return a.port == 0 || a.port == from.Port()
}

// listenerAssociations holds one listener's table.
type listenerAssociations struct {
	mu      sync.RWMutex
	entries map[*association]struct{}
}

// associationTable is keyed by the listener's local address.
//
// The TCP and UDP halves of one SOCKS inbound are constructed independently and
// share no object, but they always bind the same address string. Keying on it
// is what lets the UDP listener find the table the TCP handshake wrote to
// without a new parameter on every constructor in the chain.
type associationTable struct {
	mu sync.Mutex
	m  map[string]*listenerAssociations
}

var associations = &associationTable{m: map[string]*listenerAssociations{}}

func (t *associationTable) forListener(addr string) *listenerAssociations {
	t.mu.Lock()
	defer t.mu.Unlock()
	la, ok := t.m[addr]
	if !ok {
		la = &listenerAssociations{entries: map[*association]struct{}{}}
		t.m[addr] = la
	}
	return la
}

// registerAssociation authorizes UDP traffic from a client for as long as the
// returned release function has not been called.
//
// target is the DST.ADDR/DST.PORT the client sent in its ASSOCIATE request,
// which is its declaration of where it will send from. A wildcard or unparsable
// value falls back to the control connection's own peer address — never to
// "anyone", which is what the current code effectively allows.
func registerAssociation(localAddr string, ctrlPeer net.Addr, target socks5.Addr, user string) (func(), error) {
	ip, port := associationSource(ctrlPeer, target)
	if !ip.IsValid() {
		return nil, errors.New("socks: cannot determine the association's client address")
	}

	la := associations.forListener(localAddr)
	entry := &association{user: user, ip: ip, port: port}

	la.mu.Lock()
	if len(la.entries) >= maxAssociationsPerListener {
		la.mu.Unlock()
		return nil, errTooManyAssociations
	}
	la.entries[entry] = struct{}{}
	la.mu.Unlock()

	return func() {
		la.mu.Lock()
		delete(la.entries, entry)
		la.mu.Unlock()
	}, nil
}

// associationSource decides which client address an association covers.
func associationSource(ctrlPeer net.Addr, target socks5.Addr) (netip.Addr, uint16) {
	fallback := netip.Addr{}
	if ap, err := netip.ParseAddrPort(ctrlPeer.String()); err == nil {
		fallback = ap.Addr().Unmap()
	}

	if target == nil {
		return fallback, 0
	}
	udpAddr := target.UDPAddr()
	if udpAddr == nil {
		return fallback, 0
	}
	ip, ok := netip.AddrFromSlice(udpAddr.IP)
	if !ok {
		return fallback, 0
	}
	ip = ip.Unmap()
	// A client that sends the wildcard address is saying "I have not bound
	// yet"; it is not saying "accept everyone".
	if !ip.IsValid() || ip.IsUnspecified() {
		return fallback, 0
	}
	return ip, uint16(udpAddr.Port)
}

// lookupAssociation resolves the authenticated user behind a datagram source.
func lookupAssociation(localAddr string, from net.Addr) (string, bool) {
	ap, err := netip.ParseAddrPort(from.String())
	if err != nil {
		return "", false
	}
	la := associations.forListener(localAddr)

	la.mu.RLock()
	defer la.mu.RUnlock()
	for entry := range la.entries {
		if entry.matches(ap) {
			return entry.user, true
		}
	}
	return "", false
}

// dropUnassociated logs a rejected datagram at debug level. It is deliberately
// not a warning: an unassociated datagram is the expected steady state for a
// listener under scan, and warning on each would be a log-flood primitive.
func dropUnassociated(localAddr string, from net.Addr) {
	log.Debugln("[SOCKS] dropped UDP datagram from unassociated source %s on %s", from, localAddr)
}
