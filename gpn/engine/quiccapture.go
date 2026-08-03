package engine

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"time"

	N "github.com/metacubex/mihomo/common/net"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/log"
	"github.com/metacubex/quic-go"
	"github.com/metacubex/quic-go/http3"
	"github.com/metacubex/tls"

	"github.com/metacubex/http"
)

// The datagram half of interception.
//
// Capture over TCP is a handover: the core has a connection, nothing has been
// read off it, and the engine takes ownership. UDP has no connection to give
// away. The core builds an association and asks the outbound for a
// C.PacketConn, which it then drives as though it were the remote -- writes to
// it are the client's datagrams, reads from it are the remote's replies. So the
// engine returns one of those instead, and what sits behind it is a QUIC
// listener rather than a socket.
//
// The whole process shares one listener, fed by one in-memory net.PacketConn
// that every captured association writes into. Not one listener per
// association, because a QUIC connection is not a 4-tuple. A client that
// rebinds -- Wi-Fi to cellular, or a NAT that re-maps the port -- keeps its
// connection IDs and expects the server to follow it there. The core sees that
// as a brand new association; a per-association listener would see a packet
// carrying connection IDs it has never issued and answer with a stateless
// reset. Feeding every association into one listener is what makes migration
// work, because quic-go routes on the connection ID and does not care which
// association carried the datagram in.
//
// The handler is the same interceptProxy.ServeHTTP the TLS path uses. An H3
// request therefore runs the same actions, resolves through the same upstream
// generation, and is bounded by the same body budget as the same request
// arriving over TLS on TCP. Nothing about a transformation is transport-aware,
// and this is where that pays for itself.

const (
	// Datagrams in flight per direction before the queue drops. UDP may drop,
	// and blocking would be worse than dropping in both directions: a blocked
	// write stalls the QUIC server's send loop, and a blocked read stalls the
	// core's per-association Process loop -- which carries every other datagram
	// for this client. QUIC retransmits what it loses; it cannot un-stall a
	// send loop.
	quicAssociationQueue = 128
	quicBridgeQueue      = 512

	// How long the QUIC layer keeps a connection whose peer has gone quiet. The
	// core tears the association down after its own 60s idle timeout, so a
	// shorter budget here would only mean answering a returning client with a
	// closed connection instead of a live one.
	quicCaptureIdleTimeout = 90 * time.Second
)

var (
	errQUICCaptureClosed = errors.New("gpn/engine: the QUIC capture bridge is closed")
	// errQUICAssociationTaken is what a second association from one client
	// address to a different gateway address gets. See registerAssociation.
	errQUICAssociationTaken = errors.New("gpn/engine: the client address already has a captured association elsewhere")
)

// quicDatagram is one datagram in flight through the bridge, with the address
// that identifies the association it belongs to.
type quicDatagram struct {
	payload []byte
	addr    net.Addr
}

// quicBridge is the net.PacketConn the shared QUIC listener is built on.
//
// It is not a socket and does not pretend to be one. A read returns whatever
// the core last wrote into some captured association, addressed as the client
// that sent it; a write is routed back to the association that client belongs
// to. The addressing is the real client address rather than a synthetic one,
// which is what lets quic-go recognise a migrating client as the same peer.
type quicBridge struct {
	incoming chan quicDatagram

	mu     sync.RWMutex
	routes map[netip.AddrPort]*quicAssociation
	closed bool

	done chan struct{}

	deadlineMu   sync.Mutex
	readDeadline time.Time
	readTimer    *time.Timer
}

func newQUICBridge() *quicBridge {
	return &quicBridge{
		incoming: make(chan quicDatagram, quicBridgeQueue),
		routes:   make(map[netip.AddrPort]*quicAssociation),
		done:     make(chan struct{}),
	}
}

// deliver hands a client datagram to the QUIC listener. It drops rather than
// blocks: see quicAssociationQueue.
func (b *quicBridge) deliver(payload []byte, from net.Addr) {
	select {
	case <-b.done:
	case b.incoming <- quicDatagram{payload: payload, addr: from}:
	default:
	}
}

func (b *quicBridge) ReadFrom(p []byte) (int, net.Addr, error) {
	datagram, err := b.read()
	if err != nil {
		return 0, nil, err
	}
	n := copy(p, datagram.payload)
	return n, datagram.addr, nil
}

func (b *quicBridge) read() (quicDatagram, error) {
	timeout := b.armReadTimer()
	select {
	case <-b.done:
		return quicDatagram{}, net.ErrClosed
	case datagram := <-b.incoming:
		return datagram, nil
	case <-timeout:
		return quicDatagram{}, timeoutError{}
	}
}

// armReadTimer returns the channel that fires at the current read deadline, or
// nil when there is none. The timer is reused across reads because this is a
// per-datagram path and a fresh timer per read would allocate once per packet.
func (b *quicBridge) armReadTimer() <-chan time.Time {
	b.deadlineMu.Lock()
	defer b.deadlineMu.Unlock()
	if b.readDeadline.IsZero() {
		return nil
	}
	remaining := time.Until(b.readDeadline)
	if b.readTimer == nil {
		b.readTimer = time.NewTimer(remaining)
	} else {
		if !b.readTimer.Stop() {
			select {
			case <-b.readTimer.C:
			default:
			}
		}
		b.readTimer.Reset(remaining)
	}
	return b.readTimer.C
}

func (b *quicBridge) WriteTo(p []byte, addr net.Addr) (int, error) {
	target, ok := addrPortOf(addr)
	if !ok {
		return 0, fmt.Errorf("gpn/engine: QUIC capture cannot address %v", addr)
	}
	b.mu.RLock()
	association := b.routes[target]
	closed := b.closed
	b.mu.RUnlock()
	if closed {
		return 0, net.ErrClosed
	}
	if association == nil {
		// The association went away -- an idle timeout, or the client stopped.
		// Reporting success is deliberate: a QUIC server that sees a write error
		// tears the connection down, and this datagram is merely undeliverable,
		// which on a datagram transport is not an error the sender must act on.
		return len(p), nil
	}
	association.deliver(p)
	return len(p), nil
}

func (b *quicBridge) Close() error {
	b.mu.Lock()
	if b.closed {
		b.mu.Unlock()
		return nil
	}
	b.closed = true
	b.mu.Unlock()
	close(b.done)
	return nil
}

// LocalAddr is the unspecified address, which is the honest answer: this
// listener serves every gateway address at once, because the associations
// feeding it were accepted on all of them.
func (b *quicBridge) LocalAddr() net.Addr {
	return &net.UDPAddr{IP: net.IPv4zero, Port: 443}
}

func (b *quicBridge) SetDeadline(t time.Time) error {
	return b.SetReadDeadline(t)
}

func (b *quicBridge) SetReadDeadline(t time.Time) error {
	b.deadlineMu.Lock()
	b.readDeadline = t
	b.deadlineMu.Unlock()
	return nil
}

// SetWriteDeadline is a no-op because a write here is a channel send that
// either completes or drops. There is nothing for a deadline to interrupt.
func (b *quicBridge) SetWriteDeadline(time.Time) error { return nil }

// registerAssociation binds a client address to the association that carries
// it, replacing an association to the same gateway address and refusing one to
// a different address.
//
// The refusal is the interesting case. Routing back to a client is keyed on the
// address the datagram is addressed to, and that address is all a write gives
// us -- so two live associations from one client address to two different
// gateway addresses would be indistinguishable on the way back, and one of them
// would receive the other's traffic. A QUIC client does not do this: its socket
// is connected, so one source port reaches one destination. Refusing rather
// than guessing means the pathological case falls through to ordinary routing,
// where the fixed UDP/443 reject turns it into a TCP connection that is
// captured properly.
func (b *quicBridge) registerAssociation(association *quicAssociation) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed {
		return errQUICCaptureClosed
	}
	if existing := b.routes[association.client]; existing != nil {
		if existing.origin.String() != association.origin.String() {
			return errQUICAssociationTaken
		}
		// Same client, same gateway address: the previous association timed out
		// and the client came back. Retire the old one so its reader stops.
		existing.close()
	}
	b.routes[association.client] = association
	return nil
}

// releaseAssociation removes a route, but only if it still points at the
// association doing the releasing. A late close must not unregister the
// association that replaced it.
func (b *quicBridge) releaseAssociation(association *quicAssociation) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.routes[association.client] == association {
		delete(b.routes, association.client)
	}
}

// quicAssociation is one captured client, seen from the core's side.
//
// It implements the raw half of a packet conn; deadlines are added by wrapping
// it, and the C.Connection methods are added by quicPacketConn.
type quicAssociation struct {
	bridge *quicBridge
	// client is the client's own address, which is both the association's
	// identity and the address quic-go sees its peer at.
	client netip.AddrPort
	// origin is the gateway address the client sent to. Every datagram read
	// back reports it as the source, so the reply reaches the client from the
	// address it was talking to.
	origin *net.UDPAddr
	// host is the captured name, for diagnostics only.
	host string

	out       chan []byte
	done      chan struct{}
	closeOnce sync.Once
}

func (a *quicAssociation) deliver(payload []byte) {
	buffered := make([]byte, len(payload))
	copy(buffered, payload)
	select {
	case <-a.done:
	case a.out <- buffered:
	default:
	}
}

func (a *quicAssociation) close() {
	a.closeOnce.Do(func() { close(a.done) })
}

// WriteTo is the core handing over a datagram the client sent. The destination
// it names is this gateway, so it is not carried: what the bridge needs is who
// sent it.
func (a *quicAssociation) WriteTo(p []byte, _ net.Addr) (int, error) {
	select {
	case <-a.done:
		return 0, net.ErrClosed
	default:
	}
	buffered := make([]byte, len(p))
	copy(buffered, p)
	a.bridge.deliver(buffered, net.UDPAddrFromAddrPort(a.client))
	return len(p), nil
}

func (a *quicAssociation) ReadFrom(p []byte) (int, net.Addr, error) {
	data, _, addr, err := a.WaitReadFrom()
	if err != nil {
		return 0, nil, err
	}
	return copy(p, data), addr, nil
}

// WaitReadFrom returns a datagram the QUIC server produced for this client.
//
// It carries no deadline of its own: the association is wrapped in mihomo's
// deadline packet conn, which is what the core's 60s idle read expects to be
// honoured. Implementing it twice would give the association two answers to the
// same question.
func (a *quicAssociation) WaitReadFrom() ([]byte, func(), net.Addr, error) {
	select {
	case <-a.done:
		return nil, nil, nil, net.ErrClosed
	case payload := <-a.out:
		return payload, nil, a.origin, nil
	}
}

func (a *quicAssociation) Close() error {
	a.close()
	a.bridge.releaseAssociation(a)
	return nil
}

func (a *quicAssociation) LocalAddr() net.Addr              { return a.origin }
func (a *quicAssociation) SetDeadline(time.Time) error      { return nil }
func (a *quicAssociation) SetReadDeadline(time.Time) error  { return nil }
func (a *quicAssociation) SetWriteDeadline(time.Time) error { return nil }

// quicPacketConn is what the core receives: a deadline-honouring packet conn
// wearing the C.Connection methods every outbound's conn wears.
type quicPacketConn struct {
	N.EnhancePacketConn
	association *quicAssociation
	chain       C.Chain
	pdChain     C.Chain
}

var _ C.PacketConn = (*quicPacketConn)(nil)

// ResolveUDP is a no-op. The destination is this gateway; there is nothing to
// look up, and the association is already bound to the client it serves.
func (c *quicPacketConn) ResolveUDP(context.Context, *C.Metadata) error { return nil }

func (c *quicPacketConn) RemoteDestination() string { return c.association.host }

func (c *quicPacketConn) Chains() C.Chain         { return c.chain }
func (c *quicPacketConn) ProviderChains() C.Chain { return c.pdChain }

func (c *quicPacketConn) AppendToChains(a C.ProxyAdapter) {
	c.chain = append(c.chain, a.Name())
	c.pdChain = append(c.pdChain, a.ProxyInfo().ProviderName)
}

// captureQUIC takes ownership of a datagram association for a captured host.
//
// The listener is started on the first captured association and lives for the
// process, because the engine is assembled once: gpn.StartInterception runs at
// startup and document changes are an atomic pointer swap inside the config
// store, never a rebuild. A listener whose lifetime tracked the document would
// therefore have exactly one lifetime anyway, and would drop every live H3
// session for an edit that did not concern it.
func (p *interceptProxy) captureQUIC(metadata *C.Metadata) (C.PacketConn, error) {
	origin := metadata.UDPAddr()
	if origin == nil {
		return nil, fmt.Errorf("gpn/engine: captured association for %s has no destination address", metadata.Host)
	}
	client := metadata.SourceAddrPort()
	if !client.IsValid() {
		return nil, fmt.Errorf("gpn/engine: captured association for %s has no client address", metadata.Host)
	}

	bridge, err := p.quicListener()
	if err != nil {
		return nil, err
	}

	association := &quicAssociation{
		bridge: bridge,
		client: client,
		origin: origin,
		host:   metadata.Host,
		out:    make(chan []byte, quicAssociationQueue),
		done:   make(chan struct{}),
	}
	if err := bridge.registerAssociation(association); err != nil {
		return nil, err
	}
	log.Debugln("[GPN] captured QUIC association for %s from %s", metadata.Host, client)
	return &quicPacketConn{
		EnhancePacketConn: N.NewDeadlineEnhancePacketConn(association),
		association:       association,
	}, nil
}

// quicListener starts the shared bridge, listener and H3 server once.
func (p *interceptProxy) quicListener() (*quicBridge, error) {
	p.quicMu.Lock()
	defer p.quicMu.Unlock()
	if p.quicBridge != nil {
		return p.quicBridge, nil
	}

	// One config for one long-lived listener, so crypto/tls owns its own
	// session ticket keys and rotates them. The TCP path sets keys explicitly
	// only because it builds a config per connection and a per-connection
	// config's keys are never seen twice.
	tlsConfig := http3.ConfigureTLSConfig(&tls.Config{
		MinVersion:     tls.VersionTLS13,
		GetCertificate: p.certificates.GetCertificate,
	})
	bridge := newQUICBridge()
	listener, err := quic.ListenEarly(bridge, tlsConfig, &quic.Config{
		Versions:       []quic.Version{quic.Version1, quic.Version2},
		MaxIdleTimeout: quicCaptureIdleTimeout,
		Allow0RTT:      false,
	})
	if err != nil {
		_ = bridge.Close()
		return nil, fmt.Errorf("gpn/engine: QUIC capture listener: %w", err)
	}
	server := &http3.Server{Handler: p, IdleTimeout: quicCaptureIdleTimeout}
	go func() {
		if err := server.ServeListener(listener); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Warnln("[GPN] QUIC capture listener stopped: %v", err)
		}
	}()
	p.quicBridge = bridge
	p.quicServer = server
	log.Infoln("[GPN] QUIC capture listener started")
	return bridge, nil
}

// closeQUICCapture stops the listener and the bridge. Nothing in the running
// gateway calls it -- the engine is assembled once -- but a test that starts a
// listener must be able to stop it, and a leaked listener in a test binary is a
// goroutine that outlives the test that made it.
func (p *interceptProxy) closeQUICCapture() {
	p.quicMu.Lock()
	server, bridge := p.quicServer, p.quicBridge
	p.quicServer, p.quicBridge = nil, nil
	p.quicMu.Unlock()
	if server != nil {
		_ = server.Close()
	}
	if bridge != nil {
		_ = bridge.Close()
	}
}

func addrPortOf(addr net.Addr) (netip.AddrPort, bool) {
	if addr == nil {
		return netip.AddrPort{}, false
	}
	if udp, ok := addr.(*net.UDPAddr); ok {
		if udp == nil {
			return netip.AddrPort{}, false
		}
		parsed := udp.AddrPort()
		return parsed, parsed.IsValid()
	}
	parsed, err := netip.ParseAddrPort(addr.String())
	if err != nil {
		return netip.AddrPort{}, false
	}
	return parsed, parsed.IsValid()
}

// timeoutError is what a read past its deadline returns. net.Error rather than
// a bare error because quic-go distinguishes a timed-out read, which it retries,
// from a broken conn, which ends the listener.
type timeoutError struct{}

func (timeoutError) Error() string   { return "i/o timeout" }
func (timeoutError) Timeout() bool   { return true }
func (timeoutError) Temporary() bool { return true }
