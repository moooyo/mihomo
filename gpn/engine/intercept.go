package engine

import (
	"net"
	"time"

	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/log"
)

// Interceptor adapts the engine to C.Interceptor.
//
// This is what replaced the SOCKS5 listener. The core hands over a connection
// it has already sniffed; the engine terminates it, runs the plugin actions and
// dials the upstream back through the core. What used to be a listener, an
// authenticated greeting, a CONNECT exchange and a reply is now a method call
// with the connection as its argument.
type Interceptor struct {
	proxy  *interceptProxy
	engine *Engine
}

// NewInterceptor wraps a proxy for installation via tunnel.SetInterceptor.
func NewInterceptor(p *interceptProxy) *Interceptor { return &Interceptor{proxy: p} }

var _ C.Interceptor = (*Interceptor)(nil)

// MatchTCP reports whether this connection is one the active extension set has
// asked to see.
//
// It is deliberately stricter than the SOCKS predicate it replaces. That one
// accepted a bare IP target, because a SOCKS client could connect by address
// and the allowlisted SNI would only arrive during the handshake that followed.
// Here the hostname is already known or it never will be: the core sniffs
// before offering the connection, so an empty Host means sniffing failed. The
// old code would have captured that and fallen back to checking the SNI later;
// capturing it now would mean terminating TLS for a connection nobody proved
// belongs to a capture host. No host, no capture, ordinary routing.
func (i *Interceptor) MatchTCP(metadata *C.Metadata) bool {
	if metadata.Host == "" {
		return false
	}
	if metadata.DstPort != 80 && metadata.DstPort != 443 {
		return false
	}
	cfg, err := i.proxy.config.Current()
	if err != nil || !cfg.MITM.Enabled {
		return false
	}
	if i.engine != nil {
		binding, exists := i.engine.CaptureFor(metadata.Host)
		return exists && binding.Ready
	}
	return activeInterceptHost(cfg, metadata.Host)
}

// HandleTCP takes ownership of a captured connection.
//
// conn still holds everything the sniffer peeked -- the ClientHello for :443,
// the request line for :80 -- because the core offers the connection before
// anything consumes it and BufferedConn replays what Peek left behind.
func (i *Interceptor) HandleTCP(conn net.Conn, metadata *C.Metadata) {
	defer conn.Close()

	// The handshake gets a deadline; the session that follows does not. This
	// mirrors what the SOCKS entry did around its greeting, and the reason
	// survives the transport: a client that opens a connection and then says
	// nothing must not hold an engine goroutine and a TLS state machine open
	// indefinitely, while a legitimate long-lived session must not be cut off
	// mid-stream by a timer meant for the handshake.
	_ = conn.SetDeadline(time.Now().Add(15 * time.Second))

	var err error
	if metadata.DstPort == 80 {
		_ = conn.SetDeadline(time.Time{})
		err = i.proxy.servePlainHTTPConnection(conn)
	} else {
		err = i.proxy.serveTLSConnection(conn, metadata.Host)
	}
	if err != nil {
		log.Debugln("[GPN] intercepted session for %s failed: %v", metadata.Host, err)
	}
}

// MatchUDP always leaves QUIC to the gateway's fixed UDP/443 reject rule.
//
// Extension interception supports plain HTTP and TLS over TCP only. Keeping
// this refusal independent of document state is the defensive boundary: even
// an invalid in-memory value cannot turn datagram capture back on.
func (*Interceptor) MatchUDP(*C.Metadata) bool { return false }

// HandleUDP retains the interface method for the dormant bridge. The core calls
// it only after MatchUDP accepts an association, and MatchUDP always refuses.
func (i *Interceptor) HandleUDP(metadata *C.Metadata) (C.PacketConn, error) {
	return i.proxy.captureQUIC(metadata)
}
