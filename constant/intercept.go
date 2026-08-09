package constant

import "net"

// Interceptor takes ownership of connections whose destination has been
// sniffed but not yet routed.
//
// It exists so the core can hand a connection to a transformation stage without
// knowing anything about it. The stage that implements this used to be a
// separate process reached over an authenticated loopback SOCKS5 hop in each
// direction; the interface is what remains once both hops are a function call.
//
// The contract is deliberately narrow. Match runs on the hot path for every
// sniffed connection and must be cheap and allocation-free. Handle takes
// ownership: it closes the connection, and the core does not touch it again.
type Interceptor interface {
	// MatchTCP reports whether this connection should be captured. It runs
	// after sniffing has filled Host and before rule resolution chooses an
	// outbound, so a true answer means the operator's own routing is bypassed
	// for this connection and the interceptor's egress is used instead.
	//
	// An implementation MUST return false for Type == INNER. The interceptor
	// reaches its own upstreams by dialing back through the tunnel, which
	// produces exactly such a connection; capturing it would hand the
	// interceptor its own output forever.
	MatchTCP(metadata *Metadata) bool

	// HandleTCP takes ownership of conn, which is the buffered connection the
	// sniffer peeked -- its ClientHello or request line is still unread. The
	// implementation is responsible for closing it.
	HandleTCP(conn net.Conn, metadata *Metadata)
}
