package tunnel

import (
	"sync/atomic"

	"github.com/metacubex/mihomo/component/nat"
	C "github.com/metacubex/mihomo/constant"
)

// This file is fork-owned. It exists so the hooks in tunnel.go stay three lines
// each: new files do not conflict on rebase, edited upstream files do.

var interceptor atomic.Pointer[C.Interceptor]

// SetInterceptor installs (or with nil, removes) the capture stage.
//
// An atomic pointer rather than a mutex-guarded field because the interceptor is
// consulted on every sniffed connection and must never contend with a
// reconfiguration that happens a few times an hour.
func SetInterceptor(i C.Interceptor) {
	if i == nil {
		interceptor.Store(nil)
		return
	}
	interceptor.Store(&i)
}

// captureTCPFor returns the interceptor that wants this connection, or nil.
//
// The decision lives here rather than at the call site for one reason: the
// INNER guard. The interceptor reaches its upstreams by dialing back through
// this same tunnel, which arrives as Type == INNER. Capturing that would feed
// the interceptor its own output forever. Putting the guard behind the only
// function that can answer "yes" makes it impossible to add a second call site
// that forgets it.
func captureTCPFor(metadata *C.Metadata) C.Interceptor {
	p := interceptor.Load()
	if p == nil || metadata.Type == C.INNER {
		return nil
	}
	ic := *p
	if !ic.MatchTCP(metadata) {
		return nil
	}
	return ic
}

// captureUDPFor is the datagram equivalent, used for QUIC.
//
// Same INNER guard and for the same reason: the engine reaches its own H3
// upstreams by listening on a packet conn dialled back through this tunnel.
func captureUDPFor(metadata *C.Metadata) C.Interceptor {
	p := interceptor.Load()
	if p == nil || metadata.Type == C.INNER {
		return nil
	}
	ic := *p
	if !ic.MatchUDP(metadata) {
		return nil
	}
	return ic
}

// dialCapturedUDP completes an association the interceptor has claimed.
//
// It lives here rather than at the call site so the hook in tunnel.go stays
// three lines. The bookkeeping is deliberately the same as the uncaptured path
// below it -- the destination NAT mapping, the write-back proxy, the reader
// pump -- because the core still owns both directions of the association. What
// capture replaces is only where the datagrams go: the interceptor's packet
// conn instead of an outbound's.
//
// There is no statistic tracker and no rule, for the same reason the TCP
// capture has neither: this association was never routed. The engine's own
// upstream is dialled back through the tunnel and appears in the connection
// table there, which is the row that describes an egress choice actually made.
func dialCapturedUDP(
	ic C.Interceptor,
	packet C.PacketAdapter,
	sender C.PacketSender,
	originMetadata *C.Metadata,
	metadata *C.Metadata,
	key string,
) (C.PacketConn, C.WriteBackProxy, error) {
	pc, err := ic.HandleUDP(metadata)
	if err != nil {
		return nil, nil, err
	}
	dialMetadata := metadata.Pure()
	sender.AddMapping(originMetadata, dialMetadata)
	writeBackProxy := nat.NewWriteBackProxy(packet)
	go handleUDPToLocal(writeBackProxy, pc, sender, key, dialMetadata.AddrPort())
	return pc, writeBackProxy, nil
}

// ResolveMetadata exposes rule evaluation to fork-owned packages.
//
// The interception engine needs the same answer the core would have reached for
// a destination, because its upstream must obey the operator's routing exactly
// as an uncaptured connection would. Exporting the existing function is how that
// stays one implementation rather than two that drift.
func ResolveMetadata(metadata *C.Metadata) (C.Proxy, C.Rule, error) {
	return resolveMetadata(metadata)
}
