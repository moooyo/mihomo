package tunnel

import (
	"sync/atomic"

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
// Not called yet. The UDP path cannot simply hand a connection away: it builds
// an association, so a capture there also owns nat.NewWriteBackProxy and the
// handleUDPToLocal pump. That plumbing deserves its own change with its own
// tests rather than a guess appended to the TCP one, and until it exists
// gateway QUIC is handled by the fixed UDP/443 reject, which makes a capable
// client fall back to TCP.
func captureUDPFor(metadata *C.Metadata) C.Interceptor { //nolint:unused // wired with the H3 capture path
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

// ResolveMetadata exposes rule evaluation to fork-owned packages.
//
// The interception engine needs the same answer the core would have reached for
// a destination, because its upstream must obey the operator's routing exactly
// as an uncaptured connection would. Exporting the existing function is how that
// stays one implementation rather than two that drift.
func ResolveMetadata(metadata *C.Metadata) (C.Proxy, C.Rule, error) {
	return resolveMetadata(metadata)
}
