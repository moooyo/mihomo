package dns

import (
	"context"
	"time"

	D "github.com/miekg/dns"
)

// arbitrate runs the china and trust groups concurrently and adopts one reply
// by a single rule: if china returned an address inside the CN set, china wins;
// otherwise trust does.
//
// The decision is by SET MEMBERSHIP, never by which reply arrived first and
// never by upstream health. That is the whole point of running both: a
// domestic CDN answers from a domestic resolver, and the only way to know
// whether a name has a domestic presence is to ask a domestic resolver and look
// at what comes back. Racing them would make the answer depend on the weather.
//
// Both are bounded by the caller's deadline and no second timeout is added.
// arbitrate derives a cancellable child so the abandoned group is torn down on
// return rather than lingering on a hung upstream until the caller's context
// expires.
//
// The stats are observability only. china is always awaited so its outcome is
// always counted; trust is counted only when it was actually consulted, since
// when china wins its result is never read.
func arbitrate(ctx context.Context, q *D.Msg, china, trust Exchanger, cn *CNSet, stats *counters) (*D.Msg, string, error) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	type result struct {
		msg *D.Msg
		err error
	}
	chinaCh := make(chan result, 1)
	trustCh := make(chan result, 1)

	// Only a COMPLETED exchange is a latency sample. Timing failures too would
	// move the number in contradictory directions: a dead upstream contributes
	// full-timeout samples that inflate it while an open breaker contributes
	// near-zero non-attempts that deflate it, so an unhealthy group could read
	// faster than a healthy one. Cancellation is sharper still -- when china
	// wins, the deferred cancel aborts a trust exchange that may still be
	// dialing, and timing that abort would record "how long until china
	// answered" as trust's round trip. Group health is the ok/err counters, not
	// these samples.
	go func() {
		start := time.Now()
		m, err := china.Exchange(ctx, q)
		if err == nil {
			stats.recordChinaLatency(time.Since(start))
		}
		chinaCh <- result{m, err}
	}()
	go func() {
		start := time.Now()
		m, err := trust.Exchange(ctx, q)
		if err == nil {
			stats.recordTrustLatency(time.Since(start))
		}
		trustCh <- result{m, err}
	}()

	chinaRes := <-chinaCh
	stats.bumpChina(chinaRes.err == nil)
	if chinaRes.err == nil && hasCNAddress(chinaRes.msg, cn) {
		return chinaRes.msg, "china", nil
	}

	trustRes := <-trustCh
	stats.bumpTrust(trustRes.err == nil)
	if trustRes.err != nil {
		return nil, "", trustRes.err
	}
	return trustRes.msg, "trust", nil
}

// hasCNAddress reports whether reply carries at least one A record inside the
// CN set.
//
// A truncated reply is treated as not-CN. It carries only part of the answer,
// so deciding membership on it can call a domestic name foreign and send the
// whole of it through the gateway -- and the trust group is configured
// independently and can answer the question properly.
func hasCNAddress(reply *D.Msg, cn *CNSet) bool {
	if reply == nil || reply.Truncated {
		return false
	}
	for _, rr := range reply.Answer {
		if a, ok := rr.(*D.A); ok {
			if addr, ok := netipFromIP(a.A); ok && cn.Contains(addr) {
				return true
			}
		}
	}
	return false
}
