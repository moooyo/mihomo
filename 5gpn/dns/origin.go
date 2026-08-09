package dns

import (
	"context"
	"strings"
	"time"

	D "github.com/miekg/dns"
)

// The origin boundary is where mihomo re-resolves a hostname the sniffer
// recovered, after a client has already been steered here.
//
// It is a different question from the one the client asked. The client asked
// "where should I connect", and the answer was this gateway; mihomo is asking
// "where does this name actually live", and answering that with the gateway
// address would point the box at itself. So the ordered policy, the CN
// arbitration and the gateway rewrite are all absent here by construction, not
// by configuration -- there is no setting that turns them on.
//
// What the boundary does own is two things the client path cannot. It forces
// the operator's china/trust binding for a captured host, so an extension that
// declared its origin lives behind a domestic resolver gets one. And it answers
// AAAA with synthetic NODATA, which is what actually keeps egress on IPv4:
// mihomo issues the AAAA query unconditionally, and were it answered, mihomo
// would learn the origin's real IPv6 addresses and race them against the v4
// ones. A winning v6 leg completes its TCP dial, which retires mihomo's
// dual-stack fallback, and a destination that refuses or mislocates the
// gateway's datacenter prefix then fails at the application layer with nothing
// left to fall back to.
//
// The accepted consequence is that an origin published only as AAAA is
// unreachable through the gateway. An IPv6 answer would not have been dialable
// on an IPv4-only data plane either.

// origin is the handler bound to the loopback origin listener.
type origin struct{ r *Resolver }

// Origin returns the handler mihomo's own resolver queries.
func (r *Resolver) Origin() D.Handler { return origin{r: r} }

func (o origin) ServeDNS(w D.ResponseWriter, req *D.Msg) {
	r := o.r
	if len(req.Question) != 1 {
		_ = w.WriteMsg(rcode(req, D.RcodeFormatError))
		return
	}
	if req.Question[0].Qclass != D.ClassINET {
		_ = w.WriteMsg(rcode(req, D.RcodeNotImplemented))
		return
	}
	if !tryAcquire(r.originSem) {
		r.stats.bump(&r.stats.refused)
		_ = w.WriteMsg(rcode(req, D.RcodeRefused))
		return
	}
	defer releaseAdmission(r.originSem)

	runtime := r.snapshot()
	if runtime == nil {
		_ = w.WriteMsg(rcode(req, D.RcodeServerFailure))
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), runtime.tuning.timeout)
	defer cancel()

	q := req.Question[0]
	resp := r.resolveOriginRuntime(ctx, q, req, runtime)
	if isUDP(w) {
		resp.Truncate(udpBudget(req))
	}
	_ = w.WriteMsg(resp)
}

// resolveOrigin answers one origin lookup.
func (r *Resolver) resolveOrigin(ctx context.Context, q D.Question, req *D.Msg) *D.Msg {
	return r.resolveOriginRuntime(ctx, q, req, r.snapshot())
}

func (r *Resolver) resolveOriginRuntime(ctx context.Context, q D.Question, req *D.Msg, runtime *runtimeSnapshot) *D.Msg {
	var capture *Capture
	if runtime != nil && runtime.capture != nil {
		if current, ok := runtime.capture(normalizeDomain(q.Name)); ok {
			capture = &current
		}
	}
	return r.resolveOriginRuntimeCapture(ctx, q, req, runtime, capture)
}

func (r *Resolver) resolveOriginRuntimeCapture(ctx context.Context, q D.Question, req *D.Msg, runtime *runtimeSnapshot, capture *Capture) *D.Msg {
	if WithholdsType(q.Qtype) {
		if runtime != nil {
			return tunedSyntheticNODATA(req, runtime.tuning)
		}
		return SyntheticNODATA(req)
	}

	if runtime == nil || runtime.ups == nil {
		return rcode(req, D.RcodeServerFailure)
	}
	up := runtime.ups

	// The binding is per capture host and defaults to trust, for every name and
	// for every extension that did not choose otherwise.
	upstream := up.trust
	label := "trust"
	if capture != nil && capture.Resolver == "china" {
		upstream, label = up.china, "china"
	}

	key := cacheKeyOf(q.Name, q.Qtype, req)
	key.origin = true
	key.action = actionOrigin
	key.originResolver = label
	if cached, _, ok := r.cache.getGeneration(key, runtime.generation); ok {
		adoptRequest(cached, req)
		return cached
	}

	scope := flightScope{runtime: runtime, action: actionOrigin, originResolver: label}
	resp, _, ok := r.coalesce(ctx, q, req, scope, trace{}, func(runCtx context.Context, flightReq *D.Msg, ft *trace) *D.Msg {
		start := time.Now()
		resolved, err := upstream.Exchange(runCtx, flightReq)
		if err == nil {
			if label == "china" {
				r.stats.recordChinaLatency(time.Since(start))
			} else {
				r.stats.recordTrustLatency(time.Since(start))
			}
		}
		if label == "china" {
			r.stats.bumpChina(err == nil)
		} else {
			r.stats.bumpTrust(err == nil)
		}
		if err != nil || resolved == nil {
			return r.staleOrFail(flightReq, key, runtime.generation, ft)
		}
		// The same filter as the client path. mihomo consumes this answer to
		// choose a dial target, so an AAAA arriving as glue is exactly as
		// effective at putting egress on IPv6 as one in the answer section.
		resolved = filterSteeringBypass(resolved)
		r.cachePut(key, resolved, runtime, cacheMeta{Upstream: label})
		return resolved
	})
	if !ok || resp == nil {
		return rcode(req, D.RcodeServerFailure)
	}
	return resp
}

// OriginResolve is the in-process form of the same lookup, for callers inside
// this program that hold a hostname and need its addresses.
func (r *Resolver) OriginResolve(ctx context.Context, host string) ([]string, error) {
	if !tryAcquire(r.originSem) {
		r.stats.bump(&r.stats.refused)
		return nil, errOriginAdmission
	}
	defer releaseAdmission(r.originSem)
	runtime := r.snapshot()
	if runtime == nil {
		return nil, errOriginLookup
	}

	req := new(D.Msg)
	req.SetQuestion(D.Fqdn(strings.TrimSpace(host)), D.TypeA)
	resp := r.resolveOriginRuntime(ctx, req.Question[0], req, runtime)
	if resp == nil || resp.Rcode != D.RcodeSuccess {
		return nil, errOriginLookup
	}
	return answerIPs(resp, 16), nil
}
