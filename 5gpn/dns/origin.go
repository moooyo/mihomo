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

	ctx, cancel := context.WithTimeout(context.Background(), r.timeout)
	defer cancel()

	q := req.Question[0]
	resp := r.resolveOrigin(ctx, q, req)
	if isUDP(w) {
		resp.Truncate(udpBudget(req))
	}
	_ = w.WriteMsg(resp)
}

// resolveOrigin answers one origin lookup.
func (r *Resolver) resolveOrigin(ctx context.Context, q D.Question, req *D.Msg) *D.Msg {
	if WithholdsType(q.Qtype) {
		return SyntheticNODATA(req)
	}

	epoch := r.cache.Epoch()
	up := r.ups.Load()
	if up == nil {
		return rcode(req, D.RcodeServerFailure)
	}

	name := normalizeDomain(q.Name)
	// The binding is per capture host and defaults to trust, for every name and
	// for every extension that did not choose otherwise.
	upstream := up.trust
	label := "trust"
	if lookup := r.capture.Load(); lookup != nil {
		if c, ok := (*lookup)(name); ok && c.Resolver == "china" {
			upstream, label = up.china, "china"
		}
	}

	key := cacheKeyOf(q.Name, q.Qtype, req)
	key.origin = true
	if cached, _, ok := r.cache.get(key); ok {
		adoptRequest(cached, req)
		return cached
	}

	scope := flightScope{epoch: epoch, policy: r.policy.Load(), ups: up, action: actionOrigin}
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
			return r.staleOrFail(flightReq, key, ft)
		}
		// The same filter as the client path. mihomo consumes this answer to
		// choose a dial target, so an AAAA arriving as glue is exactly as
		// effective at putting egress on IPv6 as one in the answer section.
		resolved = filterSteeringBypass(resolved)
		r.cachePut(key, resolved, scope.epoch, cacheMeta{Upstream: label})
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
	req := new(D.Msg)
	req.SetQuestion(D.Fqdn(strings.TrimSpace(host)), D.TypeA)
	resp := r.resolveOrigin(ctx, req.Question[0], req)
	if resp == nil || resp.Rcode != D.RcodeSuccess {
		return nil, errOriginLookup
	}
	return answerIPs(resp, 16), nil
}
