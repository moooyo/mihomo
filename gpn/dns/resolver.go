package dns

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	D "github.com/miekg/dns"
)

// Verdict is what a name resolved to and why.
//
// Verdict is "direct", "proxy", "block", or empty when no name-only rule was
// terminal and the address arbitration still has to decide. Reason names the
// step that produced it, and is what every counter, the query log, and the
// resolve diagnostic report.
type Verdict struct {
	Verdict string `json:"verdict,omitempty"`
	Reason  string `json:"reason,omitempty"`
}

// Capture is what the interception engine says about a name.
type Capture struct {
	ExtensionID   string `json:"extensionId"`
	ExtensionName string `json:"extensionName,omitempty"`
	Pattern       string `json:"pattern,omitempty"`
	// Resolver is the operator's china/trust binding for this extension, used
	// when mihomo re-resolves the origin after the sniffer.
	Resolver string `json:"resolver,omitempty"`
	// Ready is false when an extension declared the name but the interception
	// master is off. The declaration is still reported, because the extensions
	// page shows the extension as enabled and an operator asking "why is this
	// name not captured" needs the answer to be the master switch rather than
	// silence.
	Ready bool `json:"ready"`
}

// CaptureLookup resolves a name against the interception engine's capture
// hosts. gpn wires the engine in; nothing here imports it, so the resolver runs
// unchanged on a gateway with interception absent or failed.
type CaptureLookup func(name string) (Capture, bool)

// pool is one upstream group as the resolver uses it. An interface rather than
// the concrete group so a test can drive the decision path with a scripted
// exchanger instead of a socket -- the arbitration rules are the part worth
// testing, and they are indifferent to what answered.
type pool interface {
	Exchanger
	Specs() []string
	SetECS(netip.Prefix)
	ECS() netip.Prefix
	Close()
}

// upstreams is the hot-swappable pair. Both are replaced together so one query
// can never mix a group from two generations.
type upstreams struct {
	china pool
	trust pool
}

// Resolver is the 5gpn DNS decision engine.
//
// It owns its upstreams and never touches mihomo's resolver globals. That is
// not fastidiousness: hub/executor.updateDNS reassigns all six of them and
// recreates the DNS server on every ApplyConfig, so a resolver that shared them
// would be rebuilt whenever an operator edited an unrelated proxy -- and the
// port every phone on the network is pointed at would be rebound underneath
// them.
type Resolver struct {
	cn    *CNSet
	cache *cache
	qlog  *queryLog
	stats *counters

	policy     atomic.Pointer[compiledPolicy]
	ups        atomic.Pointer[upstreams]
	gateway    atomic.Pointer[netip.Addr]
	localNames atomic.Pointer[map[string]struct{}]
	capture    atomic.Pointer[CaptureLookup]

	timeout time.Duration
	ttlMin  time.Duration
	ttlMax  time.Duration

	// sem bounds concurrent resolutions. A random-subdomain flood pins every
	// query at the timeout, and without a ceiling the process accretes
	// goroutines and sockets until it hits the descriptor limit or the OOM
	// killer. Shedding with REFUSED is cheap and recoverable; neither of those
	// is. nil disables shedding.
	sem chan struct{}

	flightMu    sync.Mutex
	flights     map[flightKey]*flight
	flightLimit int
}

// Options configures a Resolver. Zero values take documented defaults.
type Options struct {
	Timeout     time.Duration
	TTLMin      time.Duration
	TTLMax      time.Duration
	CacheSize   int
	MaxInflight int
	FlightLimit int
	QueryLog    int
}

const (
	defaultTimeout     = 5 * time.Second
	defaultTTLMin      = 60 * time.Second
	defaultTTLMax      = 6 * time.Hour
	defaultCacheSize   = 8192
	defaultFlightLimit = 1024
)

// NewResolver builds a resolver with an empty policy and no upstreams. Callers
// publish those with Apply before serving.
func NewResolver(opt Options) *Resolver {
	if opt.Timeout <= 0 {
		opt.Timeout = defaultTimeout
	}
	if opt.TTLMin <= 0 {
		opt.TTLMin = defaultTTLMin
	}
	if opt.TTLMax <= 0 {
		opt.TTLMax = defaultTTLMax
	}
	if opt.TTLMax < opt.TTLMin {
		opt.TTLMax = opt.TTLMin
	}
	if opt.CacheSize <= 0 {
		opt.CacheSize = defaultCacheSize
	}
	if opt.FlightLimit <= 0 {
		opt.FlightLimit = defaultFlightLimit
	}
	r := &Resolver{
		cn:          NewCNSet(),
		cache:       newCache(opt.CacheSize),
		qlog:        newQueryLog(opt.QueryLog, 0),
		stats:       newCounters(),
		timeout:     opt.Timeout,
		ttlMin:      opt.TTLMin,
		ttlMax:      opt.TTLMax,
		flights:     make(map[flightKey]*flight),
		flightLimit: opt.FlightLimit,
	}
	if opt.MaxInflight > 0 {
		r.sem = make(chan struct{}, opt.MaxInflight)
	}
	return r
}

// SetCaptureLookup installs the interception engine's capture table, or removes
// it with nil.
func (r *Resolver) SetCaptureLookup(fn CaptureLookup) {
	if fn == nil {
		r.capture.Store(nil)
		return
	}
	r.capture.Store(&fn)
}

// SetGateway publishes the address proxied names resolve to. An invalid address
// means none is configured.
func (r *Resolver) SetGateway(addr netip.Addr) {
	addr = addr.Unmap()
	r.gateway.Store(&addr)
	r.cache.Flush()
}

// Gateway reports the configured gateway address.
func (r *Resolver) Gateway() netip.Addr {
	if a := r.gateway.Load(); a != nil {
		return *a
	}
	return netip.Addr{}
}

// SetLocalNames publishes names answered with the gateway address without
// consulting an upstream.
//
// These are the gateway's own service names. They have no public A record --
// the box they name is the box being asked -- so forwarding them would return
// NXDOMAIN and make the surface they front unreachable from a client that has
// already switched to this resolver.
func (r *Resolver) SetLocalNames(names []string) {
	set := make(map[string]struct{}, len(names))
	for _, n := range names {
		if n = normalizeDomain(n); n != "" {
			set[n] = struct{}{}
		}
	}
	r.localNames.Store(&set)
	r.cache.Flush()
}

// SetPolicy publishes a compiled policy snapshot and flushes the cache.
//
// The flush is not optional. Cached values are final, already-steered answers,
// so a policy change without one keeps serving the previous decision until each
// entry's TTL expires -- which turns an apply into a silent no-op for exactly
// the names the operator was most likely editing.
func (r *Resolver) SetPolicy(p Policy, cacheDir string) error {
	compiled, err := compile(p, cacheDir)
	if err != nil {
		return err
	}
	r.setCompiledPolicy(compiled)
	return nil
}

func (r *Resolver) setCompiledPolicy(compiled *compiledPolicy) {
	r.policy.Store(compiled)
	r.cache.Flush()
}

// SetUpstreams rebuilds both groups and retires the previous pair.
func (r *Resolver) SetUpstreams(china, trust []MemberSpec, ecs netip.Prefix) {
	next := &upstreams{china: newGroup("china", china), trust: newGroup("trust", trust)}
	// Only china carries a client subnet -- see the note in ecs.go.
	next.china.SetECS(ecs)
	r.swapUpstreams(next)
}

func (r *Resolver) swapUpstreams(next *upstreams) {
	previous := r.ups.Swap(next)
	r.cache.Flush()
	if previous != nil {
		retire(previous.china, 2*r.timeout)
		retire(previous.trust, 2*r.timeout)
	}
}

// SetECS updates the china group's client subnet in place.
func (r *Resolver) SetECS(p netip.Prefix) {
	if u := r.ups.Load(); u != nil {
		u.china.SetECS(p)
	}
	r.cache.Flush()
}

// Stats reports counters, cache size, and the CN set's range count -- a set
// that parsed to nothing calls the whole internet foreign, and nothing outside
// this process can observe that except a bandwidth bill.
func (r *Resolver) Stats() Stats {
	s := r.stats.snapshot()
	s.CacheEntries = r.cache.Len()
	s.CNRanges = r.cn.Len()
	return s
}

// QueryLog returns recent queries, newest first.
func (r *Resolver) QueryLog(q string, limit int) []QueryLogEntry {
	return r.qlog.search(q, limit, time.Now())
}

// Upstreams reports the configured member specs of both groups.
func (r *Resolver) Upstreams() (china, trust []string) {
	if u := r.ups.Load(); u != nil {
		return u.china.Specs(), u.trust.Specs()
	}
	return nil, nil
}

// FlushCache drops every cached answer.
func (r *Resolver) FlushCache() { r.cache.Flush() }

// ServeDNS implements D.Handler for the client-facing listeners.
//
// The miekg UDP/TCP/DoT path carries no client cancellation, so the query is
// dispatched on a background context and bounded by the resolver's own
// deadline.
func (r *Resolver) ServeDNS(w D.ResponseWriter, req *D.Msg) {
	r.serve(context.Background(), w, req)
}

func (r *Resolver) serve(parent context.Context, w D.ResponseWriter, req *D.Msg) {
	if len(req.Question) != 1 {
		_ = w.WriteMsg(rcode(req, D.RcodeFormatError))
		return
	}
	if req.Question[0].Qclass != D.ClassINET {
		_ = w.WriteMsg(rcode(req, D.RcodeNotImplemented))
		return
	}

	if r.sem != nil {
		select {
		case r.sem <- struct{}{}:
			defer func() { <-r.sem }()
		default:
			r.stats.bump(&r.stats.refused)
			_ = w.WriteMsg(rcode(req, D.RcodeRefused))
			return
		}
	}

	ctx, cancel := context.WithTimeout(parent, r.timeout)
	defer cancel()

	q := req.Question[0]
	start := time.Now()
	var trace trace
	resp := r.resolve(ctx, q, req, &trace)

	r.qlog.add(QueryLogEntry{
		Time:       start,
		Client:     clientHost(w),
		Name:       strings.TrimSuffix(q.Name, "."),
		Qtype:      D.TypeToString[q.Qtype],
		Verdict:    trace.verdict,
		Reason:     trace.reason,
		Upstream:   trace.upstream,
		CacheHit:   trace.cacheHit,
		Rcode:      D.RcodeToString[resp.Rcode],
		IPs:        answerIPs(resp, queryLogMaxIPs),
		DurationMs: float64(time.Since(start).Microseconds()) / 1000.0,
	})

	// A UDP reply must fit the client's advertised budget. Truncate sets TC so
	// the client retries over TCP rather than receiving an oversized datagram.
	// Stream transports report a non-UDP network and are left intact.
	if isUDP(w) {
		resp.Truncate(udpBudget(req))
	}
	_ = w.WriteMsg(resp)
}

// trace collects what the query log records.
type trace struct {
	verdict  string
	reason   string
	upstream string
	cacheHit bool
}

func (t *trace) note(v Verdict) {
	if t != nil {
		t.verdict, t.reason = v.Verdict, v.Reason
	}
}

func (t *trace) noteUpstream(src string) {
	if t != nil {
		t.upstream = src
	}
}

func (t *trace) noteCacheHit() {
	if t != nil {
		t.cacheHit = true
	}
}

// action is the executable form of a name decision, after the ordered rules and
// the fallback have been folded together.
type action uint8

const (
	actionArbitrate action = iota // resolve and rewrite foreign addresses
	actionBlock
	actionDirect  // resolve and keep the real addresses
	actionGateway // answer with the gateway address, ask nobody
	actionOrigin  // mihomo's post-sniff lookup; see origin.go
)

// errOriginLookup is what an in-process origin lookup returns when the name did
// not resolve. Deliberately opaque: the caller is inside this program and has
// no remediation the upstream's rcode would inform.
var errOriginLookup = errors.New("gpn/dns: origin lookup failed")

// Decision is what the name-only stage concluded, with the attribution a
// diagnostic needs.
type Decision struct {
	Verdict Verdict
	action  action
	policy  *compiledPolicy

	// Capture and Rule are the only way to tell two identical verdicts apart:
	// an extension capture host and an operator proxy rule both produce
	// {proxy, force-proxy}, deliberately, because every counter downstream
	// treats them as one thing.
	Capture *Capture
	Rule    *compiledRule
	// Extensions is how many extensions are enabled, so a diagnostic can say
	// "three enabled, none declared this name" rather than only "no match".
	Extensions int
}

// Decide runs the name-only stage: capture table, then ordered rules, then the
// fallback. Exported because the resolve diagnostic must reach the same
// conclusion as live resolution by running the same code, not by reimplementing
// the precedence and drifting from it.
func (r *Resolver) Decide(name string) Decision {
	name = normalizeDomain(name)

	var capture *Capture
	if lookup := r.capture.Load(); lookup != nil {
		if c, ok := (*lookup)(name); ok {
			capture = &c
		}
	}

	// Only a READY capture steers. A declaration with the master off falls
	// through to policy instead: steering it would send the client to a gateway
	// with nothing able to terminate the connection, which black-holes the name
	// rather than leaving it merely uncaptured.
	if capture != nil && capture.Ready {
		return Decision{
			Verdict: Verdict{Verdict: "proxy", Reason: "force-proxy"},
			action:  actionGateway,
			policy:  r.policy.Load(),
			Capture: capture,
		}
	}

	policy := r.policy.Load()
	verdict, rule := policy.classify(name)
	decision := Decision{Verdict: verdict, policy: policy, Capture: capture, Rule: rule}

	switch verdict.Reason {
	case "block":
		decision.action = actionBlock
		return decision
	case "force-direct":
		decision.action = actionDirect
		return decision
	case "force-proxy":
		decision.action = actionGateway
		return decision
	}

	// Nothing matched: the fallback decides, and it is part of the verdict
	// rather than a separate stage, so a diagnostic cannot report "no match"
	// and quietly omit what actually happens next.
	decision.Rule = nil
	switch policy.fallback() {
	case FallbackDirect:
		decision.Verdict = Verdict{Verdict: "direct", Reason: "fallback-direct"}
		decision.action = actionDirect
	case FallbackGateway:
		decision.Verdict = Verdict{Verdict: "proxy", Reason: "fallback-gateway"}
		decision.action = actionGateway
	default:
		decision.Verdict = Verdict{}
		decision.action = actionArbitrate
	}
	return decision
}

// resolve applies the ordered precedence:
//
//	local name        -> the gateway address, or synthetic NODATA for non-A
//	AAAA/HTTPS/SVCB   -> synthetic NODATA
//	block             -> NXDOMAIN
//	direct            -> arbitrate, keep the real addresses
//	gateway           -> the gateway address, no upstream consulted
//	otherwise         -> arbitrate, rewrite foreign addresses to the gateway
//
// Every other query type is forwarded to trust with the steering-bypass records
// stripped from all three sections.
func (r *Resolver) resolve(ctx context.Context, q D.Question, req *D.Msg, t *trace) *D.Msg {
	name := q.Name
	r.stats.bump(&r.stats.total)

	// Before any upstream: these names do not exist in public DNS.
	if r.isLocalName(name) {
		if q.Qtype == D.TypeA {
			t.note(Verdict{Verdict: "direct", Reason: "local-name"})
			return GatewayReply(req, r.Gateway())
		}
		t.note(Verdict{Reason: "local-name"})
		return SyntheticNODATA(req)
	}

	// Capture the cache epoch BEFORE any runtime snapshot. If a swap lands
	// anywhere between here and the write, the epoch mismatch discards it.
	// Loading a snapshot first would let one query combine pre-swap state with
	// a post-flush epoch and repopulate the new generation with a stale answer.
	epoch := r.cache.Epoch()

	up := r.ups.Load()
	if up == nil {
		// No upstreams published yet. Fail rather than answer from nothing.
		return rcode(req, D.RcodeServerFailure)
	}

	if WithholdsType(q.Qtype) {
		t.note(Verdict{Reason: withheldReason(q.Qtype)})
		return SyntheticNODATA(req)
	}

	decision := r.Decide(name)
	scope := flightScope{epoch: epoch, policy: decision.policy, ups: up, action: decision.action}

	if decision.action == actionBlock {
		r.stats.bumpReason(decision.Verdict.Reason)
		t.note(decision.Verdict)
		return rcode(req, D.RcodeNameError)
	}

	isA := q.Qtype == D.TypeA

	if decision.action == actionGateway {
		t.note(decision.Verdict)
		if isA {
			r.stats.bumpReason(decision.Verdict.Reason)
			return GatewayReply(req, r.Gateway())
		}
		// Steering is an A-record mechanism; every other type still needs a
		// real answer.
		return r.forwardTrust(ctx, up.trust, q, req, scope, t)
	}

	if !isA {
		t.note(decision.Verdict)
		return r.forwardTrust(ctx, up.trust, q, req, scope, t)
	}

	if decision.action == actionDirect {
		t.note(decision.Verdict)
		r.stats.bumpReason(decision.Verdict.Reason)
	}

	key := cacheKeyOf(name, q.Qtype, req)
	if cached, meta, ok := r.cacheGet(key, req); ok {
		if meta.Reason != "" {
			t.note(Verdict{Verdict: meta.Verdict, Reason: meta.Reason})
			t.noteUpstream(meta.Upstream)
			if decision.action != actionDirect {
				r.stats.bumpReason(meta.Reason)
			}
		}
		t.noteCacheHit()
		return cached
	}

	rewrite := decision.action == actionArbitrate
	declared := decision.Verdict

	resp, info, ok := r.coalesce(ctx, q, req, scope, *t, func(runCtx context.Context, flightReq *D.Msg, ft *trace) *D.Msg {
		resolved, src, err := arbitrate(runCtx, flightReq, up.china, up.trust, r.cn, r.stats)
		if err != nil || resolved == nil {
			return r.staleOrFail(flightReq, key, ft)
		}
		ft.noteUpstream(src)
		resolved = filterSteeringBypass(resolved)

		verdict := declared
		if rewrite {
			resolved = r.rewriteA(resolved, flightReq)
			verdict = r.arbitratedVerdict(resolved)
			ft.note(verdict)
			r.stats.bumpReason(verdict.Reason)
		}
		r.cachePut(key, resolved, scope.epoch, cacheMeta{
			Verdict: verdict.Verdict, Reason: verdict.Reason, Upstream: src,
		})
		return resolved
	})
	if !ok || resp == nil {
		return rcode(req, D.RcodeServerFailure)
	}
	*t = info
	return resp
}

func withheldReason(qtype uint16) string {
	if qtype == D.TypeAAAA {
		return "aaaa-synthetic"
	}
	return "https-synthetic"
}

// forwardTrust sends a non-steering query type to trust and returns the reply
// with the bypass records stripped.
func (r *Resolver) forwardTrust(ctx context.Context, trust Exchanger, q D.Question, req *D.Msg, scope flightScope, t *trace) *D.Msg {
	if t != nil && t.reason == "" {
		t.reason = "forward-trust"
	}
	key := cacheKeyOf(q.Name, q.Qtype, req)
	if cached, meta, ok := r.cacheGet(key, req); ok {
		if meta.Reason != "" {
			t.note(Verdict{Verdict: meta.Verdict, Reason: meta.Reason})
			t.noteUpstream(meta.Upstream)
		}
		t.noteCacheHit()
		return cached
	}

	resp, info, ok := r.coalesce(ctx, q, req, scope, *t, func(runCtx context.Context, flightReq *D.Msg, ft *trace) *D.Msg {
		// This is the second trust exchange site; arbitrate is the other. Count
		// it the same way: latency only for a completed exchange, health either
		// way. Leaving it uncounted made every query type that lands here --
		// which is everything the steps above do not special-case -- invisible
		// to the trust health numbers, so the reported sample set matched
		// neither the query total nor ok+err.
		start := time.Now()
		resolved, err := trust.Exchange(runCtx, flightReq)
		if err == nil {
			r.stats.recordTrustLatency(time.Since(start))
		}
		r.stats.bumpTrust(err == nil)
		if err != nil || resolved == nil {
			return r.staleOrFail(flightReq, key, ft)
		}
		ft.noteUpstream("trust")
		resolved = filterSteeringBypass(resolved)
		r.cachePut(key, resolved, scope.epoch, cacheMeta{
			Upstream: "trust", Verdict: ft.verdict, Reason: ft.reason,
		})
		return resolved
	})
	if !ok || resp == nil {
		return rcode(req, D.RcodeServerFailure)
	}
	*t = info
	return resp
}

// arbitratedVerdict classifies a rewritten answer the way the counters and the
// query log report it.
func (r *Resolver) arbitratedVerdict(resp *D.Msg) Verdict {
	if resp == nil {
		return Verdict{}
	}
	gateway := r.Gateway()
	seenA := false
	for _, rr := range resp.Answer {
		a, ok := rr.(*D.A)
		if !ok {
			continue
		}
		seenA = true
		if addr, ok := netipFromIP(a.A); ok && gateway.IsValid() && addr == gateway {
			return Verdict{Verdict: "proxy", Reason: "chnroute-foreign"}
		}
	}
	if seenA {
		return Verdict{Verdict: "direct", Reason: "chnroute-cn"}
	}
	return Verdict{}
}

// rewriteA keeps CN addresses and replaces foreign ones with the gateway.
//
// Several foreign addresses collapse to one gateway record: they were
// alternative routes to the same origin, and the gateway is a single
// destination, so emitting it repeatedly would only make a client retry the
// same socket.
func (r *Resolver) rewriteA(resp *D.Msg, req *D.Msg) *D.Msg {
	out := new(D.Msg)
	out.SetReply(req)
	out.RecursionAvailable = true
	// SetReply resets the code to NOERROR; carry the upstream's through.
	// Without this an NXDOMAIN becomes an uncacheable NOERROR with no SOA, and
	// an upstream SERVFAIL is laundered into a synthetic "no records" answer
	// that then slips past the don't-cache-failures guard and is stored as if
	// it were authoritative.
	out.Rcode = resp.Rcode

	gateway := r.Gateway()
	// With no gateway configured there is nowhere to steer foreign traffic, so
	// keep every address as-is and degrade to plain split resolution. The
	// alternative -- substituting an unspecified address for every foreign name
	// -- black-holes the entire foreign internet silently.
	steer := gateway.IsValid() && gateway.Is4() && !gateway.IsUnspecified()

	var rewritten []D.RR
	added := false
	for _, rr := range resp.Answer {
		a, ok := rr.(*D.A)
		if !ok {
			rewritten = append(rewritten, rr) // CNAME and friends pass through
			continue
		}
		addr, parsed := netipFromIP(a.A)
		if !steer || (parsed && r.cn.Contains(addr)) {
			rewritten = append(rewritten, a)
			continue
		}
		if !added {
			gw := &D.A{Hdr: a.Hdr, A: net.IP(gateway.AsSlice())}
			gw.Hdr.Ttl = clampTTL(a.Hdr.Ttl, r.ttlMin, r.ttlMax)
			rewritten = append(rewritten, gw)
			added = true
		}
	}
	out.Answer = rewritten
	// The authority section carries the SOA a stub needs to negative-cache
	// NXDOMAIN and NODATA, so it is passed through. OPT is not: EDNS belongs to
	// the transport.
	out.Ns = resp.Ns

	if added {
		// A rewritten address makes any signature covering that RRset provably
		// bogus. Left in place it makes validating stubs fail on exactly the
		// proxied set of names -- a very confusing signature, where domestic
		// names validate and foreign ones do not. Answers with nothing
		// rewritten keep their signatures.
		out.Answer = stripDNSSEC(out.Answer)
		out.Ns = stripDNSSEC(out.Ns)
	}
	return out
}

func (r *Resolver) isLocalName(name string) bool {
	set := r.localNames.Load()
	if set == nil || len(*set) == 0 {
		return false
	}
	_, ok := (*set)[normalizeDomain(name)]
	return ok
}

func (r *Resolver) cacheGet(k cacheKey, req *D.Msg) (*D.Msg, cacheMeta, bool) {
	msg, meta, ok := r.cache.get(k)
	if ok {
		r.stats.bump(&r.stats.cacheHits)
		adoptRequest(msg, req)
	} else {
		r.stats.bump(&r.stats.cacheMisses)
	}
	return msg, meta, ok
}

// staleOrFail serves a stale entry when every upstream failed, else SERVFAIL.
func (r *Resolver) staleOrFail(req *D.Msg, k cacheKey, t *trace) *D.Msg {
	if stale, meta, ok := r.cache.getStale(k); ok {
		adoptRequest(stale, req)
		if meta.Reason != "" {
			t.note(Verdict{Verdict: meta.Verdict, Reason: meta.Reason})
			t.noteUpstream(meta.Upstream)
		}
		t.noteCacheHit()
		return stale
	}
	return rcode(req, D.RcodeServerFailure)
}

// cachePut stores a successful answer with its TTL clamped.
func (r *Resolver) cachePut(k cacheKey, resp *D.Msg, epoch uint64, meta cacheMeta) {
	if resp == nil || resp.Rcode != D.RcodeSuccess {
		// A failure is not an answer. Caching one turns a transient upstream
		// problem into a sticky one.
		return
	}
	ttl := r.ttlMin
	if len(resp.Answer) > 0 {
		ttl = minAnswerTTL(resp, r.ttlMin, r.ttlMax)
	}
	r.cache.put(k, resp, ttl, epoch, meta)
}

// --- single flight -------------------------------------------------------

// flightKey is every request property that can vary the answer, plus the exact
// snapshots the leader used. Snapshot identity is what keeps a reload boundary
// from serving a new-policy caller the old-policy result.
type flightKey struct {
	name             string
	qtype            uint16
	qclass           uint16
	dnssecOK         bool
	checkingDisabled bool
	epoch            uint64
	policy           *compiledPolicy
	ups              *upstreams
	action           action
}

type flightScope struct {
	epoch  uint64
	policy *compiledPolicy
	ups    *upstreams
	action action
}

type flight struct {
	done   chan struct{}
	msg    *D.Msg
	result trace
}

// coalesce runs one resolution for every concurrent caller with the same key.
//
// The shared resolution is detached and carries its own deadline, so a caller
// that gives up stops waiting without cancelling the work the others are still
// waiting on. When the map is at capacity the caller resolves independently:
// capacity pressure must not block unrelated names, and a random-subdomain
// flood must not turn coalescing into an unbounded map.
func (r *Resolver) coalesce(
	ctx context.Context,
	q D.Question,
	req *D.Msg,
	scope flightScope,
	initial trace,
	run func(context.Context, *D.Msg, *trace) *D.Msg,
) (*D.Msg, trace, bool) {
	if err := ctx.Err(); err != nil {
		return nil, initial, false
	}

	template := new(D.Msg)
	if req != nil {
		template = req.Copy()
	} else {
		template.Question = []D.Question{q}
	}

	key := flightKey{
		name:     strings.ToLower(D.Fqdn(q.Name)),
		qtype:    q.Qtype,
		qclass:   q.Qclass,
		epoch:    scope.epoch,
		policy:   scope.policy,
		ups:      scope.ups,
		action:   scope.action,
		dnssecOK: cacheKeyOf(q.Name, q.Qtype, template).dnssecOK,
	}
	key.checkingDisabled = template.CheckingDisabled

	r.flightMu.Lock()
	f := r.flights[key]
	leader := false
	if f == nil && len(r.flights) < r.flightLimit {
		f = &flight{done: make(chan struct{})}
		r.flights[key] = f
		leader = true
	}
	r.flightMu.Unlock()

	if f == nil {
		info := initial
		msg := run(ctx, template, &info)
		return replyFor(msg, req), info, true
	}

	if leader {
		go func() {
			runCtx, cancel := context.WithTimeout(context.Background(), r.timeout)
			defer cancel()

			info := initial
			f.msg = run(runCtx, template, &info)
			f.result = info
			close(f.done)

			r.flightMu.Lock()
			if r.flights[key] == f {
				delete(r.flights, key)
			}
			r.flightMu.Unlock()
		}()
	}

	select {
	case <-f.done:
		return replyFor(f.msg, req), f.result, true
	case <-ctx.Done():
		return nil, initial, false
	}
}

func replyFor(msg, req *D.Msg) *D.Msg {
	if msg == nil {
		return nil
	}
	reply := msg.Copy()
	adoptRequest(reply, req)
	return reply
}

// adoptRequest re-stamps a shared or cached message with this caller's ID and
// question, which is the difference between an answer and one the client
// discards as unsolicited.
func adoptRequest(msg, req *D.Msg) {
	if msg == nil || req == nil {
		return
	}
	msg.Id = req.Id
	msg.Question = append(msg.Question[:0], req.Question...)
}

// --- small helpers -------------------------------------------------------

func rcode(req *D.Msg, code int) *D.Msg {
	m := new(D.Msg)
	m.SetRcode(req, code)
	return m
}

func netipFromIP(ip net.IP) (netip.Addr, bool) {
	addr, ok := netip.AddrFromSlice(ip)
	if !ok {
		return netip.Addr{}, false
	}
	return addr.Unmap(), true
}

func isUDP(w D.ResponseWriter) bool {
	if w == nil {
		return false
	}
	ra := w.RemoteAddr()
	return ra != nil && ra.Network() == "udp"
}

// udpBudget is the client's advertised EDNS size, floored at the non-EDNS
// limit.
func udpBudget(req *D.Msg) int {
	if opt := req.IsEdns0(); opt != nil {
		if sz := int(opt.UDPSize()); sz >= D.MinMsgSize {
			return sz
		}
	}
	return D.MinMsgSize
}

func minAnswerTTL(m *D.Msg, lo, hi time.Duration) time.Duration {
	smallest := hi
	for _, rr := range m.Answer {
		if t := time.Duration(rr.Header().Ttl) * time.Second; t < smallest {
			smallest = t
		}
	}
	if smallest < lo {
		return lo
	}
	if smallest > hi {
		return hi
	}
	return smallest
}

func clampTTL(v uint32, lo, hi time.Duration) uint32 {
	t := time.Duration(v) * time.Second
	if t < lo {
		return uint32(lo.Seconds())
	}
	if t > hi {
		return uint32(hi.Seconds())
	}
	return v
}
