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
	// runtime cannot currently accept new traffic.
	Ready bool `json:"ready"`
	// Claimed keeps an enabled host on the gateway while the master is on but a
	// certificate, boundary, or egress dependency is pending. The tunnel then
	// rejects it at the reviewed client boundary instead of letting DNS leak it
	// to an origin. With the master off, Claimed is false and policy applies.
	Claimed bool `json:"claimed"`
}

// CaptureLookup resolves a name against the interception engine's capture
// hosts. 5gpn wires the engine in; nothing here imports it, so the resolver runs
// unchanged on a gateway with interception absent or failed.
type CaptureLookup func(name string) (Capture, bool)

// pool is one upstream group as the resolver uses it. An interface rather than
// the concrete group so a test can drive the decision path with a scripted
// exchanger instead of a socket -- the arbitration rules are the part worth
// testing, and they are indifferent to what answered.
type pool interface {
	Exchanger
	Specs() []string
	Close()
}

// upstreams is the hot-swappable pair. Both are replaced together so one query
// can never mix a group from two generations.
type upstreams struct {
	china pool
	trust pool
}

// runtimeTuning is the validated executable form of the document's tuning
// section. It lives in the same immutable snapshot as policy and upstreams so
// one query cannot use a new timeout with an old admission limit or TTL policy.
type runtimeTuning struct {
	timeout     time.Duration
	ttlMin      time.Duration
	ttlMax      time.Duration
	cacheSize   int
	maxInflight int
}

// runtimeSnapshot is every DNS-document input that can change the answer or
// the work a query is allowed to consume. A query loads this pointer exactly
// once and carries it through decision, upstream exchange, cache, and
// rewriting. Capture is an engine-owned projection accessor; each query calls
// it once, and the resulting action/resolver discriminator is carried in its
// cache and flight keys across the engine's publish-then-notify handoff.
type runtimeSnapshot struct {
	generation uint64
	policy     *compiledPolicy
	ups        *upstreams
	gateway    netip.Addr
	localNames map[string]struct{}
	capture    CaptureLookup
	tuning     runtimeTuning
	clientSem  chan struct{}
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

	runtime   atomic.Pointer[runtimeSnapshot]
	runtimeMu sync.Mutex
	closed    atomic.Bool
	// originSem is deliberately separate from the client budget. Origin
	// lookups are made by the tunnel and by guarded subscription fetches; if
	// they shared a saturated client budget, work already admitted on the
	// client path could deadlock waiting for a slot held by itself.
	originSem chan struct{}

	flightMu    sync.Mutex
	flights     map[flightKey]*flight
	flightLimit int
}

// Close releases the currently published upstream connection pools after the
// service has stopped accepting DNS requests. Replaced generations already
// retire themselves; this handles the final live generation at process exit.
func (r *Resolver) Close() {
	if r == nil || r.closed.Swap(true) {
		return
	}
	current := r.snapshot()
	if current == nil || current.ups == nil {
		return
	}
	if current.ups.china != nil {
		current.ups.china.Close()
	}
	if current.ups.trust != nil {
		current.ups.trust.Close()
	}
}

// Options configures a Resolver. Zero values take documented defaults.
type Options struct {
	Timeout     time.Duration
	TTLMin      time.Duration
	TTLMax      time.Duration
	CacheSize   int
	MaxInflight int
	// OriginMaxInflight bounds both the loopback origin listener and the
	// in-process OriginResolve API. It is process integration rather than an
	// operator tuning knob, so the service uses the safe default.
	OriginMaxInflight int
	FlightLimit       int
	QueryLog          int
}

const (
	defaultTimeout     = 5 * time.Second
	defaultTTLMin      = 60 * time.Second
	defaultTTLMax      = 6 * time.Hour
	defaultCacheSize   = 8192
	defaultMaxInflight = 256
	// Origin resolution is internal and normally much narrower than public
	// DoT ingress. A separate smaller budget prevents tunnel/subscription work
	// from exhausting the client budget while still allowing ordinary bursts.
	defaultOriginMaxInflight = 64
	defaultFlightLimit       = 1024
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
	if opt.MaxInflight <= 0 {
		opt.MaxInflight = defaultMaxInflight
	}
	if opt.OriginMaxInflight <= 0 {
		opt.OriginMaxInflight = defaultOriginMaxInflight
	}
	if opt.FlightLimit <= 0 {
		opt.FlightLimit = defaultFlightLimit
	}
	tuning := runtimeTuning{
		timeout: opt.Timeout, ttlMin: opt.TTLMin, ttlMax: opt.TTLMax,
		cacheSize: opt.CacheSize, maxInflight: opt.MaxInflight,
	}
	r := &Resolver{
		cn:          NewCNSet(),
		cache:       newCache(opt.CacheSize),
		qlog:        newQueryLog(opt.QueryLog, 0),
		stats:       newCounters(),
		originSem:   make(chan struct{}, opt.OriginMaxInflight),
		flights:     make(map[flightKey]*flight),
		flightLimit: opt.FlightLimit,
	}
	r.runtime.Store(&runtimeSnapshot{
		generation: 1,
		localNames: make(map[string]struct{}),
		tuning:     tuning,
		clientSem:  make(chan struct{}, tuning.maxInflight),
	})
	return r
}

func (r *Resolver) snapshot() *runtimeSnapshot {
	if r == nil {
		return nil
	}
	return r.runtime.Load()
}

// updateRuntime serializes all writers and makes the cache ready for the next
// generation before publishing its single pointer. Readers can briefly finish
// on the previous snapshot, but no reader can assemble fields from both.
func (r *Resolver) updateRuntime(change func(*runtimeSnapshot) *runtimeSnapshot) {
	r.runtimeMu.Lock()
	current := r.runtime.Load()
	next := change(current)
	if next == nil {
		r.runtimeMu.Unlock()
		return
	}
	next.generation = current.generation + 1
	if next.clientSem == nil || cap(next.clientSem) != next.tuning.maxInflight {
		next.clientSem = make(chan struct{}, next.tuning.maxInflight)
	}
	// A new configuration is a hard boundary. Prepare its empty cache before
	// making the runtime visible; old in-flight writes carry the old generation
	// and are rejected.
	r.cache.hardInvalidate(next.generation, next.tuning.cacheSize)
	r.runtime.Store(next)
	r.runtimeMu.Unlock()

	if current.ups != nil && current.ups != next.ups {
		retire(current.ups.china, 2*current.tuning.timeout)
		retire(current.ups.trust, 2*current.tuning.timeout)
	}
}

func cloneRuntime(current *runtimeSnapshot) *runtimeSnapshot {
	if current == nil {
		return &runtimeSnapshot{}
	}
	next := *current
	return &next
}

// applyDocumentRuntime publishes one fully prepared DNS document projection.
// Capture is owned by the interception transaction and is retained, while all
// document-owned fields move together in this one generation.
func (r *Resolver) applyDocumentRuntime(policy *compiledPolicy, ups *upstreams, localNames map[string]struct{}, gateway netip.Addr, tuning runtimeTuning) {
	gateway = gateway.Unmap()
	if !usableGateway(gateway) {
		gateway = netip.Addr{}
	}
	r.updateRuntime(func(current *runtimeSnapshot) *runtimeSnapshot {
		clientSem := current.clientSem
		if current.tuning.maxInflight != tuning.maxInflight {
			clientSem = nil
		}
		return &runtimeSnapshot{
			policy: policy, ups: ups, gateway: gateway, localNames: localNames,
			capture: current.capture, tuning: tuning, clientSem: clientSem,
		}
	})
}

// SetCaptureLookup installs the interception engine's capture table, or removes
// it with nil.
func (r *Resolver) SetCaptureLookup(fn CaptureLookup) {
	r.updateRuntime(func(current *runtimeSnapshot) *runtimeSnapshot {
		next := cloneRuntime(current)
		next.capture = fn
		return next
	})
}

// SetGateway publishes the address proxied names resolve to. An invalid address
// means none is configured.
func (r *Resolver) SetGateway(addr netip.Addr) {
	addr = addr.Unmap()
	if !usableGateway(addr) {
		addr = netip.Addr{}
	}
	r.updateRuntime(func(current *runtimeSnapshot) *runtimeSnapshot {
		next := cloneRuntime(current)
		next.gateway = addr
		return next
	})
}

// Gateway reports the configured gateway address.
func (r *Resolver) Gateway() netip.Addr {
	if current := r.snapshot(); current != nil {
		return current.gateway
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
	r.updateRuntime(func(current *runtimeSnapshot) *runtimeSnapshot {
		next := cloneRuntime(current)
		next.localNames = set
		return next
	})
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
	r.updateRuntime(func(current *runtimeSnapshot) *runtimeSnapshot {
		next := cloneRuntime(current)
		next.policy = compiled
		return next
	})
}

// SetUpstreams rebuilds both groups and retires the previous pair.
func (r *Resolver) SetUpstreams(china, trust []MemberSpec, ecs netip.Prefix) {
	chinaGroup := newGroup("china", china)
	// Only china carries a client subnet -- see the note in ecs.go.
	chinaGroup.SetECS(ecs)
	next := &upstreams{china: chinaGroup, trust: newGroup("trust", trust)}
	r.swapUpstreams(next)
}

func (r *Resolver) swapUpstreams(next *upstreams) {
	r.updateRuntime(func(current *runtimeSnapshot) *runtimeSnapshot {
		runtime := cloneRuntime(current)
		runtime.ups = next
		return runtime
	})
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
	if current := r.snapshot(); current != nil && current.ups != nil {
		u := current.ups
		return u.china.Specs(), u.trust.Specs()
	}
	return nil, nil
}

// FlushCache drops every cached answer.
func (r *Resolver) FlushCache() {
	r.updateRuntime(func(current *runtimeSnapshot) *runtimeSnapshot {
		return cloneRuntime(current)
	})
}

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

	runtime := r.snapshot()
	if runtime == nil || !tryAcquire(runtime.clientSem) {
		r.stats.bump(&r.stats.refused)
		_ = w.WriteMsg(rcode(req, D.RcodeRefused))
		return
	}
	defer releaseAdmission(runtime.clientSem)

	ctx, cancel := context.WithTimeout(parent, runtime.tuning.timeout)
	defer cancel()

	q := req.Question[0]
	start := time.Now()
	var trace trace
	resp := r.resolveRuntime(ctx, q, req, &trace, runtime)

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
var errOriginLookup = errors.New("5gpn/dns: origin lookup failed")

// errOriginAdmission distinguishes load shedding from an upstream lookup
// failure for in-process callers. Both are recoverable operation failures, but
// only the former tells a caller that retrying later may make progress without
// changing DNS configuration.
var errOriginAdmission = errors.New("5gpn/dns: origin lookup admission full")

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
	return r.decide(r.snapshot(), name)
}

func (r *Resolver) decide(runtime *runtimeSnapshot, name string) Decision {
	name = normalizeDomain(name)
	if runtime == nil || runtime.policy == nil {
		return Decision{}
	}

	var capture *Capture
	if runtime.capture != nil {
		if c, ok := runtime.capture(name); ok {
			capture = &c
		}
	}

	// A ready capture steers normally. A claimed-but-not-ready capture also
	// stays on the gateway, where RouteClient rejects it before ordinary mihomo
	// fallback. Letting it fall through here would expose traffic that the
	// operator authorized for interception directly to its origin during a
	// certificate or egress transition.
	if capture != nil && (capture.Ready || capture.Claimed) {
		return Decision{
			Verdict: Verdict{Verdict: "proxy", Reason: "force-proxy"},
			action:  actionGateway,
			policy:  runtime.policy,
			Capture: capture,
		}
	}

	policy := runtime.policy
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
	return r.resolveRuntime(ctx, q, req, t, r.snapshot())
}

func (r *Resolver) resolveRuntime(ctx context.Context, q D.Question, req *D.Msg, t *trace, runtime *runtimeSnapshot) *D.Msg {
	return r.resolveRuntimeDecision(ctx, q, req, t, runtime, nil)
}

func (r *Resolver) resolveRuntimeDecision(ctx context.Context, q D.Question, req *D.Msg, t *trace, runtime *runtimeSnapshot, preset *Decision) *D.Msg {
	if runtime == nil || runtime.policy == nil || runtime.ups == nil {
		return rcode(req, D.RcodeServerFailure)
	}
	name := q.Name
	r.stats.bump(&r.stats.total)

	// Before any upstream: these names do not exist in public DNS.
	if isLocalName(runtime, name) {
		if q.Qtype == D.TypeA {
			t.note(Verdict{Verdict: "direct", Reason: "local-name"})
			return tunedGatewayReply(req, runtime.gateway, runtime.tuning)
		}
		t.note(Verdict{Reason: "local-name"})
		return tunedSyntheticNODATA(req, runtime.tuning)
	}

	up := runtime.ups

	if WithholdsType(q.Qtype) {
		t.note(Verdict{Reason: withheldReason(q.Qtype)})
		return tunedSyntheticNODATA(req, runtime.tuning)
	}

	decision := Decision{}
	if preset != nil {
		decision = *preset
	} else {
		decision = r.decide(runtime, name)
	}
	scope := flightScope{runtime: runtime, action: decision.action}

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
			return tunedGatewayReply(req, runtime.gateway, runtime.tuning)
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
	key.action = decision.action
	if cached, meta, ok := r.cacheGet(key, req, runtime.generation); ok {
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
			return r.staleOrFail(flightReq, key, runtime.generation, ft)
		}
		ft.noteUpstream(src)
		resolved = filterSteeringBypass(resolved)

		verdict := declared
		if rewrite {
			resolved = r.rewriteA(resolved, flightReq, runtime)
			verdict = r.arbitratedVerdict(resolved, runtime)
			ft.note(verdict)
			r.stats.bumpReason(verdict.Reason)
		}
		r.cachePut(key, resolved, runtime, cacheMeta{
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
	key.action = scope.action
	if cached, meta, ok := r.cacheGet(key, req, scope.runtime.generation); ok {
		if scope.action == actionGateway || scope.action == actionArbitrate {
			cached = filterGatewayAddressDisclosure(cached)
		}
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
			return r.staleOrFail(flightReq, key, scope.runtime.generation, ft)
		}
		ft.noteUpstream("trust")
		if scope.action == actionGateway || scope.action == actionArbitrate {
			// A non-A question can still carry usable origin addresses in ANY
			// answers or MX/NS/SRV glue. A gateway decision must not disclose
			// them, and an auto decision must force a separate A lookup so it can
			// arbitrate the address before returning it.
			resolved = filterGatewayAddressDisclosure(resolved)
		} else {
			resolved = filterSteeringBypass(resolved)
		}
		r.cachePut(key, resolved, scope.runtime, cacheMeta{
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
func (r *Resolver) arbitratedVerdict(resp *D.Msg, runtime *runtimeSnapshot) Verdict {
	if resp == nil {
		return Verdict{}
	}
	gateway := runtime.gateway
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
func (r *Resolver) rewriteA(resp *D.Msg, req *D.Msg, runtime *runtimeSnapshot) *D.Msg {
	out := new(D.Msg)
	out.SetReply(req)
	out.RecursionAvailable = true
	// SetReply resets the code to NOERROR; carry the upstream's through.
	// Without this an NXDOMAIN becomes an uncacheable NOERROR with no SOA, and
	// an upstream SERVFAIL is laundered into a synthetic "no records" answer
	// that then slips past the don't-cache-failures guard and is stored as if
	// it were authoritative.
	out.Rcode = resp.Rcode

	gateway := runtime.gateway
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
			gw.Hdr.Ttl = clampTTL(a.Hdr.Ttl, runtime.tuning.ttlMin, runtime.tuning.ttlMax)
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
		out.AuthenticatedData = false
	}
	return out
}

func isLocalName(runtime *runtimeSnapshot, name string) bool {
	if runtime == nil || len(runtime.localNames) == 0 {
		return false
	}
	_, ok := runtime.localNames[normalizeDomain(name)]
	return ok
}

func (r *Resolver) cacheGet(k cacheKey, req *D.Msg, generation uint64) (*D.Msg, cacheMeta, bool) {
	msg, meta, ok := r.cache.getGeneration(k, generation)
	if ok {
		r.stats.bump(&r.stats.cacheHits)
		adoptRequest(msg, req)
	} else {
		r.stats.bump(&r.stats.cacheMisses)
	}
	return msg, meta, ok
}

// staleOrFail serves a stale entry when every upstream failed, else SERVFAIL.
func (r *Resolver) staleOrFail(req *D.Msg, k cacheKey, generation uint64, t *trace) *D.Msg {
	if stale, meta, ok := r.cache.getStaleGeneration(k, generation); ok {
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
func (r *Resolver) cachePut(k cacheKey, resp *D.Msg, runtime *runtimeSnapshot, meta cacheMeta) {
	if resp == nil {
		return
	}
	// Clamp the first reply as well as its cache lifetime. Otherwise the first
	// client observes the upstream's original TTL and may not return until long
	// after TTLMax, while only later cache hits see the configured value. Signed
	// or AD-authenticated data is never extended beyond the upstream's remaining
	// validity; raising an authenticated TTL would manufacture freshness.
	ttl := normalizeResponseTTLs(resp, runtime.tuning.ttlMin, runtime.tuning.ttlMax)
	if resp.Rcode != D.RcodeSuccess || ttl <= 0 {
		// A failure is not a cache entry. Caching one turns a transient upstream
		// problem into a sticky one; normalization above still keeps the first
		// returned response inside the configured TTL boundary.
		return
	}
	r.cache.put(k, resp, ttl, runtime.generation, meta)
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
	runtime          *runtimeSnapshot
	action           action
	originResolver   string
}

type flightScope struct {
	runtime        *runtimeSnapshot
	action         action
	originResolver string
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
// waiting on. When the map is at capacity a new key fails immediately. Running
// it independently would turn the bounded map into unbounded upstream work,
// exactly when a random-subdomain flood has already exhausted the guard.
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

	runtime := scope.runtime
	if runtime == nil {
		runtime = r.snapshot()
	}
	key := flightKey{
		name:           strings.ToLower(D.Fqdn(q.Name)),
		qtype:          q.Qtype,
		qclass:         q.Qclass,
		runtime:        runtime,
		action:         scope.action,
		originResolver: scope.originResolver,
		dnssecOK:       cacheKeyOf(q.Name, q.Qtype, template).dnssecOK,
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
		return nil, initial, false
	}

	if leader {
		go func() {
			timeout := defaultTimeout
			if runtime != nil {
				timeout = runtime.tuning.timeout
			}
			runCtx, cancel := context.WithTimeout(context.Background(), timeout)
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

func tryAcquire(sem chan struct{}) bool {
	if sem == nil {
		return false
	}
	select {
	case sem <- struct{}{}:
		return true
	default:
		return false
	}
}

func releaseAdmission(sem chan struct{}) { <-sem }

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

func normalizeResponseTTLs(m *D.Msg, lo, hi time.Duration) time.Duration {
	if m == nil {
		return 0
	}
	mayRaise := !m.AuthenticatedData && !containsRRSIG(m)
	found := false
	smallest := uint32(0)
	visit := func(rr D.RR) {
		if _, ok := rr.(*D.OPT); ok {
			return
		}
		ttl := rr.Header().Ttl
		if mayRaise {
			ttl = clampTTL(ttl, lo, hi)
		} else if maximum := uint32(hi / time.Second); ttl > maximum {
			ttl = maximum
		}
		rr.Header().Ttl = ttl
		if !found || ttl < smallest {
			smallest, found = ttl, true
		}
		if soa, ok := rr.(*D.SOA); ok {
			minimum := soa.Minttl
			if mayRaise {
				minimum = clampTTL(minimum, lo, hi)
				soa.Minttl = minimum
			}
			if minimum < smallest {
				smallest = minimum
			}
		}
	}
	for _, section := range [][]D.RR{m.Answer, m.Ns, m.Extra} {
		for _, rr := range section {
			visit(rr)
		}
	}
	if !found {
		if !mayRaise {
			return 0
		}
		smallest = uint32(lo / time.Second)
	}
	for _, section := range [][]D.RR{m.Answer, m.Ns, m.Extra} {
		for _, rr := range section {
			if _, ok := rr.(*D.OPT); ok {
				continue
			}
			rr.Header().Ttl = smallest
			if soa, ok := rr.(*D.SOA); ok && mayRaise {
				soa.Minttl = smallest
			}
		}
	}
	return time.Duration(smallest) * time.Second
}

func containsRRSIG(m *D.Msg) bool {
	for _, section := range [][]D.RR{m.Answer, m.Ns, m.Extra} {
		for _, rr := range section {
			if _, ok := rr.(*D.RRSIG); ok {
				return true
			}
		}
	}
	return false
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
