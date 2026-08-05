package dns

import (
	"context"
	"net"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	D "github.com/miekg/dns"
)

// fakePool is a scripted upstream group. The arbitration and policy rules are
// what these tests are about, and those are indifferent to what answered.
type fakePool struct {
	mu    sync.Mutex
	reply func(*D.Msg) (*D.Msg, error)
	delay time.Duration
	sent  []*D.Msg
	ecs   netip.Prefix
}

func (f *fakePool) Exchange(ctx context.Context, q *D.Msg) (*D.Msg, error) {
	f.mu.Lock()
	f.sent = append(f.sent, q.Copy())
	delay, reply := f.delay, f.reply
	f.mu.Unlock()

	if delay > 0 {
		select {
		case <-time.After(delay):
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	return reply(q)
}

func (f *fakePool) Specs() []string       { return nil }
func (f *fakePool) SetECS(p netip.Prefix) { f.ecs = p }
func (f *fakePool) ECS() netip.Prefix     { return f.ecs }
func (f *fakePool) Close()                {}
func (f *fakePool) lastSent() *D.Msg {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.sent) == 0 {
		return nil
	}
	return f.sent[len(f.sent)-1]
}

// answering builds a pool that returns one A record for every query.
func answering(addr string) *fakePool {
	return &fakePool{reply: func(q *D.Msg) (*D.Msg, error) {
		m := new(D.Msg)
		m.SetReply(q)
		m.Answer = []D.RR{&D.A{
			Hdr: D.RR_Header{Name: q.Question[0].Name, Rrtype: D.TypeA, Class: D.ClassINET, Ttl: 300},
			A:   net.ParseIP(addr),
		}}
		return m, nil
	}}
}

func failing() *fakePool {
	return &fakePool{reply: func(*D.Msg) (*D.Msg, error) { return nil, context.DeadlineExceeded }}
}

// testResolver wires a resolver with a hand-built CN set, so a test never
// depends on whether a real address is in the shipped list.
func testResolver(t *testing.T, china, trust pool) *Resolver {
	t.Helper()
	r := NewResolver(Options{Timeout: 2 * time.Second})
	r.cn = parseCNSet("203.0.113.0/24\n")
	r.swapUpstreams(&upstreams{china: china, trust: trust})
	r.SetGateway(netip.MustParseAddr("198.51.100.1"))
	return r
}

func ask(t *testing.T, r *Resolver, name string, qtype uint16) *D.Msg {
	t.Helper()
	req := new(D.Msg)
	req.SetQuestion(D.Fqdn(name), qtype)
	var tr trace
	return r.resolve(context.Background(), req.Question[0], req, &tr)
}

func askTraced(t *testing.T, r *Resolver, name string, qtype uint16) (*D.Msg, trace) {
	t.Helper()
	req := new(D.Msg)
	req.SetQuestion(D.Fqdn(name), qtype)
	var tr trace
	msg := r.resolve(context.Background(), req.Question[0], req, &tr)
	return msg, tr
}

func answerAddrs(m *D.Msg) []string { return answerIPs(m, 16) }

func policyWith(t *testing.T, r *Resolver, fallback Fallback, rules ...Rule) {
	t.Helper()
	if err := r.SetPolicy(Policy{Rules: rules, Fallback: fallback}, t.TempDir()); err != nil {
		t.Fatalf("SetPolicy: %v", err)
	}
}

// The ordered list is evaluated once, first match wins, across every intent.
// The previous design ran a block pass, then a direct pass, then a proxy pass,
// which meant an operator's `direct` rule above a `block` rule did nothing and
// nothing said so.
func TestOrderedPolicyFirstMatchWinsAcrossIntents(t *testing.T) {
	r := testResolver(t, answering("203.0.113.9"), answering("192.0.2.9"))
	policyWith(t, r, FallbackAuto,
		Rule{ID: "allow", Kind: KindDomain, Value: "ads.example.com", Intent: IntentDirect, Enabled: true},
		Rule{ID: "deny", Kind: KindDomainSuffix, Value: "example.com", Intent: IntentBlock, Enabled: true},
	)

	msg, tr := askTraced(t, r, "ads.example.com", D.TypeA)
	if msg.Rcode != D.RcodeSuccess {
		t.Fatalf("rcode %s, want NOERROR: the direct rule above the block did not win", D.RcodeToString[msg.Rcode])
	}
	if tr.reason != "force-direct" {
		t.Errorf("reason %q, want force-direct", tr.reason)
	}

	// And the block still applies to everything the direct rule did not name.
	if msg := ask(t, r, "tracker.example.com", D.TypeA); msg.Rcode != D.RcodeNameError {
		t.Errorf("rcode %s, want NXDOMAIN", D.RcodeToString[msg.Rcode])
	}
}

func TestDisabledRuleNeverMatches(t *testing.T) {
	r := testResolver(t, answering("203.0.113.9"), answering("192.0.2.9"))
	policyWith(t, r, FallbackAuto,
		Rule{ID: "deny", Kind: KindDomainSuffix, Value: "example.com", Intent: IntentBlock, Enabled: false},
	)
	if msg := ask(t, r, "a.example.com", D.TypeA); msg.Rcode == D.RcodeNameError {
		t.Error("a disabled rule blocked the name")
	}
}

func TestFallbacks(t *testing.T) {
	for _, tc := range []struct {
		fallback Fallback
		want     []string
		reason   string
	}{
		// The trust answer is foreign, so auto rewrites it to the gateway.
		{FallbackAuto, []string{"198.51.100.1"}, "chnroute-foreign"},
		// direct keeps the real address even though it is foreign.
		{FallbackDirect, []string{"192.0.2.9"}, "fallback-direct"},
		// gateway answers without asking anyone.
		{FallbackGateway, []string{"198.51.100.1"}, "fallback-gateway"},
	} {
		t.Run(string(tc.fallback), func(t *testing.T) {
			china, trust := failing(), answering("192.0.2.9")
			r := testResolver(t, china, trust)
			policyWith(t, r, tc.fallback)

			msg, tr := askTraced(t, r, "unlisted.example", D.TypeA)
			if got := answerAddrs(msg); !equalStrings(got, tc.want) {
				t.Errorf("answers %v, want %v", got, tc.want)
			}
			if tr.reason != tc.reason {
				t.Errorf("reason %q, want %q", tr.reason, tc.reason)
			}
			if tc.fallback == FallbackGateway && len(trust.sent) != 0 {
				t.Error("the gateway fallback consulted an upstream")
			}
		})
	}
}

// A domestic answer wins on membership, not on arriving first. A trust group
// that answers instantly must not beat a china group that answers slowly with a
// CN address, or the steering decision becomes a function of the weather.
func TestArbitrationIsByMembershipNotSpeed(t *testing.T) {
	china := answering("203.0.113.5")
	china.delay = 150 * time.Millisecond
	trust := answering("192.0.2.5")

	r := testResolver(t, china, trust)
	policyWith(t, r, FallbackAuto)

	msg, tr := askTraced(t, r, "slow.example", D.TypeA)
	if got := answerAddrs(msg); !equalStrings(got, []string{"203.0.113.5"}) {
		t.Errorf("answers %v, want the slow CN answer", got)
	}
	if tr.upstream != "china" {
		t.Errorf("adopted %q, want china", tr.upstream)
	}
	if tr.reason != "chnroute-cn" {
		t.Errorf("reason %q, want chnroute-cn", tr.reason)
	}
}

// Several foreign addresses are alternative routes to one origin, and the
// gateway is a single destination.
func TestForeignAddressesCollapseToOneGatewayRecord(t *testing.T) {
	trust := &fakePool{reply: func(q *D.Msg) (*D.Msg, error) {
		m := new(D.Msg)
		m.SetReply(q)
		for _, ip := range []string{"192.0.2.1", "192.0.2.2", "203.0.113.7"} {
			m.Answer = append(m.Answer, &D.A{
				Hdr: D.RR_Header{Name: q.Question[0].Name, Rrtype: D.TypeA, Class: D.ClassINET, Ttl: 300},
				A:   net.ParseIP(ip),
			})
		}
		return m, nil
	}}
	r := testResolver(t, failing(), trust)
	policyWith(t, r, FallbackAuto)

	got := answerAddrs(ask(t, r, "mixed.example", D.TypeA))
	// The CN address is kept as itself; the two foreign ones become one gateway
	// record, in the position the first of them held.
	if !equalStrings(got, []string{"198.51.100.1", "203.0.113.7"}) {
		t.Errorf("answers %v, want one gateway record plus the kept CN address", got)
	}
}

// SetReply resets the code to NOERROR. Carrying the upstream's through is what
// stops an NXDOMAIN becoming an uncacheable empty NOERROR, and an upstream
// SERVFAIL becoming a synthetic "no records" answer that then gets cached.
func TestRewritePreservesUpstreamRcode(t *testing.T) {
	trust := &fakePool{reply: func(q *D.Msg) (*D.Msg, error) {
		m := new(D.Msg)
		m.SetRcode(q, D.RcodeNameError)
		return m, nil
	}}
	r := testResolver(t, failing(), trust)
	policyWith(t, r, FallbackAuto)

	msg := ask(t, r, "missing.example", D.TypeA)
	if msg.Rcode != D.RcodeNameError {
		t.Errorf("rcode %s, want NXDOMAIN", D.RcodeToString[msg.Rcode])
	}
}

func TestWithheldTypesAnswerSyntheticNODATA(t *testing.T) {
	r := testResolver(t, answering("203.0.113.1"), answering("192.0.2.1"))
	policyWith(t, r, FallbackAuto)

	for _, qtype := range []uint16{D.TypeAAAA, D.TypeHTTPS, D.TypeSVCB} {
		msg := ask(t, r, "example.com", qtype)
		if msg.Rcode != D.RcodeSuccess || len(msg.Answer) != 0 {
			t.Errorf("%s: rcode %s with %d answers, want an empty NOERROR",
				D.TypeToString[qtype], D.RcodeToString[msg.Rcode], len(msg.Answer))
		}
		// The SOA is the part that matters: without it the asker cannot
		// negatively cache and re-queries on every single connection.
		if len(msg.Ns) != 1 {
			t.Errorf("%s: %d authority records, want the synthetic SOA", D.TypeToString[qtype], len(msg.Ns))
		}
	}
}

// An address is exactly as usable to a client from the additional section as it
// is from the answer, so an MX reply's AAAA glue defeats steering just as
// effectively as an AAAA question would.
func TestGlueAddressesAreStrippedFromEverySection(t *testing.T) {
	trust := &fakePool{reply: func(q *D.Msg) (*D.Msg, error) {
		m := new(D.Msg)
		m.SetReply(q)
		m.Answer = []D.RR{&D.MX{
			Hdr: D.RR_Header{Name: q.Question[0].Name, Rrtype: D.TypeMX, Class: D.ClassINET, Ttl: 300},
			Mx:  "mail.example.com.", Preference: 10,
		}}
		m.Extra = []D.RR{
			&D.AAAA{Hdr: D.RR_Header{Name: "mail.example.com.", Rrtype: D.TypeAAAA, Class: D.ClassINET, Ttl: 300}, AAAA: net.ParseIP("2001:db8::1")},
			&D.A{Hdr: D.RR_Header{Name: "mail.example.com.", Rrtype: D.TypeA, Class: D.ClassINET, Ttl: 300}, A: net.ParseIP("192.0.2.20")},
		}
		return m, nil
	}}
	r := testResolver(t, failing(), trust)
	policyWith(t, r, FallbackAuto)

	msg := ask(t, r, "example.com", D.TypeMX)
	for _, rr := range append(append([]D.RR{}, msg.Answer...), append(msg.Ns, msg.Extra...)...) {
		if _, ok := rr.(*D.AAAA); ok {
			t.Fatal("an AAAA survived in the reply")
		}
	}
	// The A glue is legitimate and must survive, or the client loses the
	// address it actually can use.
	found := false
	for _, rr := range msg.Extra {
		if _, ok := rr.(*D.A); ok {
			found = true
		}
	}
	if !found {
		t.Error("the A glue was stripped along with the AAAA")
	}
}

// A signature left behind after the data it covers was rewritten makes a
// validating stub fail -- on exactly the proxied names, which reads as "some
// sites are broken" rather than as a DNSSEC problem.
func TestRewrittenAnswerDropsSignatures(t *testing.T) {
	withRRSIG := func(addr string) *fakePool {
		return &fakePool{reply: func(q *D.Msg) (*D.Msg, error) {
			m := new(D.Msg)
			m.SetReply(q)
			m.Answer = []D.RR{
				&D.A{Hdr: D.RR_Header{Name: q.Question[0].Name, Rrtype: D.TypeA, Class: D.ClassINET, Ttl: 300}, A: net.ParseIP(addr)},
				&D.RRSIG{Hdr: D.RR_Header{Name: q.Question[0].Name, Rrtype: D.TypeRRSIG, Class: D.ClassINET, Ttl: 300}, TypeCovered: D.TypeA},
			}
			return m, nil
		}}
	}

	t.Run("foreign answer is rewritten, so signatures go", func(t *testing.T) {
		r := testResolver(t, failing(), withRRSIG("192.0.2.30"))
		policyWith(t, r, FallbackAuto)
		for _, rr := range ask(t, r, "signed.example", D.TypeA).Answer {
			if _, ok := rr.(*D.RRSIG); ok {
				t.Fatal("a signature survived a rewritten answer")
			}
		}
	})

	t.Run("CN answer is untouched, so signatures stay", func(t *testing.T) {
		r := testResolver(t, withRRSIG("203.0.113.30"), failing())
		policyWith(t, r, FallbackAuto)
		signed := false
		for _, rr := range ask(t, r, "signed.cn", D.TypeA).Answer {
			if _, ok := rr.(*D.RRSIG); ok {
				signed = true
			}
		}
		if !signed {
			t.Error("signatures were stripped from an answer nothing rewrote")
		}
	})
}

func TestUpstreamFailureIsServfailNotAnEmptyAnswer(t *testing.T) {
	r := testResolver(t, failing(), failing())
	policyWith(t, r, FallbackAuto)
	if msg := ask(t, r, "down.example", D.TypeA); msg.Rcode != D.RcodeServerFailure {
		t.Errorf("rcode %s, want SERVFAIL", D.RcodeToString[msg.Rcode])
	}
}

// A slightly stale answer beats handing every client a hard error while correct
// data sat in memory seconds ago.
func TestStaleAnswerServedWhenEveryUpstreamFails(t *testing.T) {
	trust := answering("192.0.2.40")
	r := testResolver(t, failing(), trust)
	policyWith(t, r, FallbackAuto)

	if got := answerAddrs(ask(t, r, "flaky.example", D.TypeA)); len(got) == 0 {
		t.Fatal("the first query did not populate the cache")
	}
	// Expire everything, then take the upstream away.
	r.cache.mu.Lock()
	for k, e := range r.cache.m {
		e.expiry = time.Now().Add(-time.Minute)
		r.cache.m[k] = e
	}
	r.cache.mu.Unlock()
	trust.mu.Lock()
	trust.reply = func(*D.Msg) (*D.Msg, error) { return nil, context.DeadlineExceeded }
	trust.mu.Unlock()

	msg, tr := askTraced(t, r, "flaky.example", D.TypeA)
	if msg.Rcode != D.RcodeSuccess {
		t.Fatalf("rcode %s, want the stale answer", D.RcodeToString[msg.Rcode])
	}
	if !tr.cacheHit {
		t.Error("the stale answer was not reported as a cache hit")
	}
	for _, rr := range msg.Answer {
		if rr.Header().Ttl != staleReplyTTL {
			t.Errorf("stale TTL %d, want %d so the client comes back soon", rr.Header().Ttl, staleReplyTTL)
		}
	}
}

// A flush that lands while a query is in flight must not be repopulated by that
// query's pre-flush answer, or a policy apply is a silent no-op for exactly the
// name the operator was editing.
func TestFlushDuringFlightDiscardsTheWrite(t *testing.T) {
	c := newCache(16)
	key := cacheKey{name: "example.com.", qtype: D.TypeA}
	epoch := c.Epoch()

	c.Flush() // the apply lands here

	msg := new(D.Msg)
	msg.SetQuestion("example.com.", D.TypeA)
	c.put(key, msg, time.Hour, epoch, cacheMeta{})

	if _, _, ok := c.get(key); ok {
		t.Error("a pre-flush answer repopulated the flushed cache")
	}
}

func TestBreakerOpensAndCancellationDoesNot(t *testing.T) {
	b := newBreaker()
	for i := 0; i < breakerThreshold; i++ {
		if !b.allow() {
			t.Fatalf("breaker opened after %d failures, before the threshold", i)
		}
		b.record(false)
	}
	if b.allow() {
		t.Error("breaker stayed closed at the threshold")
	}

	// Cancellation is the common case on this gateway: arbitration abandons
	// trust on every domestic win. Counting those would trip the breaker after
	// five CN answers in a row.
	b2 := newBreaker()
	for i := 0; i < breakerThreshold*3; i++ {
		b2.allow()
		b2.recordCanceled()
	}
	if !b2.allow() {
		t.Error("caller cancellation tripped the breaker")
	}
}

func TestParseMemberGrammar(t *testing.T) {
	ok := map[string]Transport{
		"223.5.5.5":                                TransportUDP,
		"223.5.5.5:5353":                           TransportUDP,
		"dns.alidns.com@223.5.5.5":                 TransportDoT,
		"dns.alidns.com@223.5.5.5:853":             TransportDoT,
		"https://dns.google/dns-query@8.8.8.8":     TransportDoH,
		"https://dns.google/dns-query@8.8.8.8:443": TransportDoH,
	}
	for spec, want := range ok {
		m, err := ParseMember(spec)
		if err != nil {
			t.Errorf("ParseMember(%q): %v", spec, err)
			continue
		}
		if m.Transport != want {
			t.Errorf("ParseMember(%q) transport %d, want %d", spec, m.Transport, want)
		}
		if _, _, err := net.SplitHostPort(m.DialAddr); err != nil {
			t.Errorf("ParseMember(%q) dial address %q has no port", spec, m.DialAddr)
		}
	}

	// A bare hostname is refused rather than parsed: resolving an upstream's
	// own name would have to come back through this resolver.
	bad := []string{
		"", "dns.google", "dns.alidns.com@", "@223.5.5.5",
		"https://dns.google@8.8.8.8",   // no endpoint path
		"https://dns.google/dns-query", // no pinned address
		"dns.alidns.com@example.com",   // dial part is a name
		"223.5.5.5:0", "223.5.5.5:99999",
	}
	for _, spec := range bad {
		if m, err := ParseMember(spec); err == nil {
			t.Errorf("ParseMember(%q) accepted it as %+v", spec, m)
		}
	}
}

func TestParseMembersRefusesAnEmptyGroup(t *testing.T) {
	if _, err := ParseMembers("china", []string{"  ", ""}); err == nil {
		t.Error("an empty group was accepted; every query against it would time out with no error anywhere")
	}
}

// Only the operator's subnet may leave the gateway, and it must never be echoed
// back to a client that did not ask for it.
func TestECSReplacesTheClientSubnetAndStripsTheEcho(t *testing.T) {
	members, err := ParseMembers("china", []string{"203.0.113.53"})
	if err != nil {
		t.Fatal(err)
	}
	g := newGroup("china", members)
	g.SetECS(netip.MustParsePrefix("112.96.32.0/24"))

	req := new(D.Msg)
	req.SetQuestion("example.com.", D.TypeA)
	req.SetEdns0(1232, false)
	setECS(req, netip.MustParsePrefix("10.9.8.0/24")) // the client's own value

	sent := req.Copy()
	stripECS(sent)
	if p := g.ecs.Load(); p != nil {
		setECS(sent, *p)
	}

	opt := sent.IsEdns0()
	if opt == nil {
		t.Fatal("the OPT record was lost")
	}
	subnets := 0
	for _, o := range opt.Option {
		if s, ok := o.(*D.EDNS0_SUBNET); ok {
			subnets++
			if got := s.Address.String(); got != "112.96.32.0" {
				t.Errorf("sent subnet %s, want the operator's 112.96.32.0", got)
			}
		}
	}
	if subnets != 1 {
		t.Errorf("%d subnet options on the wire, want exactly the operator's", subnets)
	}

	// And an upstream echo does not reach the client.
	reply := sent.Copy()
	stripECS(reply)
	for _, o := range reply.IsEdns0().Option {
		if _, ok := o.(*D.EDNS0_SUBNET); ok {
			t.Error("the subnet was echoed back to the client")
		}
	}
}

// A dead first member must not consume the whole query budget.
func TestGroupRollsPastADeadMember(t *testing.T) {
	// A bound socket that never replies is a black hole rather than a refusal,
	// which is the case that costs a timeout.
	blackhole, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer blackhole.Close()

	live := &D.Server{Addr: "127.0.0.1:0", Net: "udp"}
	ready := make(chan struct{})
	live.NotifyStartedFunc = func() { close(ready) }
	live.Handler = D.HandlerFunc(func(w D.ResponseWriter, req *D.Msg) {
		m := new(D.Msg)
		m.SetReply(req)
		m.Answer = []D.RR{&D.A{
			Hdr: D.RR_Header{Name: req.Question[0].Name, Rrtype: D.TypeA, Class: D.ClassINET, Ttl: 60},
			A:   net.ParseIP("203.0.113.77"),
		}}
		_ = w.WriteMsg(m)
	})
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	live.PacketConn = pc
	go func() { _ = live.ActivateAndServe() }()
	defer live.Shutdown()
	<-ready

	members, err := ParseMembers("trust", []string{blackhole.LocalAddr().String(), pc.LocalAddr().String()})
	if err != nil {
		t.Fatal(err)
	}
	g := newGroup("trust", members)

	req := new(D.Msg)
	req.SetQuestion("example.com.", D.TypeA)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	reply, err := g.Exchange(ctx, req)
	if err != nil {
		t.Fatalf("the group gave up instead of trying the second member: %v", err)
	}
	if got := answerAddrs(reply); !equalStrings(got, []string{"203.0.113.77"}) {
		t.Errorf("answers %v, want the live member's", got)
	}
}

// The origin boundary answers a different question from the client one, and
// answering it with the gateway address would point the box at itself.
func TestOriginNeverReturnsTheGatewayAddress(t *testing.T) {
	r := testResolver(t, failing(), answering("192.0.2.60"))
	policyWith(t, r, FallbackGateway) // every client name steers

	if got := answerAddrs(ask(t, r, "origin.example", D.TypeA)); !equalStrings(got, []string{"198.51.100.1"}) {
		t.Fatalf("client answers %v, want the gateway", got)
	}

	origin, err := r.OriginResolve(context.Background(), "origin.example")
	if err != nil {
		t.Fatalf("OriginResolve: %v", err)
	}
	if !equalStrings(origin, []string{"192.0.2.60"}) {
		t.Errorf("origin answers %v, want the real address", origin)
	}
}

// The origin boundary is what actually keeps egress on IPv4: mihomo issues the
// AAAA query unconditionally, and an answered one gets raced against the v4
// addresses.
func TestOriginWithholdsAAAA(t *testing.T) {
	trust := &fakePool{reply: func(q *D.Msg) (*D.Msg, error) {
		t := new(D.Msg)
		t.SetReply(q)
		t.Answer = []D.RR{&D.AAAA{
			Hdr:  D.RR_Header{Name: q.Question[0].Name, Rrtype: D.TypeAAAA, Class: D.ClassINET, Ttl: 300},
			AAAA: net.ParseIP("2001:db8::5"),
		}}
		return t, nil
	}}
	r := testResolver(t, failing(), trust)
	policyWith(t, r, FallbackAuto)

	req := new(D.Msg)
	req.SetQuestion("v6.example.", D.TypeAAAA)
	resp := r.resolveOrigin(context.Background(), req.Question[0], req)
	if len(resp.Answer) != 0 {
		t.Errorf("the origin boundary answered AAAA with %d records", len(resp.Answer))
	}
	if len(trust.sent) != 0 {
		t.Error("the origin boundary asked an upstream for an AAAA it will never serve")
	}
}

// An extension's china binding must reach the origin lookup, or the operator's
// choice is recorded and ignored.
func TestOriginHonoursTheCaptureResolverBinding(t *testing.T) {
	china, trust := answering("203.0.113.80"), answering("192.0.2.80")
	r := testResolver(t, china, trust)
	policyWith(t, r, FallbackAuto)
	r.SetCaptureLookup(func(name string) (Capture, bool) {
		if name == "bound.example" {
			return Capture{ExtensionID: "ext", Resolver: "china", Ready: true}, true
		}
		return Capture{}, false
	})

	got, err := r.OriginResolve(context.Background(), "bound.example")
	if err != nil {
		t.Fatal(err)
	}
	if !equalStrings(got, []string{"203.0.113.80"}) {
		t.Errorf("origin answers %v, want the china group's", got)
	}

	// Everything else still uses trust.
	got, err = r.OriginResolve(context.Background(), "unbound.example")
	if err != nil {
		t.Fatal(err)
	}
	if !equalStrings(got, []string{"192.0.2.80"}) {
		t.Errorf("origin answers %v, want the trust group's", got)
	}
}

// A ready capture steers; a declaration with the master off falls through to
// policy, because steering it would send the client to a gateway with nothing
// able to terminate the connection.
func TestCaptureSteersOnlyWhenReady(t *testing.T) {
	for _, ready := range []bool{true, false} {
		r := testResolver(t, failing(), answering("192.0.2.90"))
		policyWith(t, r, FallbackDirect)
		r.SetCaptureLookup(func(string) (Capture, bool) {
			return Capture{ExtensionID: "ext", Pattern: "captured.example", Ready: ready}, true
		})

		got := answerAddrs(ask(t, r, "captured.example", D.TypeA))
		want := []string{"192.0.2.90"}
		if ready {
			want = []string{"198.51.100.1"}
		}
		if !equalStrings(got, want) {
			t.Errorf("ready=%v: answers %v, want %v", ready, got, want)
		}

		// Either way the diagnostic names the extension, so an operator asking
		// why a name is not captured is told about the master switch rather
		// than shown an empty answer.
		if d := r.Decide("captured.example"); d.Capture == nil {
			t.Errorf("ready=%v: the decision dropped the capture attribution", ready)
		}
	}
}

// The diagnostic runs the real path. A reimplementation drifts, and an operator
// trusts it enough to stop looking.
func TestExplainAgreesWithLiveResolution(t *testing.T) {
	r := testResolver(t, failing(), answering("192.0.2.100"))
	policyWith(t, r, FallbackAuto,
		Rule{ID: "steer", Kind: KindDomainSuffix, Value: "corp.example", Intent: IntentProxy, Enabled: true},
	)

	msg, tr := askTraced(t, r, "www.corp.example", D.TypeA)
	got := r.Explain(context.Background(), "www.corp.example")

	if got.Verdict.Reason != tr.reason {
		t.Errorf("Explain reason %q, live %q", got.Verdict.Reason, tr.reason)
	}
	if !equalStrings(got.Answers, answerAddrs(msg)) {
		t.Errorf("Explain answers %v, live %v", got.Answers, answerAddrs(msg))
	}
	if got.Rule == nil || got.Rule.ID != "steer" {
		t.Errorf("Explain did not name the rule that won: %+v", got.Rule)
	}
	// The origin is reported alongside, because that is where the two diverge
	// and seeing only the steered answer reads as "DNS is broken".
	if !equalStrings(got.Origin, []string{"192.0.2.100"}) {
		t.Errorf("Explain origin %v, want the real address", got.Origin)
	}
}

func TestKeywordAndSuffixMatching(t *testing.T) {
	set := &domainSet{
		exact:   map[string]struct{}{"exact.example": {}},
		suffix:  map[string]struct{}{"suffix.example": {}},
		keyword: []string{"track"},
	}
	for name, want := range map[string]bool{
		"exact.example":        true,
		"sub.exact.example":    false, // exact is exact
		"suffix.example":       true,  // the suffix covers itself
		"a.b.suffix.example":   true,
		"notsuffix.example":    false, // label boundary, not string suffix
		"cdn.tracking.example": true,  // keyword
		"clean.example":        false,
	} {
		if got := set.match(name); got != want {
			t.Errorf("match(%q) = %v, want %v", name, got, want)
		}
	}
}

func TestPolicyValidation(t *testing.T) {
	bad := []Policy{
		{Fallback: "sideways"},
		{Fallback: FallbackAuto, Rules: []Rule{{ID: "a", Kind: KindDomain, Value: "example.com", Intent: "steer", Enabled: true}}},
		{Fallback: FallbackAuto, Rules: []Rule{{ID: "../escape", Kind: KindDomain, Value: "example.com", Intent: IntentBlock}}},
		{Fallback: FallbackAuto, Rules: []Rule{{ID: "a", Kind: KindDomain, Value: "com", Intent: IntentBlock}}},
		{Fallback: FallbackAuto, Rules: []Rule{{ID: "a", Kind: KindDomain, Value: "ok.example\nx", Intent: IntentBlock}}},
		{Fallback: FallbackAuto, Rules: []Rule{
			{ID: "dup", Kind: KindDomain, Value: "a.example", Intent: IntentBlock},
			{ID: "dup", Kind: KindDomain, Value: "b.example", Intent: IntentBlock},
		}},
		{Fallback: FallbackAuto, Rules: []Rule{{ID: "s", Kind: KindSubscription, Value: "http://plain.example/list", Format: "plain", IntervalSeconds: 3600}}},
		{Fallback: FallbackAuto, Rules: []Rule{{ID: "s", Kind: KindSubscription, Value: "https://example/list", Format: "plain"}}},
		{Fallback: FallbackAuto, Rules: []Rule{{ID: "s", Kind: KindDomain, Value: "a.example", Intent: IntentBlock, Format: "plain"}}},
	}
	for i, p := range bad {
		if err := p.Validate(); err == nil {
			t.Errorf("policy %d was accepted: %+v", i, p)
		}
	}

	good := Policy{Fallback: FallbackAuto, Rules: []Rule{
		{ID: "a", Kind: KindDomain, Value: "a.example", Intent: IntentBlock, Enabled: true},
		{ID: "b", Kind: KindDomainKeyword, Value: "ads", Intent: IntentBlock, Enabled: true},
		{ID: "c", Kind: KindSubscription, Value: "https://example.com/list.txt", Format: "clash", IntervalSeconds: 86400, Intent: IntentProxy, Enabled: true},
	}}
	if err := good.Validate(); err != nil {
		t.Errorf("a valid policy was rejected: %v", err)
	}
}

func TestDocumentValidation(t *testing.T) {
	d := DefaultDocument()
	if err := d.Validate(); err != nil {
		t.Fatalf("the default document is invalid: %v", err)
	}
	d.Gateway = "not-an-address"
	if err := d.Validate(); err == nil {
		t.Error("a malformed gateway was accepted")
	}
	d = DefaultDocument()
	d.Gateway = "2001:db8::1"
	if err := d.Validate(); err == nil {
		t.Error("an IPv6 gateway was accepted on an IPv4-only data plane")
	}
}

func TestECSParsing(t *testing.T) {
	for raw, want := range map[string]string{
		"":               "",
		"122.96.30.5":    "122.96.30.0/24",
		"122.96.30.0/22": "122.96.28.0/22",
		// A /56 cuts inside the fourth group, so the low half of 0002 goes too.
		"2001:db8:1:2::5": "2001:db8:1::/56",
	} {
		got, err := parseECS(raw)
		if err != nil {
			t.Errorf("parseECS(%q): %v", raw, err)
			continue
		}
		if ecsString(got) != want {
			t.Errorf("parseECS(%q) = %q, want %q", raw, ecsString(got), want)
		}
	}
	if _, err := parseECS("nonsense"); err == nil {
		t.Error("parseECS accepted nonsense")
	}
}

// An unstripped marker passes name validation and is cached as a literal that
// label-boundary matching can never match -- a subscription reporting a healthy
// count while matching nothing.
func TestClashMarkersAreStripped(t *testing.T) {
	raw := []byte(strings.Join([]string{
		"payload:",
		"  - '+.example.com'",
		"  - '.other.example'",
		"  - 'DOMAIN-SUFFIX,third.example'",
		"  - 'DOMAIN,fourth.example'",
		"  - 'DOMAIN-KEYWORD,ads'",
		"  - 'IP-CIDR,10.0.0.0/8'",
		"  - '*.wild.example'",
	}, "\n"))
	got, err := parseDomains("clash", raw)
	if err != nil {
		t.Fatalf("parseDomains: %v", err)
	}
	want := []string{"example.com", "fourth.example", "other.example", "third.example"}
	if !equalStrings(got, want) {
		t.Errorf("parsed %v, want %v", got, want)
	}
}

func TestSubscriptionFetchRefusesPrivateAddresses(t *testing.T) {
	for _, addr := range []string{"127.0.0.1", "10.1.2.3", "192.168.1.1", "169.254.1.1", "100.64.0.1", "0.0.0.0", "224.0.0.1"} {
		if isPublicUnicast(netip.MustParseAddr(addr)) {
			t.Errorf("isPublicUnicast(%s) accepted it", addr)
		}
	}
	for _, addr := range []string{"8.8.8.8", "1.1.1.1", "2001:db8::1"} {
		if !isPublicUnicast(netip.MustParseAddr(addr)) {
			t.Errorf("isPublicUnicast(%s) refused a public address", addr)
		}
	}
}

func TestAdmissionControlShedsRatherThanAccretes(t *testing.T) {
	r := NewResolver(Options{Timeout: time.Second, MaxInflight: 1})
	r.cn = parseCNSet("203.0.113.0/24\n")
	r.swapUpstreams(&upstreams{china: failing(), trust: failing()})
	if err := r.SetPolicy(Policy{Fallback: FallbackAuto}, t.TempDir()); err != nil {
		t.Fatal(err)
	}

	r.sem <- struct{}{} // the one slot is taken
	w := &captureWriter{}
	req := new(D.Msg)
	req.SetQuestion("shed.example.", D.TypeA)
	r.ServeDNS(w, req)

	if w.msg == nil || w.msg.Rcode != D.RcodeRefused {
		t.Fatalf("got %v, want REFUSED", w.msg)
	}
}

type captureWriter struct {
	D.ResponseWriter
	msg *D.Msg
}

func (c *captureWriter) WriteMsg(m *D.Msg) error { c.msg = m; return nil }
func (c *captureWriter) RemoteAddr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 5300}
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
