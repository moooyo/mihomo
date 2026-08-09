package dns

import (
	"context"
	"net"
	"net/netip"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/metacubex/mihomo/5gpn/state"
	D "github.com/miekg/dns"
)

func TestDocumentTuningValidation(t *testing.T) {
	tests := []struct {
		name   string
		tuning Tuning
	}{
		{name: "negative", tuning: Tuning{TimeoutMs: -1}},
		{name: "timeout below minimum", tuning: Tuning{TimeoutMs: 99}},
		{name: "timeout above maximum", tuning: Tuning{TimeoutMs: 30001}},
		{name: "ttl min above maximum", tuning: Tuning{TTLMinSeconds: 86401}},
		{name: "ttl max above maximum", tuning: Tuning{TTLMaxSeconds: 604801}},
		{name: "ttl range inverted", tuning: Tuning{TTLMinSeconds: 120, TTLMaxSeconds: 60}},
		{name: "cache below minimum", tuning: Tuning{CacheSize: 127}},
		{name: "cache above maximum", tuning: Tuning{CacheSize: maxDocumentCache + 1}},
		{name: "inflight above maximum", tuning: Tuning{MaxInflight: 4097}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			document := DefaultDocument()
			document.Tuning = test.tuning
			if err := document.Validate(); err == nil {
				t.Fatalf("tuning %+v was accepted", test.tuning)
			}
		})
	}

	document := DefaultDocument()
	document.Tuning = Tuning{
		TimeoutMs: 100, TTLMinSeconds: 1, TTLMaxSeconds: 604800,
		CacheSize: 128, MaxInflight: 1,
	}
	if err := document.Validate(); err != nil {
		t.Fatalf("valid tuning was rejected: %v", err)
	}
}

func TestDocumentTuningHotAppliesAsOneRuntime(t *testing.T) {
	stateDir := t.TempDir()
	seed := DefaultDocument()
	seed.Policy = Policy{Rules: []Rule{}, Fallback: FallbackDirect}
	if _, err := state.New(filepath.Join(stateDir, "dns.json"), seed); err != nil {
		t.Fatalf("seed document: %v", err)
	}
	service, err := Open(stateDir)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	service.subs.stopRun()
	t.Cleanup(func() { service.Shutdown(context.Background()) })

	_, revision := service.Document()
	_, nextRevision, err := service.Update(revision, func(document Document) (Document, error) {
		document.Tuning = Tuning{
			TimeoutMs: 1500, TTLMinSeconds: 30, TTLMaxSeconds: 90,
			CacheSize: 256, MaxInflight: 3,
		}
		return document, nil
	})
	if err != nil {
		t.Fatalf("Update: %v", err)
	}
	runtime := service.resolver.snapshot()
	if runtime.tuning.timeout != 1500*time.Millisecond || runtime.tuning.ttlMin != 30*time.Second || runtime.tuning.ttlMax != 90*time.Second {
		t.Fatalf("live tuning = %+v", runtime.tuning)
	}
	if cap(runtime.clientSem) != 3 {
		t.Fatalf("live admission capacity = %d, want 3", cap(runtime.clientSem))
	}
	service.resolver.cache.mu.Lock()
	cacheSize := service.resolver.cache.max
	service.resolver.cache.mu.Unlock()
	if cacheSize != 256 {
		t.Fatalf("live cache capacity = %d, want 256", cacheSize)
	}

	before := runtime
	_, rejectedRevision, err := service.Update(nextRevision, func(document Document) (Document, error) {
		document.Tuning.MaxInflight = maxDocumentInflight + 1
		return document, nil
	})
	if err == nil {
		t.Fatal("invalid tuning update succeeded")
	}
	if rejectedRevision != nextRevision {
		t.Fatalf("rejected revision = %q, want %q", rejectedRevision, nextRevision)
	}
	if service.resolver.snapshot() != before {
		t.Fatal("rejected tuning update changed the live runtime")
	}
}

func TestRuntimeSnapshotDoesNotMixLocalNamesAndGateway(t *testing.T) {
	r := testResolver(t, failing(), answering("192.0.2.9"))
	policyWith(t, r, FallbackDirect)
	base := r.snapshot()
	publishA := func() {
		r.applyDocumentRuntime(base.policy, base.ups, map[string]struct{}{"a.example": {}}, netip.MustParseAddr("198.51.100.1"), base.tuning)
	}
	publishB := func() {
		r.applyDocumentRuntime(base.policy, base.ups, map[string]struct{}{"b.example": {}}, netip.MustParseAddr("198.51.100.2"), base.tuning)
	}
	publishA()

	start := make(chan struct{})
	var writers sync.WaitGroup
	writers.Add(1)
	go func() {
		defer writers.Done()
		<-start
		for i := 0; i < 500; i++ {
			publishB()
			publishA()
		}
	}()
	close(start)
	for i := 0; i < 500; i++ {
		for _, address := range answerAddrs(ask(t, r, "a.example", D.TypeA)) {
			if address == "198.51.100.2" {
				t.Fatal("a.example combined generation A's local name with generation B's gateway")
			}
		}
		for _, address := range answerAddrs(ask(t, r, "b.example", D.TypeA)) {
			if address == "198.51.100.1" {
				t.Fatal("b.example combined generation B's local name with generation A's gateway")
			}
		}
	}
	writers.Wait()
}

func TestHardInvalidationCannotServePreviousGenerationStale(t *testing.T) {
	trust := answering("192.0.2.40")
	r := testResolver(t, failing(), trust)
	policyWith(t, r, FallbackDirect)
	if got := answerAddrs(ask(t, r, "changed.example", D.TypeA)); len(got) == 0 {
		t.Fatal("initial lookup did not populate the cache")
	}
	r.cache.softExpire(r.snapshot().generation)
	trust.mu.Lock()
	trust.reply = func(*D.Msg) (*D.Msg, error) { return nil, context.DeadlineExceeded }
	trust.mu.Unlock()

	r.SetGateway(netip.MustParseAddr("198.51.100.2"))
	response := ask(t, r, "changed.example", D.TypeA)
	if response.Rcode != D.RcodeServerFailure {
		t.Fatalf("rcode = %s, want SERVFAIL instead of previous-generation stale", D.RcodeToString[response.Rcode])
	}
}

func TestCaptureSwapInvalidatesOriginBindingCache(t *testing.T) {
	r := testResolver(t, answering("203.0.113.8"), answering("192.0.2.8"))
	addresses, err := r.OriginResolve(context.Background(), "bound.example")
	if err != nil || len(addresses) != 1 || addresses[0] != "192.0.2.8" {
		t.Fatalf("initial origin = %v, %v", addresses, err)
	}
	r.SetCaptureLookup(func(string) (Capture, bool) {
		return Capture{Resolver: "china", Claimed: true}, true
	})
	addresses, err = r.OriginResolve(context.Background(), "bound.example")
	if err != nil || len(addresses) != 1 || addresses[0] != "203.0.113.8" {
		t.Fatalf("origin after capture swap = %v, %v", addresses, err)
	}
}

func TestCaptureHandoffCannotReuseDirectAddressCache(t *testing.T) {
	trust := &fakePool{reply: func(query *D.Msg) (*D.Msg, error) {
		message := new(D.Msg)
		message.SetReply(query)
		message.Answer = []D.RR{&D.MX{
			Hdr: D.RR_Header{Name: query.Question[0].Name, Rrtype: D.TypeMX, Class: D.ClassINET, Ttl: 300},
			Mx:  "mail.example.",
		}}
		message.Extra = []D.RR{&D.A{
			Hdr: D.RR_Header{Name: "mail.example.", Rrtype: D.TypeA, Class: D.ClassINET, Ttl: 300},
			A:   net.ParseIP("192.0.2.44"),
		}}
		return message, nil
	}}
	r := testResolver(t, failing(), trust)
	policyWith(t, r, FallbackDirect)
	var captured atomic.Bool
	r.SetCaptureLookup(func(string) (Capture, bool) {
		if !captured.Load() {
			return Capture{}, false
		}
		return Capture{Claimed: true, Resolver: "trust"}, true
	})
	if message := ask(t, r, "handoff.example", D.TypeMX); len(message.Extra) != 1 {
		t.Fatalf("direct response did not populate the address cache: %+v", message.Extra)
	}

	// Model the engine's config publication immediately before it invokes the
	// DNS generation callback. The dynamic lookup sees capture while the runtime
	// pointer is intentionally still the same.
	captured.Store(true)
	message := ask(t, r, "handoff.example", D.TypeMX)
	for _, rr := range append(append([]D.RR{}, message.Answer...), message.Extra...) {
		if _, ok := rr.(*D.A); ok {
			t.Fatalf("capture handoff reused a direct address cache entry: %v", rr)
		}
	}
	trust.mu.Lock()
	requests := len(trust.sent)
	trust.mu.Unlock()
	if requests != 2 {
		t.Fatalf("capture handoff upstream requests = %d, want a distinct gateway decision lookup", requests)
	}
}

func TestOriginFlightsAreSeparatedByCaptureResolver(t *testing.T) {
	r := testResolver(t, answering("203.0.113.9"), answering("192.0.2.9"))
	runtime := r.snapshot()
	query := new(D.Msg)
	query.SetQuestion("flight.example.", D.TypeA)
	started := make(chan struct{})
	release := make(chan struct{})
	var releaseOnce sync.Once
	defer releaseOnce.Do(func() { close(release) })
	firstDone := make(chan struct{})
	go func() {
		defer close(firstDone)
		_, _, _ = r.coalesce(context.Background(), query.Question[0], query,
			flightScope{runtime: runtime, action: actionOrigin, originResolver: "trust"}, trace{},
			func(_ context.Context, request *D.Msg, _ *trace) *D.Msg {
				close(started)
				<-release
				message := new(D.Msg)
				message.SetReply(request)
				return message
			})
	}()
	<-started
	secondRan := false
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	response, _, ok := r.coalesce(ctx, query.Question[0], query,
		flightScope{runtime: runtime, action: actionOrigin, originResolver: "china"}, trace{},
		func(_ context.Context, request *D.Msg, _ *trace) *D.Msg {
			secondRan = true
			message := new(D.Msg)
			message.SetReply(request)
			return message
		})
	if !ok || response == nil || !secondRan {
		t.Fatal("china origin lookup joined the in-flight trust lookup")
	}
	releaseOnce.Do(func() { close(release) })
	<-firstDone
}

func TestGatewayNonAResponsesDoNotDiscloseAddresses(t *testing.T) {
	responsePool := &fakePool{reply: func(query *D.Msg) (*D.Msg, error) {
		message := new(D.Msg)
		message.SetReply(query)
		message.AuthenticatedData = true
		message.Answer = []D.RR{
			&D.TXT{Hdr: D.RR_Header{Name: query.Question[0].Name, Rrtype: D.TypeTXT, Class: D.ClassINET, Ttl: 300}, Txt: []string{"kept"}},
			&D.A{Hdr: D.RR_Header{Name: query.Question[0].Name, Rrtype: D.TypeA, Class: D.ClassINET, Ttl: 300}, A: net.ParseIP("192.0.2.10")},
		}
		message.Ns = []D.RR{&D.A{Hdr: D.RR_Header{Name: "ns.example.", Rrtype: D.TypeA, Class: D.ClassINET, Ttl: 300}, A: net.ParseIP("192.0.2.11")}}
		message.Extra = []D.RR{
			&D.A{Hdr: D.RR_Header{Name: "mail.example.", Rrtype: D.TypeA, Class: D.ClassINET, Ttl: 300}, A: net.ParseIP("192.0.2.12")},
			&D.AAAA{Hdr: D.RR_Header{Name: "mail.example.", Rrtype: D.TypeAAAA, Class: D.ClassINET, Ttl: 300}, AAAA: net.ParseIP("2001:db8::1")},
		}
		return message, nil
	}}
	r := testResolver(t, failing(), responsePool)
	policyWith(t, r, FallbackGateway)
	message := ask(t, r, "hidden.example", D.TypeANY)
	if len(message.Answer) != 1 {
		t.Fatalf("answer count = %d, want only the non-address TXT", len(message.Answer))
	}
	if message.AuthenticatedData {
		t.Fatal("rewritten gateway response retained the upstream AD bit")
	}
	for _, section := range [][]D.RR{message.Answer, message.Ns, message.Extra} {
		for _, rr := range section {
			switch rr.(type) {
			case *D.A, *D.AAAA, *D.HTTPS, *D.SVCB:
				t.Fatalf("gateway response disclosed %T", rr)
			}
		}
	}
	mxMessage := ask(t, r, "hidden-mx.example", D.TypeMX)
	for _, section := range [][]D.RR{mxMessage.Answer, mxMessage.Ns, mxMessage.Extra} {
		for _, rr := range section {
			if _, ok := rr.(*D.A); ok {
				t.Fatalf("gateway MX response disclosed IPv4 glue %v", rr)
			}
		}
	}

	direct := testResolver(t, failing(), responsePool)
	policyWith(t, direct, FallbackDirect)
	directMessage := ask(t, direct, "visible.example", D.TypeMX)
	foundA := false
	for _, rr := range append(append([]D.RR{}, directMessage.Ns...), directMessage.Extra...) {
		if _, ok := rr.(*D.A); ok {
			foundA = true
		}
	}
	if !foundA {
		t.Fatal("direct non-A response lost legitimate IPv4 glue")
	}

	auto := testResolver(t, failing(), responsePool)
	policyWith(t, auto, FallbackAuto)
	autoMessage := ask(t, auto, "auto.example", D.TypeANY)
	for _, section := range [][]D.RR{autoMessage.Answer, autoMessage.Ns, autoMessage.Extra} {
		for _, rr := range section {
			if _, ok := rr.(*D.A); ok {
				t.Fatalf("auto ANY response disclosed an unarbitrated origin address: %v", rr)
			}
		}
	}
}

func TestTTLClampAppliesToFirstResponse(t *testing.T) {
	for _, test := range []struct {
		name string
		ttl  uint32
		want uint32
	}{
		{name: "minimum", ttl: 10, want: 60},
		{name: "maximum", ttl: 300, want: 120},
	} {
		t.Run(test.name, func(t *testing.T) {
			trust := &fakePool{reply: func(query *D.Msg) (*D.Msg, error) {
				message := new(D.Msg)
				message.SetReply(query)
				message.Answer = []D.RR{&D.A{
					Hdr: D.RR_Header{Name: query.Question[0].Name, Rrtype: D.TypeA, Class: D.ClassINET, Ttl: test.ttl},
					A:   net.ParseIP("192.0.2.20"),
				}}
				message.Extra = []D.RR{&D.A{
					Hdr: D.RR_Header{Name: "extra.example.", Rrtype: D.TypeA, Class: D.ClassINET, Ttl: 600},
					A:   net.ParseIP("192.0.2.21"),
				}}
				return message, nil
			}}
			r := NewResolver(Options{TTLMin: 60 * time.Second, TTLMax: 120 * time.Second})
			r.cn = parseCNSet("203.0.113.0/24\n")
			r.swapUpstreams(&upstreams{china: failing(), trust: trust})
			if err := r.SetPolicy(Policy{Fallback: FallbackDirect}, t.TempDir()); err != nil {
				t.Fatal(err)
			}
			message := ask(t, r, "ttl.example", D.TypeA)
			if got := message.Answer[0].Header().Ttl; got != test.want {
				t.Fatalf("first answer TTL = %d, want %d", got, test.want)
			}
			if got := message.Extra[0].Header().Ttl; got > test.want {
				t.Fatalf("first additional TTL = %d, want at most %d", got, test.want)
			}
		})
	}
}

func TestTTLClampAppliesToSyntheticResponses(t *testing.T) {
	r := NewResolver(Options{TTLMin: time.Second, TTLMax: 10 * time.Second})
	r.cn = parseCNSet("203.0.113.0/24\n")
	r.swapUpstreams(&upstreams{china: failing(), trust: failing()})
	r.SetGateway(netip.MustParseAddr("198.51.100.1"))
	if err := r.SetPolicy(Policy{Fallback: FallbackGateway}, t.TempDir()); err != nil {
		t.Fatal(err)
	}

	gateway := ask(t, r, "gateway.example", D.TypeA)
	if got := gateway.Answer[0].Header().Ttl; got != 10 {
		t.Fatalf("synthetic gateway TTL = %d, want 10", got)
	}
	nodata := ask(t, r, "gateway.example", D.TypeAAAA)
	soa, ok := nodata.Ns[0].(*D.SOA)
	if !ok {
		t.Fatalf("synthetic NODATA authority = %T, want SOA", nodata.Ns[0])
	}
	if soa.Hdr.Ttl != 10 || soa.Minttl != 10 {
		t.Fatalf("synthetic NODATA TTL/MINIMUM = %d/%d, want 10/10", soa.Hdr.Ttl, soa.Minttl)
	}
}

func TestTTLMinimumDoesNotExtendAuthenticatedFreshness(t *testing.T) {
	trust := &fakePool{reply: func(query *D.Msg) (*D.Msg, error) {
		message := new(D.Msg)
		message.SetReply(query)
		message.AuthenticatedData = true
		message.Answer = []D.RR{
			&D.A{
				Hdr: D.RR_Header{Name: query.Question[0].Name, Rrtype: D.TypeA, Class: D.ClassINET, Ttl: 10},
				A:   net.ParseIP("192.0.2.30"),
			},
			&D.RRSIG{
				Hdr:         D.RR_Header{Name: query.Question[0].Name, Rrtype: D.TypeRRSIG, Class: D.ClassINET, Ttl: 10},
				TypeCovered: D.TypeA, OrigTtl: 10,
			},
		}
		return message, nil
	}}
	r := NewResolver(Options{TTLMin: 60 * time.Second, TTLMax: 120 * time.Second})
	r.cn = parseCNSet("203.0.113.0/24\n")
	r.swapUpstreams(&upstreams{china: failing(), trust: trust})
	if err := r.SetPolicy(Policy{Fallback: FallbackDirect}, t.TempDir()); err != nil {
		t.Fatal(err)
	}
	message := ask(t, r, "signed.example", D.TypeA)
	if !message.AuthenticatedData {
		t.Fatal("untouched authenticated response lost AD")
	}
	for _, rr := range message.Answer {
		if got := rr.Header().Ttl; got != 10 {
			t.Fatalf("authenticated %T TTL = %d, want original 10", rr, got)
		}
	}
}

func TestUnsignedNODATATTLMatchesCacheLifetime(t *testing.T) {
	trust := &fakePool{reply: func(query *D.Msg) (*D.Msg, error) {
		message := new(D.Msg)
		message.SetReply(query)
		message.Ns = []D.RR{&D.SOA{
			Hdr: D.RR_Header{Name: query.Question[0].Name, Rrtype: D.TypeSOA, Class: D.ClassINET, Ttl: 5},
			Ns:  "ns.example.", Mbox: "hostmaster.example.", Minttl: 5,
		}}
		return message, nil
	}}
	r := NewResolver(Options{TTLMin: 60 * time.Second, TTLMax: 120 * time.Second})
	r.cn = parseCNSet("203.0.113.0/24\n")
	r.swapUpstreams(&upstreams{china: failing(), trust: trust})
	if err := r.SetPolicy(Policy{Fallback: FallbackDirect}, t.TempDir()); err != nil {
		t.Fatal(err)
	}
	for attempt := 0; attempt < 2; attempt++ {
		message := ask(t, r, "nodata.example", D.TypeA)
		soa := message.Ns[0].(*D.SOA)
		if soa.Hdr.Ttl > 60 || soa.Minttl > 60 {
			t.Fatalf("attempt %d NODATA TTL/MINIMUM = %d/%d, want at most 60", attempt, soa.Hdr.Ttl, soa.Minttl)
		}
		if attempt == 0 && (soa.Hdr.Ttl != 60 || soa.Minttl != 60) {
			t.Fatalf("first NODATA TTL/MINIMUM = %d/%d, want 60/60", soa.Hdr.Ttl, soa.Minttl)
		}
	}
}

func TestGetStaleRejectsLiveEntry(t *testing.T) {
	cache := newCache(4)
	key := cacheKey{name: "live.example.", qtype: D.TypeA}
	message := new(D.Msg)
	message.SetQuestion(key.name, key.qtype)
	cache.put(key, message, time.Minute, cache.Epoch(), cacheMeta{})
	if _, _, ok := cache.getStaleGeneration(key, cache.Epoch()); ok {
		t.Fatal("a live cache entry was returned as stale")
	}
}
