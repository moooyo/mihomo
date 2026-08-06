package engine

import (
	"context"
	"errors"
	"net/netip"
	"sort"
	"testing"

	C "github.com/metacubex/mihomo/constant"
)

func engineWithTrafficConfig(t *testing.T, cfg Config) *Engine {
	t.Helper()
	runtime, err := compileScriptConfig(cfg)
	if err != nil {
		t.Fatalf("compile traffic config: %v", err)
	}
	cfg.runtime = runtime
	store := &configStore{}
	store.committed.Store(&CommittedConfigView{Config: cfg, Revision: "unchanged"})
	e := &Engine{config: store}
	e.certs = newCertificateStore(store)
	e.proxy = &interceptProxy{config: store}
	e.interceptor = NewInterceptor(e.proxy)
	e.interceptor.engine = e
	return e
}

func TestTrafficPolicyRoutingFollowsExecutionOrder(t *testing.T) {
	domain := "shared.example.com"
	a := Module{
		ID: "a", Enabled: true, CaptureHosts: []string{domain},
		RoutingRules: RoutingRules{{Action: "reject", Domain: &domain}},
	}
	b := Module{
		ID: "b", Enabled: true, CaptureHosts: []string{domain},
		RoutingRules: RoutingRules{{Action: "direct", Domain: &domain}},
	}
	metadata := &C.Metadata{Type: C.HTTP, NetWork: C.TCP, Host: domain, DstPort: 443}

	// Physical module order is deliberately the reverse of reviewed order.
	e := engineWithTrafficConfig(t, Config{
		MITM: MITMSettings{Enabled: true}, Modules: []Module{b, a},
		ExecutionOrder: []string{"a", "b"},
	})
	if got := e.RouteClient(metadata); got != C.ClientRouteReject {
		t.Fatalf("A-first route = %v, want REJECT", got)
	}

	e = engineWithTrafficConfig(t, Config{
		MITM: MITMSettings{Enabled: true}, Modules: []Module{b, a},
		ExecutionOrder: []string{"b", "a"},
	})
	if got := e.RouteClient(metadata); got != C.ClientRouteDirect {
		t.Fatalf("B-first route = %v, want DIRECT", got)
	}

	e = engineWithTrafficConfig(t, Config{
		MITM: MITMSettings{Enabled: false}, Modules: []Module{b, a},
		ExecutionOrder: []string{"a", "b"},
	})
	if got := e.RouteClient(metadata); got != C.ClientRouteNone {
		t.Fatalf("master-off route = %v, want no extension route", got)
	}

	metadata.Type = C.INNER
	if got := engineWithTrafficConfig(t, Config{
		MITM: MITMSettings{Enabled: true}, Modules: []Module{b, a},
		ExecutionOrder: []string{"a", "b"},
	}).RouteClient(metadata); got != C.ClientRouteNone {
		t.Fatalf("INNER route = %v, want no client routing", got)
	}
	metadata.Type = C.HTTP
	metadata.NetWork = C.UDP
	if got := engineWithTrafficConfig(t, Config{
		MITM: MITMSettings{Enabled: true}, Modules: []Module{b, a},
		ExecutionOrder: []string{"b", "a"},
	}).RouteClient(metadata); got != C.ClientRouteDirect {
		t.Fatalf("raw UDP/443 extension route = %v, want DIRECT before tunnel guard enforcement", got)
	}
}

func TestTrafficPolicyRoutingMatcherParity(t *testing.T) {
	anyKeywords := []string{"ads", "tracker"}
	allKeywords := []string{"prod"}
	tcp := "tcp"
	port8443 := 8443
	tests := []struct {
		name     string
		rule     RoutingRule
		metadata C.Metadata
		want     C.ClientRouteAction
	}{
		{
			name: "domain suffix apex", rule: RoutingRule{Action: "reject", DomainSuffix: trafficStringPointer("example.com")},
			metadata: C.Metadata{Type: C.HTTP, NetWork: C.TCP, Host: "example.com", DstPort: 443}, want: C.ClientRouteReject,
		},
		{
			name: "domain suffix child", rule: RoutingRule{Action: "reject", DomainSuffix: trafficStringPointer("example.com")},
			metadata: C.Metadata{Type: C.HTTP, NetWork: C.TCP, Host: "a.example.com", DstPort: 443}, want: C.ClientRouteReject,
		},
		{
			name: "domain suffix boundary", rule: RoutingRule{Action: "reject", DomainSuffix: trafficStringPointer("example.com")},
			metadata: C.Metadata{Type: C.HTTP, NetWork: C.TCP, Host: "notexample.com", DstPort: 443}, want: C.ClientRouteNone,
		},
		{
			name: "IPv4 CIDR", rule: RoutingRule{Action: "reject", IPCIDR: trafficStringPointer("203.0.113.0/24")},
			metadata: C.Metadata{Type: C.HTTP, NetWork: C.TCP, DstIP: netip.MustParseAddr("203.0.113.9"), DstPort: 443}, want: C.ClientRouteReject,
		},
		{
			name: "IPv6 CIDR", rule: RoutingRule{Action: "reject", IPCIDR: trafficStringPointer("2001:db8::/32")},
			metadata: C.Metadata{Type: C.HTTP, NetWork: C.TCP, DstIP: netip.MustParseAddr("2001:db8::9"), DstPort: 443}, want: C.ClientRouteReject,
		},
		{
			name: "CIDR no resolve", rule: RoutingRule{Action: "reject", IPCIDR: trafficStringPointer("203.0.113.0/24")},
			metadata: C.Metadata{Type: C.HTTP, NetWork: C.TCP, Host: "ip.example.com", DstPort: 443}, want: C.ClientRouteNone,
		},
		{
			name: "keyword any and all", rule: RoutingRule{Action: "reject", DomainSuffix: trafficStringPointer("example.com"), DomainKeywords: &anyKeywords, AllDomainKeywords: &allKeywords},
			metadata: C.Metadata{Type: C.HTTP, NetWork: C.TCP, Host: "prod-ads.example.com", DstPort: 443}, want: C.ClientRouteReject,
		},
		{
			name: "keyword all missing", rule: RoutingRule{Action: "reject", DomainSuffix: trafficStringPointer("example.com"), DomainKeywords: &anyKeywords, AllDomainKeywords: &allKeywords},
			metadata: C.Metadata{Type: C.HTTP, NetWork: C.TCP, Host: "ads.example.com", DstPort: 443}, want: C.ClientRouteNone,
		},
		{
			name: "network mismatch", rule: RoutingRule{Action: "reject", Domain: trafficStringPointer("api.example.com"), Network: &tcp},
			metadata: C.Metadata{Type: C.HTTP, NetWork: C.UDP, Host: "api.example.com", DstPort: 8443}, want: C.ClientRouteNone,
		},
		{
			name: "destination port", rule: RoutingRule{Action: "reject", Domain: trafficStringPointer("api.example.com"), DestinationPort: &port8443},
			metadata: C.Metadata{Type: C.HTTP, NetWork: C.TCP, Host: "api.example.com", DstPort: 8443}, want: C.ClientRouteReject,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			module := Module{ID: "a", Enabled: true, CaptureHosts: []string{"capture.example.net"}, RoutingRules: RoutingRules{test.rule}}
			e := engineWithTrafficConfig(t, Config{
				MITM: MITMSettings{Enabled: true}, Modules: []Module{module}, ExecutionOrder: []string{"a"},
			})
			if got := e.RouteClient(&test.metadata); got != test.want {
				t.Fatalf("route = %v, want %v", got, test.want)
			}
		})
	}

	first := RoutingRule{Action: "direct", Domain: trafficStringPointer("order.example.com")}
	second := RoutingRule{Action: "reject", Domain: trafficStringPointer("order.example.com")}
	e := engineWithTrafficConfig(t, Config{
		MITM:           MITMSettings{Enabled: true},
		Modules:        []Module{{ID: "a", Enabled: true, CaptureHosts: []string{"capture.example.net"}, RoutingRules: RoutingRules{first, second}}},
		ExecutionOrder: []string{"a"},
	})
	if got := e.RouteClient(&C.Metadata{Type: C.HTTP, NetWork: C.TCP, Host: "order.example.com", DstPort: 443}); got != C.ClientRouteDirect {
		t.Fatalf("module declaration order route = %v, want DIRECT", got)
	}
}

func trafficStringPointer(value string) *string { return &value }

func TestTrafficPolicySelectsBoundEgressAndFailsClosed(t *testing.T) {
	host := "shared.example.com"
	a := Module{ID: "a", Enabled: true, CaptureHosts: []string{host}, EgressGroup: "GroupA"}
	b := Module{ID: "b", Enabled: true, CaptureHosts: []string{host}, EgressGroup: "GroupB", Network: true}
	e := engineWithTrafficConfig(t, Config{
		MITM: MITMSettings{Enabled: true}, Modules: []Module{b, a},
		ExecutionOrder: []string{"a", "b"},
	})
	groups := map[string]bool{"GroupA": true, "GroupB": true}
	e.SetEgressGroupSource(func(name string) bool { return groups[name] }, nil)
	metadata := &C.Metadata{Type: C.INNER, NetWork: C.TCP, Host: host, DstPort: 443}

	group, err := e.SelectEgress(metadata, "", false)
	if err != nil || group != "GroupA" {
		t.Fatalf("A-first egress = %q, %v; want GroupA", group, err)
	}

	// An empty binding fails closed at the first matching extension and cannot
	// fall through to a later bound module.
	cfg, _ := e.config.Current()
	cfg.Modules[1].EgressGroup = ""
	e = engineWithTrafficConfig(t, cfg)
	e.SetEgressGroupSource(func(name string) bool { return groups[name] }, nil)
	group, err = e.SelectEgress(metadata, "", false)
	if !errors.Is(err, errEgressUnauthorized) || group != "" {
		t.Fatalf("empty first egress = %q, %v; want fail closed", group, err)
	}

	// Once the winning selected group vanishes, do not fall through to B.
	cfg.Modules[1].EgressGroup = "GroupA"
	e = engineWithTrafficConfig(t, cfg)
	e.SetEgressGroupSource(func(name string) bool { return groups[name] }, nil)
	delete(groups, "GroupA")
	if group, err = e.SelectEgress(metadata, "", false); err == nil || group != "" {
		t.Fatalf("removed GroupA resolved as %q, %v; want fail closed", group, err)
	}

	// A script request is bound to the module that owns that action, while an
	// unowned main request cannot borrow a broad network grant.
	arbitrary := &C.Metadata{Type: C.INNER, NetWork: C.TCP, Host: "outside.example.net", DstPort: 8443}
	group, err = e.SelectEgress(arbitrary, "b", true)
	if err != nil || group != "GroupB" {
		t.Fatalf("script-owner egress = %q, %v; want GroupB", group, err)
	}
	if group, err = e.SelectEgress(arbitrary, "", false); !errors.Is(err, errEgressUnauthorized) || group != "" {
		t.Fatalf("unowned broad target resolved as %q, %v", group, err)
	}
}

func TestSetEgressGroupAcceptsOnlyLiveNarrowCatalog(t *testing.T) {
	e := newTestEngine(t, twoExtensionDocument)
	groups := map[string]bool{"DIRECT": true, "Proxies": true}
	e.SetEgressGroupSource(func(name string) bool { return groups[name] }, func() []string { return []string{"Proxies", "DIRECT"} })
	if _, _, err := e.SetEgressGroup(e.Revision(), "second", "LeafNode"); err == nil {
		t.Fatal("SetEgressGroup accepted a proxy outside the live group catalog")
	}
	revision := e.Revision()
	if _, returned, err := e.SetEgressGroup(revision, "second", ""); err == nil || returned != revision || e.Revision() != revision {
		t.Fatalf("empty egress clear returned revision=%q err=%v current=%q", returned, err, e.Revision())
	}
	if _, _, err := e.SetEgressGroup(e.Revision(), "second", "Proxies"); err != nil {
		t.Fatalf("SetEgressGroup rejected a live group: %v", err)
	}
	if got := e.AvailableEgressGroups(); len(got) != 2 || got[0] != "DIRECT" || got[1] != "Proxies" {
		t.Fatalf("available egress groups = %v", got)
	}
}

func TestTrafficPolicyLiveGroupRemovalWithdrawsOnlyAffectedCapture(t *testing.T) {
	a := Module{
		ID: "a", Enabled: true, CaptureHosts: []string{"a.example.com"},
		EgressGroupRequired: true, EgressGroup: "GroupA",
	}
	b := Module{ID: "b", Enabled: true, CaptureHosts: []string{"b.example.com"}, EgressGroup: "GroupB"}
	e := engineWithTrafficConfig(t, Config{
		MITM: MITMSettings{Enabled: true}, Modules: []Module{a, b},
		ExecutionOrder: []string{"a", "b"},
	})
	groups := map[string]bool{"GroupA": true, "GroupB": true, "DIRECT": true}
	available := func() []string {
		out := make([]string, 0, len(groups))
		for name, present := range groups {
			if present {
				out = append(out, name)
			}
		}
		return out
	}
	e.SetEgressGroupSource(func(name string) bool { return groups[name] }, available)
	boundaryReady := true
	e.SetClientBoundarySource(func() bool { return boundaryReady })
	revision := e.Revision()

	assertReady := func(host string, ready bool) {
		t.Helper()
		binding, exists := e.CaptureFor(host)
		if !exists || binding.Ready != ready {
			t.Fatalf("CaptureFor(%s) = %+v, %v; ready want %v", host, binding, exists, ready)
		}
		if !binding.Claimed {
			t.Fatalf("CaptureFor(%s) withdrew the desired DNS/client claim while the master is on", host)
		}
		metadata := &C.Metadata{Type: C.HTTP, NetWork: C.TCP, Host: host, DstPort: 443}
		if got := e.interceptor.MatchTCP(metadata); !got {
			t.Fatalf("MatchTCP(%s) declined a claimed host while ready=%v", host, ready)
		}
	}

	assertReady("a.example.com", true)
	delete(groups, "GroupA")
	assertReady("a.example.com", false)
	assertReady("b.example.com", true)
	if got := e.RouteClient(&C.Metadata{Type: C.HTTP, NetWork: C.TCP, Host: "a.example.com", DstPort: 443}); got != C.ClientRouteReject {
		t.Fatalf("cached gateway flow after group removal = %v, want REJECT", got)
	}
	for _, metadata := range []*C.Metadata{
		{Type: C.HTTP, NetWork: C.TCP, Host: "a.example.com", DstPort: 8443},
		{Type: C.HTTP, NetWork: C.UDP, Host: "a.example.com", DstPort: 5060},
	} {
		if got := e.RouteClient(metadata); got != C.ClientRouteNone {
			t.Fatalf("non-capture %s/%d flow = %v, want ordinary routing", metadata.NetWork, metadata.DstPort, got)
		}
	}
	snapshot, err := e.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	if len(snapshot.ActiveCaptureHosts) != 1 || snapshot.ActiveCaptureHosts[0] != "b.example.com" {
		t.Fatalf("active hosts after removal = %v, want only b.example.com", snapshot.ActiveCaptureHosts)
	}
	if !sort.StringsAreSorted(snapshot.AvailableEgressGroups) || containsString(snapshot.AvailableEgressGroups, "GroupA") {
		t.Fatalf("available groups after removal = %v", snapshot.AvailableEgressGroups)
	}
	if e.Revision() != revision {
		t.Fatalf("live group loss changed document revision %q -> %q", revision, e.Revision())
	}

	groups["GroupA"] = true
	assertReady("a.example.com", true)
	snapshot, err = e.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	if len(snapshot.ActiveCaptureHosts) != 2 {
		t.Fatalf("active hosts after restore = %v, want both", snapshot.ActiveCaptureHosts)
	}

	boundaryReady = false
	assertReady("a.example.com", false)
	assertReady("b.example.com", false)
	if got := e.RouteClient(&C.Metadata{Type: C.HTTP, NetWork: C.TCP, Host: "b.example.com", DstPort: 443}); got != C.ClientRouteReject {
		t.Fatalf("capture-only flow after boundary loss = %v, want REJECT", got)
	}
	snapshot, err = e.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	if len(snapshot.ActiveCaptureHosts) != 0 || e.Revision() != revision {
		t.Fatalf("boundary loss active=%v revision=%q, want empty and unchanged", snapshot.ActiveCaptureHosts, e.Revision())
	}
	boundaryReady = true
	assertReady("a.example.com", true)
}

func TestCaptureReadinessRequiresOwnerAndBoundWinner(t *testing.T) {
	host := "shared.example.com"
	a := Module{ID: "a", Enabled: true, CaptureHosts: []string{host}}
	b := Module{ID: "b", Enabled: true, CaptureHosts: []string{host}, EgressGroup: "GroupB"}
	e := engineWithTrafficConfig(t, Config{
		MITM: MITMSettings{Enabled: true}, Modules: []Module{a, b}, ExecutionOrder: []string{"a", "b"},
	})
	groups := map[string]bool{}
	e.SetEgressGroupSource(func(name string) bool { return groups[name] }, nil)
	if binding, _ := e.CaptureFor(host); binding.Ready {
		t.Fatal("capture was ready while the bound-first egress winner was missing")
	}
	snapshot, err := e.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	if len(snapshot.ActiveCaptureHosts) != 0 {
		t.Fatalf("active hosts with missing bound winner = %v", snapshot.ActiveCaptureHosts)
	}

	groups["GroupB"] = true
	if binding, _ := e.CaptureFor(host); binding.Ready {
		t.Fatal("a later valid binding satisfied the first owner's empty egress")
	}

	a.EgressGroup = defaultExtensionEgressGroup
	groups[defaultExtensionEgressGroup] = true
	e = engineWithTrafficConfig(t, Config{
		MITM: MITMSettings{Enabled: true}, Modules: []Module{a, b}, ExecutionOrder: []string{"a", "b"},
	})
	e.SetEgressGroupSource(func(name string) bool { return groups[name] }, nil)
	if binding, _ := e.CaptureFor(host); !binding.Ready {
		t.Fatal("capture did not recover when the first owner's DIRECT binding became available")
	}
}

func TestEgressChangesRetireTransportProjection(t *testing.T) {
	a := Module{ID: "a", Enabled: true, CaptureHosts: []string{"shared.example.com"}, EgressGroup: "GroupA"}
	b := Module{ID: "b", Enabled: true, CaptureHosts: []string{"shared.example.com"}, EgressGroup: "GroupB"}
	cfg := Config{
		MITM: MITMSettings{Enabled: true}, Modules: []Module{a, b},
		ExecutionOrder: []string{"a", "b"},
	}
	first := newUpstreamTransportProjection(cfg).fingerprint
	cfg.Modules[0].EgressGroup = "GroupC"
	if changed := newUpstreamTransportProjection(cfg).fingerprint; changed == first {
		t.Fatal("egress group change did not retire the upstream transport projection")
	}
	cfg.Modules[0].EgressGroup = "GroupA"
	cfg.ExecutionOrder = []string{"b", "a"}
	if changed := newUpstreamTransportProjection(cfg).fingerprint; changed == first {
		t.Fatal("execution-order change did not retire the upstream transport projection")
	}

	cfg.Modules[0].Network = true
	projection := newUpstreamTransportProjection(cfg)
	if _, allowed := projection.targets.upstreamTarget("outside.example.net", "8443", ""); allowed {
		t.Fatal("an unowned main upstream borrowed a module network grant")
	}
	if target, allowed := projection.targets.upstreamTarget("outside.example.net", "8443", "a"); !allowed || target.Owner != "a" {
		t.Fatalf("owned network target = %+v, %v", target, allowed)
	}
}

func TestLiveGroupUpdateRetiresIdleUpstreamPool(t *testing.T) {
	proxy := &interceptProxy{}
	generation := newUpstreamTransportGeneration(Config{})
	proxy.upstream = generation
	e := &Engine{proxy: proxy}
	e.InvalidateEgressTransports()
	if proxy.upstream != nil || !generation.closed {
		t.Fatalf("group update left upstream generation attached=%v closed=%v", proxy.upstream != nil, generation.closed)
	}
}

func TestModuleNetworkTransportSeparatesLiveRebinding(t *testing.T) {
	requester := newModuleNetworkRequester(context.Background(), nil, make(chan struct{}, 1), "a")
	defer requester.Close()
	target := netTarget{Host: "outside.example.net", Port: 443, Owner: "a", OwnerOnly: true}
	a, err := requester.transport("https://outside.example.net", target, "GroupA")
	if err != nil {
		t.Fatal(err)
	}
	b, err := requester.transport("https://outside.example.net", target, "GroupB")
	if err != nil {
		t.Fatal(err)
	}
	if a == b {
		t.Fatal("module network requester reused GroupA transport after rebinding to GroupB")
	}
	if !a.DisableKeepAlives || !b.DisableKeepAlives {
		t.Fatal("module network requester retained connections across live group validation")
	}
}
