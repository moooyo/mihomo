package tunnel

import (
	"context"
	"net/netip"
	"testing"

	"github.com/metacubex/mihomo/common/utils"
	"github.com/metacubex/mihomo/component/resolver"
	"github.com/metacubex/mihomo/component/trie"
	C "github.com/metacubex/mihomo/constant"
	R "github.com/metacubex/mihomo/rules"
	"github.com/metacubex/mihomo/rules/wrapper"
)

type tunnelTestProxy struct {
	name  string
	type_ C.AdapterType
	udp   bool
}

func (p *tunnelTestProxy) Name() string               { return p.name }
func (*tunnelTestProxy) Addr() string                 { return "" }
func (p *tunnelTestProxy) Type() C.AdapterType        { return p.type_ }
func (p *tunnelTestProxy) SupportUDP() bool           { return p.udp }
func (*tunnelTestProxy) ProxyInfo() C.ProxyInfo       { return C.ProxyInfo{} }
func (*tunnelTestProxy) MarshalJSON() ([]byte, error) { return []byte(`{}`), nil }
func (*tunnelTestProxy) DialContext(context.Context, *C.Metadata) (C.Conn, error) {
	return nil, C.ErrNotSupport
}
func (*tunnelTestProxy) ListenPacketContext(context.Context, *C.Metadata) (C.PacketConn, error) {
	return nil, C.ErrNotSupport
}
func (*tunnelTestProxy) SupportUOT() bool                             { return false }
func (*tunnelTestProxy) IsL3Protocol(*C.Metadata) bool                { return false }
func (*tunnelTestProxy) Unwrap(*C.Metadata, bool) C.Proxy             { return nil }
func (*tunnelTestProxy) Close() error                                 { return nil }
func (p *tunnelTestProxy) Adapter() C.ProxyAdapter                    { return p }
func (*tunnelTestProxy) AliveForTestUrl(string) bool                  { return true }
func (*tunnelTestProxy) DelayHistory() []C.DelayHistory               { return nil }
func (*tunnelTestProxy) ExtraDelayHistories() map[string]C.ProxyState { return nil }
func (*tunnelTestProxy) LastDelayForTestUrl(string) uint16            { return 0 }
func (*tunnelTestProxy) URLTest(context.Context, string, utils.IntRanges[uint16]) (uint16, error) {
	return 0, nil
}

type tunnelTestTrafficPolicy struct {
	action C.ClientRouteAction
	calls  int
	host   string
}

type tunnelTestFakeMapper struct {
	prefix netip.Prefix
}

func (*tunnelTestFakeMapper) FakeIPEnabled() bool                    { return true }
func (*tunnelTestFakeMapper) MappingEnabled() bool                   { return true }
func (m *tunnelTestFakeMapper) IsFakeIP(address netip.Addr) bool     { return m.prefix.Contains(address) }
func (*tunnelTestFakeMapper) IsFakeBroadcastIP(netip.Addr) bool      { return false }
func (*tunnelTestFakeMapper) IsExistFakeIP(netip.Addr) bool          { return false }
func (*tunnelTestFakeMapper) FindHostByIP(netip.Addr) (string, bool) { return "", false }
func (*tunnelTestFakeMapper) FlushFakeIP() error                     { return nil }
func (*tunnelTestFakeMapper) InsertHostByIP(netip.Addr, string)      {}
func (*tunnelTestFakeMapper) StoreFakePoolState()                    {}

func (*tunnelTestTrafficPolicy) ClientPolicyActive() bool { return true }

func (p *tunnelTestTrafficPolicy) RouteClient(metadata *C.Metadata) C.ClientRouteAction {
	p.calls++
	if p.host != "" && metadata.RuleHost() != p.host {
		return C.ClientRouteNone
	}
	return p.action
}

func (*tunnelTestTrafficPolicy) SelectEgress(*C.Metadata, string, bool) (string, error) {
	return "", nil
}

func TestClientRouteProxyMapsTypedActionsAndPreservesEarlierBoundaries(t *testing.T) {
	defer SetTrafficPolicy(nil)
	metadata := &C.Metadata{Type: C.HTTP, NetWork: C.TCP, Host: "route.example.com", DstPort: 443}

	for _, test := range []struct {
		name   string
		action C.ClientRouteAction
		proxy  string
	}{
		{name: "direct", action: C.ClientRouteDirect, proxy: "DIRECT"},
		{name: "reject", action: C.ClientRouteReject, proxy: "REJECT"},
		{name: "invalid fails closed", action: C.ClientRouteAction(255), proxy: "REJECT"},
	} {
		t.Run(test.name, func(t *testing.T) {
			policy := &tunnelTestTrafficPolicy{action: test.action}
			SetTrafficPolicy(policy)
			proxy, routed := clientRouteProxyFor(metadata)
			if !routed || proxy != test.proxy || policy.calls != 1 {
				t.Fatalf("route = %q, %v; calls=%d", proxy, routed, policy.calls)
			}
		})
	}

	for _, test := range []struct {
		name     string
		metadata C.Metadata
	}{
		{name: "INNER", metadata: C.Metadata{Type: C.INNER, NetWork: C.TCP, Host: "route.example.com", DstPort: 443}},
		{name: "fixed UDP 443 guard", metadata: C.Metadata{Type: C.HTTP, NetWork: C.UDP, Host: "route.example.com", DstPort: 443}},
		{name: "existing special proxy", metadata: C.Metadata{Type: C.HTTP, NetWork: C.TCP, Host: "route.example.com", DstPort: 443, SpecialProxy: "Operator"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			policy := &tunnelTestTrafficPolicy{action: C.ClientRouteDirect}
			SetTrafficPolicy(policy)
			if proxy, routed := clientRouteProxyFor(&test.metadata); routed || proxy != "" || policy.calls != 0 {
				t.Fatalf("protected route = %q, %v; policy calls=%d", proxy, routed, policy.calls)
			}
		})
	}
	special := &C.Metadata{Type: C.HTTP, NetWork: C.TCP, Host: "route.example.com", DstPort: 443, SpecialProxy: "Operator"}
	SetTrafficPolicy(&tunnelTestTrafficPolicy{action: C.ClientRouteDirect})
	prefix, _, _, decided, err := prepareClientRouting(special)
	if err != nil || decided || prefix != nil || clientPrefixAllowsCapture(prefix) {
		t.Fatalf("special-proxy flow obtained capture permission: prefix=%v decided=%v err=%v", prefix != nil, decided, err)
	}
}

func TestFixedUDP443GuardPrecedesMatchSpecialRulesAndSpecialProxy(t *testing.T) {
	previousPolicy := trafficPolicy.Load()
	configMux.Lock()
	previousRules, previousSubRules, previousProxies, previousMode := rules, subRules, proxies, mode
	configMux.Unlock()
	defer func() {
		trafficPolicy.Store(previousPolicy)
		configMux.Lock()
		rules, subRules, proxies, mode = previousRules, previousSubRules, previousProxies, previousMode
		refreshFixedClientBoundaryLocked()
		routingConfigEpoch.Add(1)
		configMux.Unlock()
	}()

	parse := func(ruleType, payload, target string) C.Rule {
		t.Helper()
		rule, err := R.ParseRule(ruleType, payload, target, nil, nil)
		if err != nil {
			t.Fatalf("parse %s: %v", ruleType, err)
		}
		return rule
	}
	earlyMatch := parse("MATCH", "", "Proxies")
	guard := parse("AND", "((NETWORK,UDP),(DST-PORT,443))", "REJECT")
	subMatch := parse("MATCH", "", "DIRECT")
	reject := &tunnelTestProxy{name: "REJECT", type_: C.Reject, udp: true}

	configMux.Lock()
	rules = []C.Rule{earlyMatch, guard}
	subRules = map[string][]C.Rule{"bypass": {subMatch}}
	proxies = map[string]C.Proxy{
		"DIRECT":  &tunnelTestProxy{name: "DIRECT", type_: C.Direct, udp: true},
		"Proxies": &tunnelTestProxy{name: "Proxies", type_: C.Selector, udp: true},
		"REJECT":  reject,
	}
	mode = Rule
	refreshFixedClientBoundaryLocked()
	routingConfigEpoch.Add(1)
	configMux.Unlock()
	SetTrafficPolicy(nil)

	for _, test := range []struct {
		name         string
		specialRules string
		specialProxy string
	}{
		{name: "earlier MATCH"},
		{name: "SpecialRules", specialRules: "bypass"},
		{name: "SpecialProxy", specialProxy: "DIRECT"},
	} {
		t.Run(test.name, func(t *testing.T) {
			metadata := &C.Metadata{
				Type: C.HTTP, NetWork: C.UDP, Host: "h3.example.com", DstPort: 443,
				SpecialRules: test.specialRules, SpecialProxy: test.specialProxy,
			}
			proxy, rule, err := resolveMetadata(metadata)
			if err != nil || proxy != reject || rule != guard {
				t.Fatalf("UDP/443 resolved as proxy=%v rule=%v err=%v, want fixed REJECT", proxy, rule, err)
			}
		})
	}

	SetTrafficPolicy(&tunnelTestTrafficPolicy{action: C.ClientRouteNone})
	disabledGuard := wrapper.NewRuleWrapper(guard)
	disabledGuard.SetDisabled(true)
	for _, test := range []struct {
		name       string
		ruleSet    []C.Rule
		mode       TunnelMode
		withReject bool
		wantError  bool
	}{
		{name: "missing guard", ruleSet: []C.Rule{earlyMatch}, mode: Rule, withReject: true},
		{name: "disabled guard", ruleSet: []C.Rule{disabledGuard}, mode: Rule, withReject: true},
		{name: "non-rule mode", ruleSet: []C.Rule{guard}, mode: Global, withReject: true},
		{name: "missing REJECT adapter", ruleSet: []C.Rule{guard}, mode: Rule, wantError: true},
	} {
		t.Run("active policy "+test.name, func(t *testing.T) {
			configMux.Lock()
			rules = test.ruleSet
			mode = test.mode
			if test.withReject {
				proxies["REJECT"] = reject
			} else {
				delete(proxies, "REJECT")
			}
			refreshFixedClientBoundaryLocked()
			routingConfigEpoch.Add(1)
			configMux.Unlock()

			metadata := &C.Metadata{
				Type: C.HTTP, NetWork: C.UDP, Host: "h3.example.com", DstPort: 443,
				SpecialProxy: "DIRECT",
			}
			proxy, _, err := resolveMetadata(metadata)
			if test.wantError {
				if err == nil || proxy != nil {
					t.Fatalf("unavailable boundary resolved as proxy=%v err=%v, want failure", proxy, err)
				}
				return
			}
			if err != nil || proxy != reject {
				t.Fatalf("unavailable boundary resolved as proxy=%v err=%v, want REJECT", proxy, err)
			}
		})
	}

	// With interception policy withdrawn, a manually removed guard does not
	// seize ordinary operator UDP semantics. There is no datagram capture path
	// to revive, and product readiness remains false until the guard returns.
	SetTrafficPolicy(nil)
	configMux.Lock()
	rules = []C.Rule{earlyMatch}
	mode = Rule
	proxies["REJECT"] = reject
	refreshFixedClientBoundaryLocked()
	routingConfigEpoch.Add(1)
	configMux.Unlock()
	ordinary := &C.Metadata{
		Type: C.HTTP, NetWork: C.UDP, Host: "h3.example.com", DstPort: 443,
		SpecialProxy: "DIRECT",
	}
	if proxy, _, err := resolveMetadata(ordinary); err != nil || proxy == nil || proxy.Name() != "DIRECT" {
		t.Fatalf("inactive policy changed ordinary UDP routing: proxy=%v err=%v", proxy, err)
	}
}

func TestSpecialRulesUseDefaultProtectedPrefixAndCompleteSubruleRemainder(t *testing.T) {
	previousPolicy := trafficPolicy.Load()
	configMux.Lock()
	previousRules, previousSubRules, previousProxies, previousMode := rules, subRules, proxies, mode
	configMux.Unlock()
	defer func() {
		trafficPolicy.Store(previousPolicy)
		configMux.Lock()
		rules, subRules, proxies, mode = previousRules, previousSubRules, previousProxies, previousMode
		refreshFixedClientBoundaryLocked()
		routingConfigEpoch.Add(1)
		configMux.Unlock()
	}()

	parse := func(ruleType, payload, target string) C.Rule {
		t.Helper()
		rule, err := R.ParseRule(ruleType, payload, target, nil, nil)
		if err != nil {
			t.Fatalf("parse %s: %v", ruleType, err)
		}
		return rule
	}
	protected := parse("DOMAIN", "console.example.com", "REJECT")
	guard := parse("AND", "((NETWORK,UDP),(DST-PORT,443))", "REJECT")
	defaultFallback := parse("MATCH", "", "Proxies")
	subDirect := parse("MATCH", "", "DIRECT")
	reject := &tunnelTestProxy{name: "REJECT", type_: C.Reject, udp: true}
	direct := &tunnelTestProxy{name: "DIRECT", type_: C.Direct, udp: true}

	configMux.Lock()
	rules = []C.Rule{protected, guard, defaultFallback}
	subRules = map[string][]C.Rule{"selected": {subDirect}}
	proxies = map[string]C.Proxy{
		"DIRECT":  direct,
		"Proxies": &tunnelTestProxy{name: "Proxies", type_: C.Selector, udp: true},
		"REJECT":  reject,
	}
	mode = Rule
	refreshFixedClientBoundaryLocked()
	routingConfigEpoch.Add(1)
	configMux.Unlock()
	SetTrafficPolicy(&tunnelTestTrafficPolicy{action: C.ClientRouteNone})

	captured := &C.Metadata{
		Type: C.HTTP, NetWork: C.TCP, Host: "captured.example.com", DstPort: 443,
		SpecialRules: "selected",
	}
	prefix, selected, selectedRule, decided, err := prepareClientRouting(captured)
	if err != nil || decided || selected != nil || selectedRule != nil || !clientPrefixAllowsCapture(prefix) {
		t.Fatalf("selected subrule blocked capture: prefix=%v proxy=%v rule=%v decided=%v err=%v", prefix != nil, selected, selectedRule, decided, err)
	}
	proxy, rule, err := resolvePreparedClientRouting(captured, prefix, selected, selectedRule)
	if err != nil || proxy != direct || rule != subDirect {
		t.Fatalf("capture decline skipped selected subrule: proxy=%v rule=%v err=%v", proxy, rule, err)
	}

	management := &C.Metadata{
		Type: C.HTTP, NetWork: C.TCP, Host: "console.example.com", DstPort: 443,
		SpecialRules: "selected",
	}
	_, proxy, rule, decided, err = prepareClientRouting(management)
	if err != nil || !decided || proxy != reject || rule != protected {
		t.Fatalf("selected subrule bypassed protected prefix: proxy=%v rule=%v decided=%v err=%v", proxy, rule, decided, err)
	}
}

func TestClientRoutingRunsAfterFixedPrefixAndBeforeRemainder(t *testing.T) {
	previousPolicy := trafficPolicy.Load()
	previousInterceptor := interceptor.Load()
	configMux.Lock()
	previousRules, previousSubRules, previousProxies, previousMode := rules, subRules, proxies, mode
	configMux.Unlock()
	defer func() {
		trafficPolicy.Store(previousPolicy)
		interceptor.Store(previousInterceptor)
		configMux.Lock()
		rules, subRules, proxies, mode = previousRules, previousSubRules, previousProxies, previousMode
		refreshFixedClientBoundaryLocked()
		routingConfigEpoch.Add(1)
		configMux.Unlock()
	}()
	interceptor.Store(nil)

	parse := func(ruleType, payload, target string) C.Rule {
		t.Helper()
		rule, err := R.ParseRule(ruleType, payload, target, nil, nil)
		if err != nil {
			t.Fatalf("parse %s: %v", ruleType, err)
		}
		return rule
	}
	guard := parse("AND", "((NETWORK,UDP),(DST-PORT,443))", "REJECT")
	if !isFixedUDP443GuardShape(guard) {
		t.Fatalf("canonical guard payload %q was not recognized", guard.Payload())
	}
	earlyReject := parse("DOMAIN", "protected.example.com", "REJECT")
	lateReject := parse("DOMAIN", "late.example.com", "REJECT")

	configMux.Lock()
	rules = []C.Rule{earlyReject, guard, lateReject}
	subRules = nil
	proxies = map[string]C.Proxy{
		"DIRECT": &tunnelTestProxy{name: "DIRECT", type_: C.Direct, udp: true},
		"REJECT": &tunnelTestProxy{name: "REJECT", type_: C.Reject, udp: true},
	}
	mode = Rule
	refreshFixedClientBoundaryLocked()
	routingConfigEpoch.Add(1)
	configMux.Unlock()
	SetTrafficPolicy(&tunnelTestTrafficPolicy{action: C.ClientRouteDirect, host: "late.example.com"})

	early := &C.Metadata{Type: C.HTTP, NetWork: C.TCP, Host: "protected.example.com", DstPort: 443}
	prefix, selected, selectedRule, decided, err := prepareClientRouting(early)
	if err != nil || !decided || selected == nil || selected.Name() != "REJECT" || selectedRule != earlyReject {
		t.Fatalf("early prefix decision = prefix:%v proxy:%v rule:%v decided:%v err:%v", prefix != nil, selected, selectedRule, decided, err)
	}

	late := &C.Metadata{Type: C.HTTP, NetWork: C.TCP, Host: "late.example.com", DstPort: 443}
	prefix, selected, selectedRule, decided, err = prepareClientRouting(late)
	if err != nil || !decided || selected != nil || late.SpecialProxy != "DIRECT" {
		t.Fatalf("extension decision before remainder = prefix:%v proxy:%v rule:%v decided:%v special:%q err:%v", prefix != nil, selected, selectedRule, decided, late.SpecialProxy, err)
	}
	resolved, _, err := resolvePreparedClientRouting(late, prefix, selected, selectedRule)
	if err != nil || resolved == nil || resolved.Name() != "DIRECT" {
		t.Fatalf("extension DIRECT resolved as %v, %v", resolved, err)
	}
	stale := &C.Metadata{Type: C.HTTP, NetWork: C.TCP, Host: "late.example.com", DstPort: 443}
	stalePrefix, staleProxy, staleRule, _, err := prepareClientRouting(stale)
	if err != nil {
		t.Fatal(err)
	}
	SetMode(Global)
	resolved, _, err = resolvePreparedClientRouting(stale, stalePrefix, staleProxy, staleRule)
	SetMode(Rule)
	if err != nil || resolved == nil || resolved.Name() != "REJECT" {
		t.Fatalf("stale prefix after mode change resolved as %v, %v", resolved, err)
	}

	udp := &C.Metadata{Type: C.HTTP, NetWork: C.UDP, Host: "late.example.com", DstPort: 443}
	_, selected, _, decided, err = prepareClientRouting(udp)
	if err != nil || !decided || selected == nil || selected.Name() != "REJECT" {
		t.Fatalf("fixed UDP/443 decision proxy=%v decided=%v err=%v", selected, decided, err)
	}

	configMux.Lock()
	rules = []C.Rule{earlyReject, lateReject}
	refreshFixedClientBoundaryLocked()
	routingConfigEpoch.Add(1)
	configMux.Unlock()
	claimedWithoutGuard := &C.Metadata{Type: C.HTTP, NetWork: C.TCP, Host: "late.example.com", DstPort: 443}
	if _, _, _, decided, err = prepareClientRouting(claimedWithoutGuard); err == nil || !decided {
		t.Fatalf("missing fixed guard did not fail closed: decided=%v err=%v", decided, err)
	}
	unrelated := &C.Metadata{Type: C.HTTP, NetWork: C.TCP, Host: "ordinary.example.com", DstPort: 443}
	if prefix, _, _, decided, err = prepareClientRouting(unrelated); err != nil || decided || prefix != nil {
		t.Fatalf("unrelated flow was rejected for missing guard: prefix=%v decided=%v err=%v", prefix != nil, decided, err)
	}

	disabledGuard := wrapper.NewRuleWrapper(guard)
	disabledGuard.SetDisabled(true)
	configMux.Lock()
	rules = []C.Rule{guard, disabledGuard}
	refreshFixedClientBoundaryLocked()
	routingConfigEpoch.Add(1)
	configMux.Unlock()
	claimedWithDuplicate := &C.Metadata{Type: C.HTTP, NetWork: C.TCP, Host: "late.example.com", DstPort: 443}
	if _, _, _, decided, err = prepareClientRouting(claimedWithDuplicate); err == nil || !decided {
		t.Fatalf("duplicate/disabled fixed guard did not fail closed: decided=%v err=%v", decided, err)
	}
}

func TestExtensionEgressCarrierIsCanonicalAndReserved(t *testing.T) {
	binding := "Group / β:%[]{}"
	metadata, err := newExtensionEgressMetadata("origin.example.com:443", binding)
	if err != nil {
		t.Fatal(err)
	}
	decoded, present, err := decodeExtensionEgressCarrier(metadata)
	if err != nil || !present || decoded != binding || metadata.Type != C.INNER || metadata.NetWork != C.TCP || metadata.SpecialProxy != "" {
		t.Fatalf("carrier decoded=%q present=%v metadata=%+v err=%v", decoded, present, metadata, err)
	}
	ordinary := metadata.Clone()
	ordinary.SpecialRules = "ordinary-provider"
	if decoded, present, err = decodeExtensionEgressCarrier(ordinary); err != nil || present || decoded != "" {
		t.Fatalf("ordinary SpecialRules decoded=%q present=%v err=%v", decoded, present, err)
	}
	forged := metadata.Clone()
	forged.Type = C.HTTP
	if proxy, rule, err := resolveMetadata(forged); err == nil || proxy != nil || rule != nil {
		t.Fatalf("non-INNER carrier was not refused: proxy=%v rule=%v err=%v", proxy, rule, err)
	}
	forced := metadata.Clone()
	forced.SpecialProxy = "DIRECT"
	if proxy, rule, err := resolveMetadata(forced); err == nil || proxy != nil || rule != nil {
		t.Fatalf("carrier with SpecialProxy was not refused: proxy=%v rule=%v err=%v", proxy, rule, err)
	}
	malformed := metadata.Clone()
	malformed.SpecialRules = extensionEgressSpecialRulesPrefix + "***"
	if proxy, rule, err := resolveMetadata(malformed); err == nil || proxy != nil || rule != nil {
		t.Fatalf("malformed carrier was not refused: proxy=%v rule=%v err=%v", proxy, rule, err)
	}
	unknownVersion := metadata.Clone()
	unknownVersion.SpecialRules = extensionEgressSpecialRulesRoot + "v2:Zm9v"
	if proxy, rule, err := resolveMetadata(unknownVersion); err == nil || proxy != nil || rule != nil {
		t.Fatalf("unknown carrier version was not refused: proxy=%v rule=%v err=%v", proxy, rule, err)
	}
	if _, err := encodeExtensionEgressCarrier(""); err == nil {
		t.Fatal("empty extension egress binding was encoded")
	}
	if _, err := newExtensionEgressMetadata("origin.example.com:notaport", binding); err == nil {
		t.Fatal("extension egress accepted a zero destination port")
	}
}

func TestExtensionEgressAddressPolicyFailsClosedAndRejectsFakeIP(t *testing.T) {
	previousPolicy := extensionEgressAddressPolicy.Load()
	previousMapper := resolver.DefaultHostMapper
	defer func() {
		extensionEgressAddressPolicy.Store(previousPolicy)
		resolver.DefaultHostMapper = previousMapper
	}()
	SetExtensionEgressAddressPolicy(nil)
	if extensionEgressAddressAllowed(netip.MustParseAddr("8.8.8.8")) {
		t.Fatal("extension egress address was accepted without an injected policy")
	}
	SetExtensionEgressAddressPolicy(func(address netip.Addr) bool {
		return address == netip.MustParseAddr("8.8.8.8")
	})
	if !extensionEgressAddressAllowed(netip.MustParseAddr("8.8.8.8")) {
		t.Fatal("injected policy did not allow its public fixture")
	}
	if extensionEgressAddressAllowed(netip.MustParseAddr("198.18.0.1")) {
		t.Fatal("injected policy refusal was ignored for a special-purpose address")
	}
	resolver.DefaultHostMapper = &tunnelTestFakeMapper{prefix: netip.MustParsePrefix("8.8.8.0/24")}
	if extensionEgressAddressAllowed(netip.MustParseAddr("8.8.8.8")) {
		t.Fatal("configured fake IP range was accepted as extension egress")
	}
}

func TestExtensionEgressRunsSafetyPrefixAndPinsPublicTargets(t *testing.T) {
	previousAddressPolicy := extensionEgressAddressPolicy.Load()
	previousGatewaySource := managedGatewaySource.Load()
	SetExtensionEgressAddressPolicy(func(address netip.Addr) bool {
		switch address.String() {
		case "1.1.1.1", "8.8.4.4", "8.8.8.8", "9.9.9.9":
			return true
		default:
			return false
		}
	})
	configMux.Lock()
	previousRules, previousSubRules, previousProxies, previousMode := rules, subRules, proxies, mode
	configMux.Unlock()
	previousHosts := resolver.DefaultHosts
	defer func() {
		extensionEgressAddressPolicy.Store(previousAddressPolicy)
		managedGatewaySource.Store(previousGatewaySource)
		resolver.DefaultHosts = previousHosts
		configMux.Lock()
		rules, subRules, proxies, mode = previousRules, previousSubRules, previousProxies, previousMode
		refreshFixedClientBoundaryLocked()
		routingConfigEpoch.Add(1)
		configMux.Unlock()
	}()

	parse := func(ruleType, payload, target string, params ...string) C.Rule {
		t.Helper()
		rule, err := R.ParseRule(ruleType, payload, target, params, nil)
		if err != nil {
			t.Fatalf("parse %s: %v", ruleType, err)
		}
		return rule
	}
	panelAllow := parse("AND", "((NOT,((IN-TYPE,INNER))),(DOMAIN,console.example.com))", "DIRECT")
	consoleReject := parse("DOMAIN", "console.example.com", "REJECT")
	privateReject := parse("IP-CIDR", "10.0.0.0/8", "REJECT", "no-resolve")
	explicitReject := parse("DOMAIN", "blocked.example.com", "REJECT")
	ordinarySpecialReject := parse("DOMAIN", "special.example.com", "REJECT")
	dropReject := parse("DOMAIN", "drop.example.com", "REJECT-DROP")
	prefixRoute := parse("DOMAIN", "prefix.example.com", "Proxies")
	guard := parse("AND", "((NETWORK,UDP),(DST-PORT,443))", "REJECT")
	fallback := parse("MATCH", "", "Proxies")

	hosts := trie.New[resolver.HostValue]()
	insertHost := func(host string, addresses ...string) {
		t.Helper()
		parsed := make([]netip.Addr, 0, len(addresses))
		for _, address := range addresses {
			parsed = append(parsed, netip.MustParseAddr(address))
		}
		value, err := resolver.NewHostValueByIPs(parsed)
		if err != nil {
			t.Fatal(err)
		}
		if err := hosts.Insert(host, value); err != nil {
			t.Fatal(err)
		}
	}
	insertHost("console.example.com", "127.0.0.1")
	insertHost("private.example.com", "10.1.2.3")
	insertHost("public.example.com", "8.8.8.8")
	insertHost("gateway.example.com", "9.9.9.9")
	insertHost("mixed-gateway.example.com", "1.1.1.1", "9.9.9.9")
	insertHost("blocked.example.com", "8.8.4.4")
	insertHost("special.example.com", "8.8.4.4")
	insertHost("drop.example.com", "127.0.0.2")
	insertHost("prefix.example.com", "1.1.1.1")
	insertHost("metadata.example.com", "169.254.169.254")
	insertHost("mixed.example.com", "8.8.8.8", "10.9.8.7")
	insertHost("benchmark.example.com", "198.18.0.1")
	insertHost("documentation-v6.example.com", "2001:db8::1")
	insertHost("mapped-v4.example.com", "::ffff:8.8.8.8")
	alias, err := resolver.NewHostValueByDomain("public.example.com")
	if err != nil {
		t.Fatal(err)
	}
	if err := hosts.Insert("alias.example.com", alias); err != nil {
		t.Fatal(err)
	}
	hosts.Optimize()
	resolver.DefaultHosts = resolver.NewHosts(hosts)

	configMux.Lock()
	rules = []C.Rule{panelAllow, consoleReject, privateReject, explicitReject, dropReject, prefixRoute, guard, fallback}
	subRules = map[string][]C.Rule{"ordinary-provider": {ordinarySpecialReject}}
	proxies = map[string]C.Proxy{
		"DIRECT":      &tunnelTestProxy{name: "DIRECT", type_: C.Direct, udp: true},
		"REJECT":      &tunnelTestProxy{name: "REJECT", type_: C.Reject, udp: true},
		"REJECT-DROP": &tunnelTestProxy{name: "REJECT-DROP", type_: C.RejectDrop, udp: true},
		"GroupA":      &tunnelTestProxy{name: "GroupA", type_: C.Selector, udp: true},
		"Proxies":     &tunnelTestProxy{name: "Proxies", type_: C.Selector, udp: true},
	}
	mode = Rule
	refreshFixedClientBoundaryLocked()
	routingConfigEpoch.Add(1)
	configMux.Unlock()
	SetManagedGatewaySource(func() netip.Addr { return netip.MustParseAddr("9.9.9.9") })

	carrier := func(binding string) string {
		t.Helper()
		value, err := encodeExtensionEgressCarrier(binding)
		if err != nil {
			t.Fatal(err)
		}
		return value
	}
	resolve := func(host string) (*C.Metadata, C.Proxy, C.Rule, error) {
		metadata := &C.Metadata{
			Type: C.INNER, NetWork: C.TCP, Host: host, DstPort: 443,
			SpecialRules: carrier("GroupA"),
		}
		proxy, rule, err := resolveMetadata(metadata)
		return metadata, proxy, rule, err
	}

	console, proxy, rule, err := resolve("console.example.com")
	if err != nil || proxy == nil || proxy.Name() != "REJECT" || rule != consoleReject || console.DstIP.String() != "127.0.0.1" {
		t.Fatalf("console egress = proxy:%v rule:%v ip:%s err:%v", proxy, rule, console.DstIP, err)
	}

	private, proxy, rule, err := resolve("private.example.com")
	if err != nil || proxy == nil || proxy.Name() != "REJECT" || rule != privateReject || private.DstIP.String() != "10.1.2.3" {
		t.Fatalf("private egress = proxy:%v rule:%v ip:%s err:%v", proxy, rule, private.DstIP, err)
	}

	public, proxy, rule, err := resolve("public.example.com")
	if err != nil || proxy == nil || proxy.Name() != "GroupA" || rule != nil || public.Host != "public.example.com" || public.DstIP.String() != "8.8.8.8" {
		t.Fatalf("public egress = proxy:%v rule:%v host:%q ip:%s err:%v", proxy, rule, public.Host, public.DstIP, err)
	}
	pinned := extensionEgressDialMetadata(public)
	if pinned == public || pinned.Host != "" || pinned.DstIP != public.DstIP || pinned.SpecialRules != "" || public.Host != "public.example.com" || public.SpecialRules != "" {
		t.Fatalf("pinned egress metadata = same:%v host:%q ip:%s rules:%q; original host:%q rules:%q", pinned == public, pinned.Host, pinned.DstIP, pinned.SpecialRules, public.Host, public.SpecialRules)
	}
	aliasMetadata := &C.Metadata{
		Type: C.INNER, NetWork: C.TCP, Host: "alias.example.com", DstPort: 443,
		SpecialRules: carrier("GroupA"),
	}
	if err := preHandleMetadata(aliasMetadata); err != nil || aliasMetadata.Host != "alias.example.com" {
		t.Fatalf("extension alias target was rewritten before safety: host:%q err:%v", aliasMetadata.Host, err)
	}
	proxy, rule, err = resolveMetadata(aliasMetadata)
	if err != nil || proxy == nil || proxy.Name() != "GroupA" || rule != nil || aliasMetadata.Host != "public.example.com" || aliasMetadata.DstIP.String() != "8.8.8.8" {
		t.Fatalf("alias egress = proxy:%v rule:%v host:%q ip:%s err:%v", proxy, rule, aliasMetadata.Host, aliasMetadata.DstIP, err)
	}
	direct := &C.Metadata{
		Type: C.INNER, NetWork: C.TCP, Host: "public.example.com", DstPort: 443,
		SpecialRules: carrier("DIRECT"),
	}
	proxy, rule, err = resolveMetadata(direct)
	if err != nil || proxy == nil || proxy.Name() != "DIRECT" || rule != nil {
		t.Fatalf("public DIRECT egress = proxy:%v rule:%v err:%v", proxy, rule, err)
	}
	ordinarySpecial := &C.Metadata{
		Type: C.HTTP, NetWork: C.TCP, Host: "special.example.com", DstPort: 443,
		SpecialRules: "ordinary-provider",
	}
	proxy, rule, err = resolveMetadata(ordinarySpecial)
	if err != nil || proxy == nil || proxy.Name() != "REJECT" || rule != ordinarySpecialReject {
		t.Fatalf("ordinary SpecialRules changed: proxy:%v rule:%v err:%v", proxy, rule, err)
	}
	udp := &C.Metadata{
		Type: C.INNER, NetWork: C.UDP, Host: "public.example.com", DstPort: 443,
		SpecialRules: carrier("GroupA"),
	}
	if proxy, rule, err = resolveMetadata(udp); err == nil || proxy != nil || rule != nil {
		t.Fatalf("UDP extension egress = proxy:%v rule:%v err:%v, want TCP-only refusal", proxy, rule, err)
	}
	if err := Tunnel.AuthorizeExtensionEgress(&C.Metadata{
		Type: C.INNER, NetWork: C.TCP, Host: "public.example.com", DstPort: 443,
	}, "GroupA"); err != nil {
		t.Fatalf("pooled public egress preflight failed: %v", err)
	}
	gateway, proxy, rule, err := resolve("gateway.example.com")
	if err != nil || proxy == nil || proxy.Name() != "REJECT" || rule != nil || gateway.DstIP.String() != "9.9.9.9" {
		t.Fatalf("gateway egress = proxy:%v rule:%v ip:%s err:%v", proxy, rule, gateway.DstIP, err)
	}
	if err := Tunnel.AuthorizeExtensionEgress(&C.Metadata{
		Type: C.INNER, NetWork: C.TCP, Host: "gateway.example.com", DstPort: 443,
	}, "GroupA"); err == nil {
		t.Fatal("pooled egress preflight accepted the managed gateway")
	}
	if mixedGateway, mixedProxy, mixedRule, mixedErr := resolve("mixed-gateway.example.com"); mixedErr != nil || mixedProxy == nil || mixedProxy.Name() != "REJECT" || mixedRule != nil || !mixedGateway.DstIP.IsValid() {
		t.Fatalf("mixed gateway egress = proxy:%v rule:%v ip:%s err:%v", mixedProxy, mixedRule, mixedGateway.DstIP, mixedErr)
	}
	if err := Tunnel.AuthorizeExtensionEgress(&C.Metadata{
		Type: C.INNER, NetWork: C.TCP, Host: "mixed-gateway.example.com", DstPort: 443,
	}, "GroupA"); err == nil {
		t.Fatal("pooled egress preflight accepted a mixed gateway answer")
	}

	_, proxy, rule, err = resolve("blocked.example.com")
	if err != nil || proxy == nil || proxy.Name() != "REJECT" || rule != explicitReject {
		t.Fatalf("explicit REJECT egress = proxy:%v rule:%v err:%v", proxy, rule, err)
	}
	if err := Tunnel.AuthorizeExtensionEgress(&C.Metadata{
		Type: C.INNER, NetWork: C.TCP, Host: "blocked.example.com", DstPort: 443,
	}, "GroupA"); err == nil {
		t.Fatal("pooled egress preflight ignored operator REJECT")
	}
	_, proxy, rule, err = resolve("drop.example.com")
	if err != nil || proxy == nil || proxy.Name() != "REJECT-DROP" || rule != dropReject {
		t.Fatalf("REJECT-DROP egress = proxy:%v rule:%v err:%v", proxy, rule, err)
	}

	_, proxy, rule, err = resolve("prefix.example.com")
	if err == nil || proxy != nil || rule != nil {
		t.Fatalf("ambiguous operator prefix was not refused: proxy:%v rule:%v err:%v", proxy, rule, err)
	}

	_, proxy, rule, err = resolve("metadata.example.com")
	if err == nil || proxy != nil || rule != nil {
		t.Fatalf("metadata endpoint was not refused: proxy:%v rule:%v err:%v", proxy, rule, err)
	}
	_, proxy, rule, err = resolve("mixed.example.com")
	if err == nil || proxy != nil || rule != nil {
		t.Fatalf("mixed public/private DNS answer was not refused: proxy:%v rule:%v err:%v", proxy, rule, err)
	}
	for _, host := range []string{"benchmark.example.com", "documentation-v6.example.com", "mapped-v4.example.com"} {
		if _, proxy, rule, err = resolve(host); err == nil || proxy != nil || rule != nil {
			t.Fatalf("special-purpose target %s was not refused: proxy:%v rule:%v err:%v", host, proxy, rule, err)
		}
	}
}

func TestManagedGatewayAntiLoopIsScopedToFiveGPNEgress(t *testing.T) {
	previousGatewaySource := managedGatewaySource.Load()
	previousHosts := resolver.DefaultHosts
	configMux.Lock()
	previousRules, previousSubRules, previousProxies, previousMode := rules, subRules, proxies, mode
	configMux.Unlock()
	defer func() {
		managedGatewaySource.Store(previousGatewaySource)
		resolver.DefaultHosts = previousHosts
		configMux.Lock()
		rules, subRules, proxies, mode = previousRules, previousSubRules, previousProxies, previousMode
		refreshFixedClientBoundaryLocked()
		routingConfigEpoch.Add(1)
		configMux.Unlock()
	}()

	parse := func(ruleType, payload, target string, params ...string) C.Rule {
		t.Helper()
		rule, err := R.ParseRule(ruleType, payload, target, params, nil)
		if err != nil {
			t.Fatalf("parse %s: %v", ruleType, err)
		}
		return rule
	}
	operatorReject := parse("DOMAIN", "blocked.example.com", "REJECT")
	operatorDirect := parse("DOMAIN", "gateway.example.com", "DIRECT")
	guard := parse("AND", "((NETWORK,UDP),(DST-PORT,443))", "REJECT")
	fallback := parse("MATCH", "", "Proxies")

	hosts := trie.New[resolver.HostValue]()
	insertHost := func(host string, addresses ...string) {
		t.Helper()
		parsed := make([]netip.Addr, 0, len(addresses))
		for _, address := range addresses {
			parsed = append(parsed, netip.MustParseAddr(address))
		}
		value, err := resolver.NewHostValueByIPs(parsed)
		if err != nil {
			t.Fatal(err)
		}
		if err := hosts.Insert(host, value); err != nil {
			t.Fatal(err)
		}
	}
	insertHost("gateway.example.com", "8.8.8.8")
	insertHost("blocked.example.com", "8.8.8.8")
	insertHost("public.example.com", "1.1.1.1")
	insertHost("mixed.example.com", "1.1.1.1", "8.8.8.8")
	insertHost("swap.example.com", "9.9.9.9")
	hosts.Optimize()
	resolver.DefaultHosts = resolver.NewHosts(hosts)

	configMux.Lock()
	rules = []C.Rule{operatorReject, operatorDirect, guard, fallback}
	subRules = map[string][]C.Rule{}
	proxies = map[string]C.Proxy{
		"DIRECT":  &tunnelTestProxy{name: "DIRECT", type_: C.Direct, udp: true},
		"GLOBAL":  &tunnelTestProxy{name: "GLOBAL", type_: C.Selector, udp: true},
		"REJECT":  &tunnelTestProxy{name: "REJECT", type_: C.Reject, udp: true},
		"Proxies": &tunnelTestProxy{name: "Proxies", type_: C.Selector, udp: true},
	}
	mode = Rule
	refreshFixedClientBoundaryLocked()
	routingConfigEpoch.Add(1)
	configMux.Unlock()
	gatewayAddress := netip.MustParseAddr("8.8.8.8")
	SetManagedGatewaySource(func() netip.Addr { return gatewayAddress })

	managed := &C.Metadata{
		Type: C.INNER, NetWork: C.TCP, Host: "gateway.example.com", DstPort: 443,
		SpecialRules: managedSystemEgressRulesV1,
	}
	proxy, rule, err := resolveMetadata(managed)
	if err != nil || proxy == nil || proxy.Name() != "REJECT" || rule != nil || managed.DstIP.String() != "8.8.8.8" {
		t.Fatalf("managed gateway route = proxy:%v rule:%v ip:%s err:%v", proxy, rule, managed.DstIP, err)
	}

	blocked := &C.Metadata{
		Type: C.INNER, NetWork: C.TCP, Host: "blocked.example.com", DstPort: 443,
		SpecialRules: managedSystemEgressRulesV1,
	}
	proxy, rule, err = resolveMetadata(blocked)
	if err != nil || proxy == nil || proxy.Name() != "REJECT" || rule != operatorReject {
		t.Fatalf("operator reject precedence = proxy:%v rule:%v err:%v", proxy, rule, err)
	}
	mixed := &C.Metadata{
		Type: C.INNER, NetWork: C.TCP, Host: "mixed.example.com", DstPort: 443,
		SpecialRules: managedSystemEgressRulesV1,
	}
	proxy, rule, err = resolveMetadata(mixed)
	if err != nil || proxy == nil || proxy.Name() != "REJECT" || rule != nil {
		t.Fatalf("mixed gateway route = proxy:%v rule:%v err:%v", proxy, rule, err)
	}

	func() {
		originalHosts := resolver.DefaultHosts
		defer func() { resolver.DefaultHosts = originalHosts }()
		swappedTrie := trie.New[resolver.HostValue]()
		swappedValue, swapErr := resolver.NewHostValueByIPs([]netip.Addr{netip.MustParseAddr("8.8.8.8")})
		if swapErr != nil {
			t.Fatal(swapErr)
		}
		if swapErr := swappedTrie.Insert("swap.example.com", swappedValue); swapErr != nil {
			t.Fatal(swapErr)
		}
		swappedTrie.Optimize()
		swappedHosts := resolver.NewHosts(swappedTrie)

		pinnedReject := parse("IP-CIDR", "9.9.9.9/32", "REJECT", "no-resolve")
		configMux.Lock()
		rules = []C.Rule{operatorReject, operatorDirect, pinnedReject, guard, fallback}
		refreshFixedClientBoundaryLocked()
		routingConfigEpoch.Add(1)
		configMux.Unlock()
		defer func() {
			configMux.Lock()
			rules = []C.Rule{operatorReject, operatorDirect, guard, fallback}
			refreshFixedClientBoundaryLocked()
			routingConfigEpoch.Add(1)
			configMux.Unlock()
		}()

		swapMetadata := &C.Metadata{
			Type: C.INNER, NetWork: C.TCP, Host: "swap.example.com", DstPort: 443,
			SpecialRules: managedSystemEgressRulesV1,
		}
		routeStartedUnresolved := false
		routeKeptDomain := false
		swapRoute := func(audited *C.Metadata) (C.Proxy, C.Rule, error) {
			resolver.DefaultHosts = swappedHosts
			routeMetadata := managedSystemEgressRouteMetadata(audited)
			routeStartedUnresolved = !routeMetadata.DstIP.IsValid()
			routeKeptDomain = routeMetadata.RuleHost() == "swap.example.com"
			return resolveOrdinaryMetadata(routeMetadata)
		}
		proxy, rule, err = resolveManagedSystemEgressWithRoute(swapMetadata, swapRoute)
		if err != nil || proxy == nil || proxy.Name() != "Proxies" || rule != fallback {
			t.Fatalf("hosts-swap route = proxy:%v rule:%v err:%v", proxy, rule, err)
		}
		if !routeStartedUnresolved || !routeKeptDomain {
			t.Fatalf("route clone started unresolved=%v kept-domain=%v", routeStartedUnresolved, routeKeptDomain)
		}
		if swapMetadata.DstIP.String() != "9.9.9.9" || swapMetadata.Host != "swap.example.com" || swapMetadata.SpecialRules != managedSystemEgressRulesV1 {
			t.Fatalf("audited metadata changed after hosts swap: host:%q ip:%s rules:%q", swapMetadata.Host, swapMetadata.DstIP, swapMetadata.SpecialRules)
		}
		dialMetadata := managedSystemEgressDialMetadata(swapMetadata)
		if dialMetadata.Host != "" || dialMetadata.DstIP.String() != "9.9.9.9" || dialMetadata.SpecialRules != "" {
			t.Fatalf("hosts-swap dial metadata = host:%q ip:%s rules:%q", dialMetadata.Host, dialMetadata.DstIP, dialMetadata.SpecialRules)
		}
	}()

	public := &C.Metadata{
		Type: C.INNER, NetWork: C.TCP, Host: "public.example.com", DstPort: 443,
		SpecialRules: managedSystemEgressRulesV1,
	}
	proxy, rule, err = resolveMetadata(public)
	if err != nil || proxy == nil || proxy.Name() != "Proxies" || rule != fallback || public.DstIP.String() != "1.1.1.1" {
		t.Fatalf("managed public route = proxy:%v rule:%v ip:%s err:%v", proxy, rule, public.DstIP, err)
	}
	pinned := managedSystemEgressDialMetadata(public)
	if pinned == public || pinned.Host != "" || pinned.DstIP.String() != "1.1.1.1" || pinned.SpecialRules != "" || public.SpecialRules != "" {
		t.Fatalf("managed system pinned metadata = same:%v host:%q ip:%s rules:%q original-rules:%q", pinned == public, pinned.Host, pinned.DstIP, pinned.SpecialRules, public.SpecialRules)
	}

	ordinaryInner := &C.Metadata{Type: C.INNER, NetWork: C.TCP, Host: "gateway.example.com", DstPort: 443}
	proxy, rule, err = resolveMetadata(ordinaryInner)
	if err != nil || proxy == nil || proxy.Name() != "DIRECT" || rule != operatorDirect {
		t.Fatalf("ordinary INNER changed = proxy:%v rule:%v err:%v", proxy, rule, err)
	}
	client := &C.Metadata{Type: C.HTTP, NetWork: C.TCP, Host: "gateway.example.com", DstPort: 443}
	proxy, rule, err = resolveMetadata(client)
	if err != nil || proxy == nil || proxy.Name() != "DIRECT" || rule != operatorDirect {
		t.Fatalf("client gateway ingress changed = proxy:%v rule:%v err:%v", proxy, rule, err)
	}
	h3 := &C.Metadata{Type: C.HTTP, NetWork: C.UDP, Host: "gateway.example.com", DstPort: 443}
	proxy, rule, err = resolveMetadata(h3)
	if err != nil || proxy == nil || proxy.Name() != "REJECT" || rule != guard {
		t.Fatalf("fixed UDP/443 guard changed = proxy:%v rule:%v err:%v", proxy, rule, err)
	}

	gatewayAddress = netip.MustParseAddr("::ffff:1.1.1.1")
	changed := &C.Metadata{
		Type: C.INNER, NetWork: C.TCP, Host: "public.example.com", DstPort: 443,
		SpecialRules: managedSystemEgressRulesV1,
	}
	proxy, rule, err = resolveMetadata(changed)
	if err != nil || proxy == nil || proxy.Name() != "REJECT" || rule != nil {
		t.Fatalf("updated mapped gateway source = proxy:%v rule:%v err:%v", proxy, rule, err)
	}
	gatewayAddress = netip.Addr{}
	invalidSource := &C.Metadata{
		Type: C.INNER, NetWork: C.TCP, Host: "gateway.example.com", DstPort: 443,
		SpecialRules: managedSystemEgressRulesV1,
	}
	if proxy, rule, err = resolveMetadata(invalidSource); err == nil || proxy != nil || rule != nil {
		t.Fatalf("invalid gateway source did not fail closed: proxy:%v rule:%v err:%v", proxy, rule, err)
	}
	managedGatewaySource.Store(nil)
	missingSource := &C.Metadata{
		Type: C.INNER, NetWork: C.TCP, Host: "gateway.example.com", DstPort: 443,
		SpecialRules: managedSystemEgressRulesV1,
	}
	if proxy, rule, err = resolveMetadata(missingSource); err == nil || proxy != nil || rule != nil {
		t.Fatalf("missing gateway source did not fail closed: proxy:%v rule:%v err:%v", proxy, rule, err)
	}
	if err := Tunnel.AuthorizeExtensionEgress(&C.Metadata{
		Type: C.INNER, NetWork: C.TCP, Host: "public.example.com", DstPort: 443,
	}, "DIRECT"); err == nil {
		t.Fatal("extension authorization accepted a missing gateway source")
	}
	SetManagedGatewaySource(func() netip.Addr { return gatewayAddress })
	gatewayAddress = netip.MustParseAddr("8.8.8.8")
	configMux.Lock()
	delete(proxies, "REJECT")
	configMux.Unlock()
	missingReject := &C.Metadata{
		Type: C.INNER, NetWork: C.TCP, DstIP: netip.MustParseAddr("8.8.8.8"), DstPort: 443,
		SpecialRules: managedSystemEgressRulesV1,
	}
	if proxy, rule, err = resolveMetadata(missingReject); err == nil || proxy != nil || rule != nil {
		t.Fatalf("missing REJECT adapter did not fail closed: proxy:%v rule:%v err:%v", proxy, rule, err)
	}
	configMux.Lock()
	proxies["REJECT"] = &tunnelTestProxy{name: "REJECT", type_: C.Reject, udp: true}
	configMux.Unlock()

	configMux.Lock()
	mode = Global
	routingConfigEpoch.Add(1)
	configMux.Unlock()
	globalMode := &C.Metadata{
		Type: C.INNER, NetWork: C.TCP, DstIP: netip.MustParseAddr("8.8.8.8"), DstPort: 443,
		SpecialRules: managedSystemEgressRulesV1,
	}
	proxy, rule, err = resolveMetadata(globalMode)
	if err != nil || proxy == nil || proxy.Name() != "REJECT" || rule != nil {
		t.Fatalf("global-mode managed gateway route = proxy:%v rule:%v err:%v", proxy, rule, err)
	}
	ordinaryGlobal := &C.Metadata{Type: C.INNER, NetWork: C.TCP, DstIP: netip.MustParseAddr("8.8.8.8"), DstPort: 443}
	proxy, rule, err = resolveMetadata(ordinaryGlobal)
	if err != nil || proxy == nil || proxy.Name() != "GLOBAL" || rule != nil {
		t.Fatalf("global-mode ordinary INNER changed = proxy:%v rule:%v err:%v", proxy, rule, err)
	}

	configMux.Lock()
	mode = Direct
	routingConfigEpoch.Add(1)
	configMux.Unlock()
	directMode := &C.Metadata{
		Type: C.INNER, NetWork: C.TCP, DstIP: netip.MustParseAddr("8.8.8.8"), DstPort: 443,
		SpecialRules: managedSystemEgressRulesV1,
	}
	proxy, rule, err = resolveMetadata(directMode)
	if err != nil || proxy == nil || proxy.Name() != "REJECT" || rule != nil {
		t.Fatalf("direct-mode managed gateway route = proxy:%v rule:%v err:%v", proxy, rule, err)
	}
	ordinaryDirect := &C.Metadata{Type: C.INNER, NetWork: C.TCP, DstIP: netip.MustParseAddr("8.8.8.8"), DstPort: 443}
	proxy, rule, err = resolveMetadata(ordinaryDirect)
	if err != nil || proxy == nil || proxy.Name() != "DIRECT" || rule != nil {
		t.Fatalf("direct-mode ordinary INNER changed = proxy:%v rule:%v err:%v", proxy, rule, err)
	}

	forged := managed.Clone()
	forged.Type = C.HTTP
	forged.SpecialRules = managedSystemEgressRulesV1
	if proxy, rule, err = resolveMetadata(forged); err == nil || proxy != nil || rule != nil {
		t.Fatalf("non-INNER managed carrier was not refused: proxy:%v rule:%v err:%v", proxy, rule, err)
	}
	udpCarrier := managed.Clone()
	udpCarrier.NetWork = C.UDP
	udpCarrier.SpecialRules = managedSystemEgressRulesV1
	if proxy, rule, err = resolveMetadata(udpCarrier); err == nil || proxy != nil || rule != nil {
		t.Fatalf("UDP managed carrier was not refused: proxy:%v rule:%v err:%v", proxy, rule, err)
	}
	unknown := managed.Clone()
	unknown.SpecialRules = managedSystemEgressRulesRoot + "v2"
	if proxy, rule, err = resolveMetadata(unknown); err == nil || proxy != nil || rule != nil {
		t.Fatalf("unknown managed carrier was not refused: proxy:%v rule:%v err:%v", proxy, rule, err)
	}
	forced := managed.Clone()
	forced.SpecialRules = managedSystemEgressRulesV1
	forced.SpecialProxy = "DIRECT"
	if proxy, rule, err = resolveMetadata(forced); err == nil || proxy != nil || rule != nil {
		t.Fatalf("forced managed carrier was not refused: proxy:%v rule:%v err:%v", proxy, rule, err)
	}
}

func TestUpdateRuleDisabledIsAtomicAndProtectsFixedGuard(t *testing.T) {
	previousCallback := clientBoundaryUpdateCallback.Load()
	callbackCalls := 0
	SetClientBoundaryUpdateCallback(func() { callbackCalls++ })
	defer clientBoundaryUpdateCallback.Store(previousCallback)
	guardRule, err := R.ParseRule("AND", "((NETWORK,UDP),(DST-PORT,443))", "REJECT", nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	ordinaryRule, err := R.ParseRule("DOMAIN", "ordinary.example.com", "REJECT", nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	guard := wrapper.NewRuleWrapper(guardRule)
	ordinary := wrapper.NewRuleWrapper(ordinaryRule)

	configMux.Lock()
	previousRules := rules
	rules = []C.Rule{guard, ordinary}
	refreshFixedClientBoundaryLocked()
	routingConfigEpoch.Add(1)
	configMux.Unlock()
	defer func() {
		configMux.Lock()
		rules = previousRules
		refreshFixedClientBoundaryLocked()
		routingConfigEpoch.Add(1)
		configMux.Unlock()
	}()

	if err := UpdateRuleDisabled(map[int]bool{0: true}); err == nil {
		t.Fatal("fixed UDP/443 guard disable was accepted")
	}
	if guard.IsDisabled() {
		t.Fatal("rejected fixed guard patch still changed the wrapper")
	}
	if callbackCalls != 0 {
		t.Fatalf("rejected guard mutation published %d boundary updates", callbackCalls)
	}
	if err := UpdateRuleDisabled(map[int]bool{1: true, 9: true}); err == nil {
		t.Fatal("out-of-range atomic patch was accepted")
	}
	if ordinary.IsDisabled() {
		t.Fatal("part of a rejected atomic patch was applied")
	}
	before := routingConfigEpoch.Load()
	if err := UpdateRuleDisabled(map[int]bool{1: true}); err != nil {
		t.Fatal(err)
	}
	if !ordinary.IsDisabled() || routingConfigEpoch.Load() == before {
		t.Fatal("accepted disable did not publish wrapper state and routing epoch")
	}
	if callbackCalls != 1 {
		t.Fatalf("accepted disable published %d boundary updates, want 1", callbackCalls)
	}
}
