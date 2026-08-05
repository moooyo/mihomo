package tunnel

import (
	"context"
	"testing"

	"github.com/metacubex/mihomo/common/utils"
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
