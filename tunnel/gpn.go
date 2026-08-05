package tunnel

import (
	"errors"
	"fmt"
	"sort"
	"sync/atomic"

	"github.com/metacubex/mihomo/component/nat"
	C "github.com/metacubex/mihomo/constant"
)

// This file is fork-owned. It exists so the hooks in tunnel.go stay three lines
// each: new files do not conflict on rebase, edited upstream files do.

var interceptor atomic.Pointer[C.Interceptor]

var trafficPolicy atomic.Pointer[C.TrafficPolicy]

var egressProxyNames atomic.Pointer[map[string]struct{}]

var egressProxyUpdateCallback atomic.Pointer[func()]

var clientBoundaryUpdateCallback atomic.Pointer[func()]

var routingConfigEpoch atomic.Uint64

// Protected by configMux and refreshed with the default rule list.
var fixedClientBoundaryIndex = -1
var fixedClientBoundaryError = "fixed UDP/443 guard is missing or disabled"

// SetTrafficPolicy installs the reviewed in-memory client routing policy.
func SetTrafficPolicy(policy C.TrafficPolicy) {
	if policy == nil {
		trafficPolicy.Store(nil)
		return
	}
	trafficPolicy.Store(&policy)
}

// SetEgressProxyUpdateCallback installs a notification for live group-set
// changes. It is invoked after the tunnel publishes a new proxy snapshot.
func SetEgressProxyUpdateCallback(callback func()) {
	if callback == nil {
		egressProxyUpdateCallback.Store(nil)
		return
	}
	egressProxyUpdateCallback.Store(&callback)
}

// SetClientBoundaryUpdateCallback installs a notification for fixed-prefix
// readiness changes.
func SetClientBoundaryUpdateCallback(callback func()) {
	if callback == nil {
		clientBoundaryUpdateCallback.Store(nil)
		return
	}
	clientBoundaryUpdateCallback.Store(&callback)
}

func notifyClientBoundaryUpdate() {
	if callback := clientBoundaryUpdateCallback.Load(); callback != nil {
		(*callback)()
	}
}

// ClientPolicyBoundaryReady reports whether extension routing can be inserted
// after the one enabled canonical fixed guard in rule mode.
func ClientPolicyBoundaryReady() bool {
	configMux.RLock()
	defer configMux.RUnlock()
	return fixedClientBoundaryReadyLocked()
}

func fixedClientBoundaryReadyLocked() bool {
	if mode != Rule || fixedClientBoundaryError != "" || fixedClientBoundaryIndex < 0 || fixedClientBoundaryIndex >= len(rules) {
		return false
	}
	reject, exists := proxies["REJECT"]
	return exists && reject != nil && reject.Type() == C.Reject
}

func publishEgressProxyNames(newProxies map[string]C.Proxy) {
	names := make(map[string]struct{})
	for name, proxy := range newProxies {
		if proxy == nil {
			continue
		}
		if name == "DIRECT" {
			if proxy.Type() == C.Direct {
				names[name] = struct{}{}
			}
			continue
		}
		if name == "GLOBAL" {
			continue
		}
		switch proxy.Type() {
		case C.Selector, C.Fallback, C.URLTest, C.LoadBalance:
			names[name] = struct{}{}
		}
	}
	egressProxyNames.Store(&names)
	if callback := egressProxyUpdateCallback.Load(); callback != nil {
		(*callback)()
	}
}

// IsEgressProxy reports whether name is a live operator-selectable egress.
func IsEgressProxy(name string) bool {
	names := egressProxyNames.Load()
	if names == nil {
		return false
	}
	_, exists := (*names)[name]
	return exists
}

// EgressProxies returns the narrow group catalog exposed to extension binding.
func EgressProxies() []string {
	names := egressProxyNames.Load()
	if names == nil {
		return []string{}
	}
	out := make([]string, 0, len(*names))
	for name := range *names {
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

func clientRouteProxyFor(metadata *C.Metadata) (string, bool) {
	if metadata == nil || metadata.Type == C.INNER || metadata.SpecialProxy != "" {
		return "", false
	}
	// The fixed gateway UDP/443 rule has higher precedence than extension
	// routing and must not be bypassed by a reviewed DIRECT action.
	if metadata.NetWork == C.UDP && metadata.DstPort == 443 {
		return "", false
	}
	policy := trafficPolicy.Load()
	if policy == nil {
		return "", false
	}
	switch (*policy).RouteClient(metadata) {
	case C.ClientRouteNone:
		return "", false
	case C.ClientRouteDirect:
		return "DIRECT", true
	case C.ClientRouteReject:
		return "REJECT", true
	default:
		// An invalid policy result is an authorization failure, never a reason
		// to continue into capture or the operator's fallback rules.
		return "REJECT", true
	}
}

func clientPolicyActiveFor(metadata *C.Metadata) bool {
	if metadata == nil || metadata.Type == C.INNER || metadata.SpecialProxy != "" {
		return false
	}
	policy := trafficPolicy.Load()
	return policy != nil && (*policy).ClientPolicyActive()
}

func clientPolicyClaims(metadata *C.Metadata) bool {
	policy := trafficPolicy.Load()
	if policy == nil || (*policy).RouteClient(metadata) != C.ClientRouteNone {
		return policy != nil
	}
	intercept := interceptor.Load()
	if intercept == nil {
		return false
	}
	if metadata.NetWork == C.UDP {
		return (*intercept).MatchUDP(metadata)
	}
	return (*intercept).MatchTCP(metadata)
}

// prepareClientRouting performs every decision that must precede capture. A
// non-nil prefix with decided=false means capture may run; if it declines, the
// caller must resolve only prefix.remainder.
func prepareClientRouting(metadata *C.Metadata) (prefix *clientRulePrefix, proxy C.Proxy, rule C.Rule, decided bool, err error) {
	if !clientPolicyActiveFor(metadata) {
		return nil, nil, nil, false, nil
	}
	state, err := resolveClientRulePrefix(metadata)
	if err != nil {
		if clientPolicyClaims(metadata) {
			return nil, nil, nil, true, err
		}
		return nil, nil, nil, false, nil
	}
	prefix = &state
	if state.matched {
		return prefix, state.proxy, state.rule, true, nil
	}
	if specialProxy, routed := clientRouteProxyFor(metadata); routed {
		metadata.SpecialProxy = specialProxy
		return prefix, nil, nil, true, nil
	}
	return prefix, nil, nil, false, nil
}

func resolvePreparedClientRouting(metadata *C.Metadata, prefix *clientRulePrefix, proxy C.Proxy, rule C.Rule) (C.Proxy, C.Rule, error) {
	if prefix != nil && !clientRulePrefixCurrent(*prefix) {
		metadata.SpecialProxy = "REJECT"
		proxy = nil
	}
	if proxy != nil {
		return proxy, rule, nil
	}
	if metadata.SpecialProxy != "" || prefix == nil {
		return resolveMetadata(metadata)
	}
	resolvedProxy, resolvedRule, err := resolveClientRuleRemainder(metadata, *prefix)
	if err == nil {
		return resolvedProxy, resolvedRule, nil
	}
	metadata.SpecialProxy = "REJECT"
	return resolveMetadata(metadata)
}

type clientRulePrefix struct {
	proxy     C.Proxy
	rule      C.Rule
	remainder []C.Rule
	helper    C.RuleMatchHelper
	matched   bool
	epoch     uint64
	guard     C.Rule
}

// resolveClientRulePrefix evaluates the operator-owned rules through the fixed
// UDP/443 guard. Extension routing and capture are allowed only after this
// exact boundary, so DIRECT cannot bypass panel, console, or anti-loop rules.
func resolveClientRulePrefix(metadata *C.Metadata) (clientRulePrefix, error) {
	if metadata == nil {
		return clientRulePrefix{}, errors.New("extension client routing requires metadata")
	}
	helper := newRuleMatchHelper(metadata)
	configMux.RLock()
	defer configMux.RUnlock()
	if mode != Rule {
		return clientRulePrefix{}, errors.New("extension client routing requires mihomo rule mode")
	}

	ruleList := getRules(metadata)
	boundary, boundaryError := fixedClientBoundaryIndex, fixedClientBoundaryError
	if metadata.SpecialRules != "" {
		boundary, boundaryError = analyzeFixedClientBoundary(ruleList)
	}
	if boundaryError != "" {
		return clientRulePrefix{}, errors.New(boundaryError)
	}
	if reject, exists := proxies["REJECT"]; !exists || reject == nil || reject.Type() != C.Reject {
		return clientRulePrefix{}, errors.New("fixed UDP/443 guard REJECT adapter is unavailable")
	}

	result := matchRuleList(metadata, helper, ruleList[:boundary+1])
	if result.rematch != nil {
		return clientRulePrefix{}, fmt.Errorf("fixed rule prefix selected rematch proxy %q", result.rematch.Name())
	}
	state := clientRulePrefix{
		proxy: result.proxy, rule: result.rule, helper: helper, matched: result.matched,
		remainder: append(make([]C.Rule, 0, len(ruleList)-boundary-1), ruleList[boundary+1:]...),
		epoch:     routingConfigEpoch.Load(),
		guard:     ruleList[boundary],
	}
	return state, nil
}

func analyzeFixedClientBoundary(ruleList []C.Rule) (int, string) {
	boundary := -1
	guardCount := 0
	guardDisabled := false
	for index, rule := range ruleList {
		if !isFixedUDP443GuardShape(rule) {
			continue
		}
		guardCount++
		if wrapper, ok := rule.(C.RuleWrapper); ok && wrapper.IsDisabled() {
			guardDisabled = true
		}
		boundary = index
	}
	switch {
	case guardCount > 1:
		return -1, "fixed UDP/443 guard is duplicated"
	case boundary == -1 || guardDisabled:
		return -1, "fixed UDP/443 guard is missing or disabled"
	default:
		return boundary, ""
	}
}

func refreshFixedClientBoundaryLocked() {
	fixedClientBoundaryIndex, fixedClientBoundaryError = analyzeFixedClientBoundary(rules)
}

func isFixedUDP443GuardShape(rule C.Rule) bool {
	if rule == nil || rule.RuleType() != C.AND || rule.Adapter() != "REJECT" {
		return false
	}
	return rule.Payload() == "((Network,udp) && (DstPort,443))"
}

func resolveClientRuleRemainder(metadata *C.Metadata, prefix clientRulePrefix) (C.Proxy, C.Rule, error) {
	configMux.RLock()
	defer configMux.RUnlock()
	if !clientRulePrefixCurrent(prefix) {
		return nil, nil, errors.New("mihomo routing changed after the fixed prefix decision")
	}
	return matchLocked(metadata, prefix.helper, prefix.remainder)
}

func clientRulePrefixCurrent(prefix clientRulePrefix) bool {
	if prefix.epoch != routingConfigEpoch.Load() || !isFixedUDP443GuardShape(prefix.guard) {
		return false
	}
	if wrapper, ok := prefix.guard.(C.RuleWrapper); ok && wrapper.IsDisabled() {
		return false
	}
	return true
}

func clientPrefixAllowsCapture(prefix *clientRulePrefix) bool {
	return prefix != nil && clientRulePrefixCurrent(*prefix)
}

// SetInterceptor installs (or with nil, removes) the capture stage.
//
// An atomic pointer rather than a mutex-guarded field because the interceptor is
// consulted on every sniffed connection and must never contend with a
// reconfiguration that happens a few times an hour.
func SetInterceptor(i C.Interceptor) {
	if i == nil {
		interceptor.Store(nil)
		return
	}
	interceptor.Store(&i)
}

// captureTCPFor returns the interceptor that wants this connection, or nil.
//
// The decision lives here rather than at the call site for one reason: the
// INNER guard. The interceptor reaches its upstreams by dialing back through
// this same tunnel, which arrives as Type == INNER. Capturing that would feed
// the interceptor its own output forever. Putting the guard behind the only
// function that can answer "yes" makes it impossible to add a second call site
// that forgets it.
func captureTCPFor(metadata *C.Metadata) C.Interceptor {
	p := interceptor.Load()
	if p == nil || metadata.Type == C.INNER {
		return nil
	}
	ic := *p
	if !ic.MatchTCP(metadata) {
		return nil
	}
	return ic
}

// captureUDPFor is the datagram equivalent, used for QUIC.
//
// Same INNER guard and for the same reason: the engine reaches its own H3
// upstreams by listening on a packet conn dialled back through this tunnel.
func captureUDPFor(metadata *C.Metadata) C.Interceptor {
	p := interceptor.Load()
	if p == nil || metadata.Type == C.INNER {
		return nil
	}
	ic := *p
	if !ic.MatchUDP(metadata) {
		return nil
	}
	return ic
}

// dialCapturedUDP completes an association the interceptor has claimed.
//
// It lives here rather than at the call site so the hook in tunnel.go stays
// three lines. The bookkeeping is deliberately the same as the uncaptured path
// below it -- the destination NAT mapping, the write-back proxy, the reader
// pump -- because the core still owns both directions of the association. What
// capture replaces is only where the datagrams go: the interceptor's packet
// conn instead of an outbound's.
//
// There is no statistic tracker and no rule, for the same reason the TCP
// capture has neither: this association was never routed. The engine's own
// upstream is dialled back through the tunnel and appears in the connection
// table there, which is the row that describes an egress choice actually made.
func dialCapturedUDP(
	ic C.Interceptor,
	packet C.PacketAdapter,
	sender C.PacketSender,
	originMetadata *C.Metadata,
	metadata *C.Metadata,
	key string,
) (C.PacketConn, C.WriteBackProxy, error) {
	pc, err := ic.HandleUDP(metadata)
	if err != nil {
		return nil, nil, err
	}
	dialMetadata := metadata.Pure()
	sender.AddMapping(originMetadata, dialMetadata)
	writeBackProxy := nat.NewWriteBackProxy(packet)
	go handleUDPToLocal(writeBackProxy, pc, sender, key, dialMetadata.AddrPort())
	return pc, writeBackProxy, nil
}

// ResolveMetadata exposes rule evaluation to fork-owned packages.
//
// The interception engine needs the same answer the core would have reached for
// a destination, because its upstream must obey the operator's routing exactly
// as an uncaptured connection would. Exporting the existing function is how that
// stays one implementation rather than two that drift.
func ResolveMetadata(metadata *C.Metadata) (C.Proxy, C.Rule, error) {
	return resolveMetadata(metadata)
}
