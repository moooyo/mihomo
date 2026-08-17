package tunnel

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sort"
	"strings"
	"sync/atomic"
	"unicode/utf8"

	N "github.com/metacubex/mihomo/common/net"
	"github.com/metacubex/mihomo/component/resolver"
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

var extensionEgressAddressPolicy atomic.Pointer[func(netip.Addr) bool]

var managedGatewaySource atomic.Pointer[func() netip.Addr]

const (
	extensionEgressSpecialRulesRoot   = "\x005gpn-extension-egress:"
	extensionEgressSpecialRulesPrefix = extensionEgressSpecialRulesRoot + "v1:"
	managedSystemEgressRulesRoot      = "\x005gpn-system-egress:"
	managedSystemEgressRulesV1        = managedSystemEgressRulesRoot + "v1"
)

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

// SetExtensionEgressAddressPolicy installs the product-owned public-address
// predicate without making the upstream tunnel package import 5gpn code.
// Passing nil withdraws the policy and makes extension egress fail closed.
func SetExtensionEgressAddressPolicy(policy func(netip.Addr) bool) {
	if policy == nil {
		extensionEgressAddressPolicy.Store(nil)
		return
	}
	extensionEgressAddressPolicy.Store(&policy)
}

// SetManagedGatewaySource publishes the installation-owned DNS projection that
// private 5gpn system and extension tunnel carriers must never dial back into.
// Direct-socket DNS, subscription, and importer paths are outside this boundary
// and retain their separate destination policies. Ordinary mihomo startup never
// calls this hook, so its INNER flows retain upstream behavior.
func SetManagedGatewaySource(source func() netip.Addr) {
	if source == nil {
		managedGatewaySource.Store(nil)
		return
	}
	managedGatewaySource.Store(&source)
}

func managedGatewaySnapshot() (netip.Addr, bool) {
	source := managedGatewaySource.Load()
	if source == nil {
		return netip.Addr{}, false
	}
	gateway := (*source)().Unmap()
	if !gateway.Is4() || !gateway.IsGlobalUnicast() || gateway.IsLoopback() {
		return netip.Addr{}, false
	}
	return gateway, true
}

func managedGatewayTarget(address, gateway netip.Addr) bool {
	return gateway.IsValid() && address.IsValid() && address.Unmap() == gateway
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
		if isOperatorEgressProxy(name, proxy) {
			names[name] = struct{}{}
		}
	}
	egressProxyNames.Store(&names)
	if callback := egressProxyUpdateCallback.Load(); callback != nil {
		(*callback)()
	}
}

func isOperatorEgressProxy(name string, proxy C.Proxy) bool {
	if proxy == nil || name == "GLOBAL" {
		return false
	}
	if name == "DIRECT" {
		return proxy.Type() == C.Direct
	}
	switch proxy.Type() {
	case C.Selector, C.Fallback, C.URLTest, C.LoadBalance:
		return true
	default:
		return false
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

// fixedUDP443ClientReject is the product's global HTTP/3 guard, independent of
// extension state and of the request's SpecialRules or SpecialProxy shortcut.
// The default rule list remains the operator-owned readiness proof; once its
// one canonical enabled guard and REJECT adapter are live, no alternate rule
// list or earlier MATCH may make a non-INNER client UDP/443 flow bypass it.
func fixedUDP443ClientReject(metadata *C.Metadata) (C.Proxy, C.Rule, bool, error) {
	if metadata == nil || metadata.Type == C.INNER || metadata.NetWork != C.UDP || metadata.DstPort != 443 {
		return nil, nil, false, nil
	}
	policy := trafficPolicy.Load()
	policyActive := policy != nil && (*policy).ClientPolicyActive()
	configMux.RLock()
	defer configMux.RUnlock()
	if fixedClientBoundaryReadyLocked() {
		return proxies["REJECT"], rules[fixedClientBoundaryIndex], true, nil
	}
	if !policyActive {
		return nil, nil, false, nil
	}
	// Once interception policy is active, losing the fixed-boundary proof is a
	// readiness failure. Reject with the adapter when it is still available;
	// otherwise return an error so a SpecialProxy or alternate rule list cannot
	// turn that failure into forwarded HTTP/3.
	if reject, exists := proxies["REJECT"]; exists && reject != nil && reject.Type() == C.Reject {
		return reject, nil, true, nil
	}
	return nil, nil, true, errors.New("fixed UDP/443 guard REJECT adapter is unavailable")
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
	if metadata.NetWork != C.TCP {
		return false
	}
	return (*intercept).MatchTCP(metadata)
}

// prepareClientRouting performs every decision that must precede capture. A
// non-nil prefix with decided=false means capture may run; if it declines, the
// caller must resolve only prefix.remainder.
func prepareClientRouting(metadata *C.Metadata) (prefix *clientRulePrefix, proxy C.Proxy, rule C.Rule, decided bool, err error) {
	if guardProxy, guardRule, guarded, guardErr := fixedUDP443ClientReject(metadata); guarded {
		return nil, guardProxy, guardRule, true, guardErr
	}
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
// UDP/443 guard. Extension routing and TCP capture are allowed only after this
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

	boundary, boundaryError := fixedClientBoundaryIndex, fixedClientBoundaryError
	if boundaryError != "" {
		return clientRulePrefix{}, errors.New(boundaryError)
	}
	if reject, exists := proxies["REJECT"]; !exists || reject == nil || reject.Type() != C.Reject {
		return clientRulePrefix{}, errors.New("fixed UDP/443 guard REJECT adapter is unavailable")
	}

	// The protected prefix always comes from the operator's default rule list.
	// A selected SpecialRules list is an ordinary remainder, not another owner
	// of the global UDP/443 readiness proof.
	prefixRules := rules[:boundary+1]
	remainder := rules[boundary+1:]
	if metadata.SpecialRules != "" {
		if selected, exists := subRules[metadata.SpecialRules]; exists {
			remainder = selected
		}
	}
	result := matchRuleList(metadata, helper, prefixRules)
	if result.rematch != nil {
		return clientRulePrefix{}, fmt.Errorf("fixed rule prefix selected rematch proxy %q", result.rematch.Name())
	}
	state := clientRulePrefix{
		proxy: result.proxy, rule: result.rule, helper: helper, matched: result.matched,
		remainder: append(make([]C.Rule, 0, len(remainder)), remainder...),
		epoch:     routingConfigEpoch.Load(),
		guard:     rules[boundary],
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

func encodeExtensionEgressCarrier(binding string) (string, error) {
	if binding == "" || !utf8.ValidString(binding) {
		return "", errors.New("extension egress binding is empty or invalid UTF-8")
	}
	encoded := base64.RawURLEncoding.EncodeToString([]byte(binding))
	return extensionEgressSpecialRulesPrefix + encoded, nil
}

func extensionEgressCarrierPresent(specialRules string) bool {
	return strings.HasPrefix(specialRules, extensionEgressSpecialRulesRoot)
}

func managedSystemEgressCarrierPresent(specialRules string) bool {
	return strings.HasPrefix(specialRules, managedSystemEgressRulesRoot)
}

func managedEgressCarrierPresent(specialRules string) bool {
	return extensionEgressCarrierPresent(specialRules) || managedSystemEgressCarrierPresent(specialRules)
}

func decodeExtensionEgressCarrier(metadata *C.Metadata) (binding string, present bool, err error) {
	if metadata == nil || !extensionEgressCarrierPresent(metadata.SpecialRules) {
		return "", false, nil
	}
	if !strings.HasPrefix(metadata.SpecialRules, extensionEgressSpecialRulesPrefix) {
		return "", true, errors.New("reserved extension egress carrier version is unsupported")
	}
	if metadata.Type != C.INNER || metadata.NetWork != C.TCP || metadata.SpecialProxy != "" {
		return "", true, errors.New("reserved extension egress carrier requires an unforced INNER TCP flow")
	}
	encoded := strings.TrimPrefix(metadata.SpecialRules, extensionEgressSpecialRulesPrefix)
	decoded, decodeErr := base64.RawURLEncoding.Strict().DecodeString(encoded)
	if decodeErr != nil || len(decoded) == 0 || !utf8.Valid(decoded) ||
		base64.RawURLEncoding.EncodeToString(decoded) != encoded {
		return "", true, errors.New("reserved extension egress carrier is malformed")
	}
	return string(decoded), true, nil
}

func decodeManagedSystemEgressCarrier(metadata *C.Metadata) (present bool, err error) {
	if metadata == nil || !managedSystemEgressCarrierPresent(metadata.SpecialRules) {
		return false, nil
	}
	if metadata.SpecialRules != managedSystemEgressRulesV1 {
		return true, errors.New("reserved managed system egress carrier version is unsupported")
	}
	if metadata.Type != C.INNER || metadata.NetWork != C.TCP || metadata.SpecialProxy != "" {
		return true, errors.New("reserved managed system egress carrier requires an unforced INNER TCP flow")
	}
	return true, nil
}

func newManagedSystemEgressMetadata(address string) (*C.Metadata, error) {
	metadata := &C.Metadata{
		NetWork:      C.TCP,
		Type:         C.INNER,
		DNSMode:      C.DNSNormal,
		Process:      C.MihomoName,
		SpecialRules: managedSystemEgressRulesV1,
	}
	if err := metadata.SetRemoteAddress(address); err != nil {
		return nil, fmt.Errorf("invalid managed system egress target: %w", err)
	}
	if !metadata.Valid() || metadata.DstPort == 0 {
		return nil, errors.New("invalid managed system egress target address")
	}
	return metadata, nil
}

func newExtensionEgressMetadata(address string, binding string) (*C.Metadata, error) {
	carrier, err := encodeExtensionEgressCarrier(binding)
	if err != nil {
		return nil, err
	}
	metadata := &C.Metadata{
		NetWork:      C.TCP,
		Type:         C.INNER,
		DNSMode:      C.DNSNormal,
		Process:      C.MihomoName,
		SpecialRules: carrier,
	}
	if err := metadata.SetRemoteAddress(address); err != nil {
		return nil, fmt.Errorf("invalid extension egress target: %w", err)
	}
	if !metadata.Valid() || metadata.DstPort == 0 {
		return nil, errors.New("invalid extension egress target address")
	}
	return metadata, nil
}

// DialExtensionEgress enters the normal TCP tunnel without teaching the
// upstream-owned inner listener about 5gpn. The reserved SpecialRules value is
// private to this package and is removed before the selected outbound sees it.
func (t tunnel) DialExtensionEgress(address string, binding string) (net.Conn, error) {
	metadata, err := newExtensionEgressMetadata(address, binding)
	if err != nil {
		return nil, err
	}
	conn1, conn2 := N.Pipe()
	go t.HandleTCPConn(conn2, metadata)
	return conn1, nil
}

// DialManagedSystemEgress enters the normal TCP tunnel with a private marker
// that scopes the dynamic gateway anti-loop guard to 5gpn-owned control
// traffic. Generic mihomo INNER traffic never receives this marker.
func (t tunnel) DialManagedSystemEgress(address string) (net.Conn, error) {
	metadata, err := newManagedSystemEgressMetadata(address)
	if err != nil {
		return nil, err
	}
	conn1, conn2 := N.Pipe()
	go t.HandleTCPConn(conn2, metadata)
	return conn1, nil
}

func resolveManagedSystemEgress(metadata *C.Metadata) (C.Proxy, C.Rule, error) {
	return resolveManagedSystemEgressWithRoute(metadata, resolveManagedSystemEgressRoute)
}

type managedSystemEgressRoute func(*C.Metadata) (C.Proxy, C.Rule, error)

func resolveManagedSystemEgressWithRoute(metadata *C.Metadata, route managedSystemEgressRoute) (C.Proxy, C.Rule, error) {
	present, err := decodeManagedSystemEgressCarrier(metadata)
	if err != nil {
		return nil, nil, err
	}
	if !present {
		return nil, nil, errors.New("managed system egress carrier is missing")
	}
	gateway, sourceReady := managedGatewaySnapshot()
	if !sourceReady {
		return nil, nil, errors.New("managed gateway source is unavailable or invalid")
	}

	targetAllowed, gatewayTarget, targetErr := resolveManagedEgressTarget(metadata, gateway, false)
	proxy, rule, routeErr := route(metadata)
	if routeErr != nil {
		return nil, nil, routeErr
	}
	if proxy == nil {
		return nil, nil, errors.New("managed system egress routing returned no proxy")
	}
	// Preserve operator REJECT precedence and rule identity. Any non-rejecting
	// route remains subordinate to the immutable gateway anti-loop boundary.
	if proxy.Type() == C.Reject || proxy.Type() == C.RejectDrop {
		return proxy, rule, nil
	}
	if targetErr != nil {
		return nil, nil, targetErr
	}
	if gatewayTarget {
		reject, rejectErr := managedGatewayRejectProxy()
		return reject, nil, rejectErr
	}
	if !targetAllowed {
		return nil, nil, fmt.Errorf("managed system egress target %s resolved to an unusable address", metadata.RuleHost())
	}
	return proxy, rule, nil
}

func resolveManagedSystemEgressRoute(metadata *C.Metadata) (C.Proxy, C.Rule, error) {
	return resolveOrdinaryMetadata(managedSystemEgressRouteMetadata(metadata))
}

func managedSystemEgressRouteMetadata(metadata *C.Metadata) *C.Metadata {
	routeMetadata := metadata.Clone()
	routeMetadata.SpecialRules = ""
	if routeMetadata.Host != "" {
		// The original ordinary INNER flow entered rule evaluation with an
		// unresolved domain. Preserve that no-resolve behavior while carrying the
		// domain independently of any hosts lookup performed by the rule helper.
		routeMetadata.SniffHost = routeMetadata.Host
		routeMetadata.DstIP = netip.Addr{}
	}
	return routeMetadata
}

func resolveManagedEgressTarget(metadata *C.Metadata, gateway netip.Addr, requirePublic bool) (allAllowed bool, gatewayTarget bool, err error) {
	if metadata == nil {
		return false, false, errors.New("managed egress metadata is missing")
	}
	if metadata.DstIP.IsValid() {
		metadata.DstIP = metadata.DstIP.Unmap()
		allowed := !resolver.IsFakeIP(metadata.DstIP) && (!requirePublic || extensionEgressAddressAllowed(metadata.DstIP))
		return allowed, managedGatewayTarget(metadata.DstIP, gateway), nil
	}
	if metadata.Host == "" {
		return false, false, errors.New("managed egress target has no address")
	}
	if node, ok := resolver.DefaultHosts.Search(metadata.Host, true); ok {
		metadata.Host = node.Domain
	}
	ctx, cancel := context.WithTimeout(context.Background(), resolver.DefaultDNSTimeout)
	defer cancel()
	addresses, err := resolver.LookupIP(ctx, metadata.Host)
	if err != nil {
		return false, false, fmt.Errorf("resolve managed egress target %s: %w", metadata.Host, err)
	}
	selected := netip.Addr{}
	allAllowed = true
	for _, address := range addresses {
		normalized := address.Unmap()
		if !normalized.IsValid() || resolver.IsFakeIP(normalized) || (requirePublic && !extensionEgressAddressAllowed(address)) {
			allAllowed = false
		}
		if managedGatewayTarget(normalized, gateway) {
			gatewayTarget = true
		}
		if !selected.IsValid() || (normalized.Is4() && !selected.Is4()) {
			selected = normalized
		}
	}
	if !selected.IsValid() {
		return false, gatewayTarget, fmt.Errorf("managed egress target %s resolved to no usable address", metadata.Host)
	}
	metadata.DstIP = selected
	return allAllowed, gatewayTarget, nil
}

func managedGatewayRejectProxy() (C.Proxy, error) {
	configMux.RLock()
	defer configMux.RUnlock()
	reject, exists := proxies["REJECT"]
	if !exists || reject == nil || reject.Type() != C.Reject {
		return nil, errors.New("managed gateway anti-loop REJECT adapter is unavailable")
	}
	return reject, nil
}

// resolveExtensionEgress applies the immutable operator safety prefix before
// treating an extension binding as the terminal egress decision. The target is
// resolved once and pinned so neither DIRECT nor a remote proxy can resolve the
// hostname again to a private management address after this check.
func resolveExtensionEgress(metadata *C.Metadata, binding string) (C.Proxy, C.Rule, error) {
	if metadata == nil || binding == "" {
		return nil, nil, errors.New("extension egress metadata is incomplete")
	}
	if metadata.NetWork != C.TCP {
		return nil, nil, errors.New("extension egress supports TCP only")
	}
	if metadata.Type != C.INNER || metadata.SpecialProxy != "" {
		return nil, nil, errors.New("extension egress requires an unforced INNER flow")
	}
	gateway, sourceReady := managedGatewaySnapshot()
	if !sourceReady {
		return nil, nil, errors.New("managed gateway source is unavailable or invalid")
	}
	targetAllowed, gatewayTarget, targetErr := resolveManagedEgressTarget(metadata, gateway, true)
	// Rule matching needs both the dial target and the pinned address. Keep the
	// target as the rule identity rather than a sniffed application host, while
	// hiding Host from the helper's live lookup. This keeps pooled preflight and
	// the eventual inner dial on the same safety decision, including IP targets
	// and domain targets whose resolution failed.
	ruleMetadata := metadata.Clone()
	ruleMetadata.SniffHost = ruleMetadata.Host
	ruleMetadata.Host = ""
	ruleMetadata.SpecialRules = ""
	prefix, err := resolveClientRulePrefix(ruleMetadata)
	if err != nil {
		return nil, nil, fmt.Errorf("extension egress safety prefix: %w", err)
	}
	if prefix.matched {
		configMux.RLock()
		if !clientRulePrefixCurrent(prefix) {
			configMux.RUnlock()
			return nil, nil, errors.New("mihomo routing changed after the extension egress safety decision")
		}
		if prefix.proxy == nil {
			configMux.RUnlock()
			return nil, nil, errors.New("extension egress safety prefix returned no proxy")
		}
		prefixProxy, prefixRule := prefix.proxy, prefix.rule
		configMux.RUnlock()
		// An operator REJECT is terminal even when the resolved address itself is
		// unsafe; no connection is opened in that case.
		if prefixProxy.Type() == C.Reject || prefixProxy.Type() == C.RejectDrop {
			return prefixProxy, prefixRule, nil
		}
		if targetErr != nil {
			return nil, nil, targetErr
		}
		if gatewayTarget {
			reject, rejectErr := managedGatewayRejectProxy()
			return reject, nil, rejectErr
		}
		if !targetAllowed || !extensionEgressAddressAllowed(metadata.DstIP) {
			return nil, nil, fmt.Errorf("extension egress target %s resolved to a non-public address", metadata.RuleHost())
		}
		if prefixProxy.Name() != binding || !isOperatorEgressProxy(binding, prefixProxy) {
			return nil, nil, fmt.Errorf("operator safety prefix selected %s instead of extension egress %s", prefixProxy.Name(), binding)
		}
		return prefixProxy, prefixRule, nil
	}
	if targetErr != nil {
		return nil, nil, targetErr
	}
	if gatewayTarget {
		reject, rejectErr := managedGatewayRejectProxy()
		return reject, nil, rejectErr
	}
	if !targetAllowed || !extensionEgressAddressAllowed(metadata.DstIP) {
		return nil, nil, fmt.Errorf("extension egress target %s resolved to a non-public address", metadata.RuleHost())
	}

	configMux.RLock()
	defer configMux.RUnlock()
	if !clientRulePrefixCurrent(prefix) {
		return nil, nil, errors.New("mihomo routing changed after the extension egress safety decision")
	}
	proxy, exists := proxies[binding]
	if !exists || !isOperatorEgressProxy(binding, proxy) {
		return nil, nil, fmt.Errorf("extension egress proxy %q not found", binding)
	}
	return proxy, nil, nil
}

func resolveCarriedExtensionEgress(metadata *C.Metadata) (C.Proxy, C.Rule, error) {
	binding, present, err := decodeExtensionEgressCarrier(metadata)
	if err != nil {
		return nil, nil, err
	}
	if !present {
		return nil, nil, errors.New("extension egress carrier is missing")
	}
	return resolveExtensionEgress(metadata, binding)
}

// AuthorizeExtensionEgress applies the same final-use safety decision for an
// HTTP request that may reuse an existing upstream connection. A newly added
// operator REJECT therefore revokes pooled traffic without waiting for a new
// inner dial.
func (t tunnel) AuthorizeExtensionEgress(metadata *C.Metadata, egressProxy string) error {
	if metadata == nil {
		return errors.New("extension egress metadata is missing")
	}
	candidate := metadata.Clone()
	candidate.SpecialRules = ""
	proxy, _, err := resolveExtensionEgress(candidate, egressProxy)
	if err != nil {
		return err
	}
	if proxy == nil {
		return errors.New("extension egress safety decision returned no proxy")
	}
	if proxy.Type() == C.Reject || proxy.Type() == C.RejectDrop {
		return fmt.Errorf("operator safety rule selected %s", proxy.Name())
	}
	if proxy.Name() != egressProxy {
		return fmt.Errorf("operator safety rule selected %s instead of %s", proxy.Name(), egressProxy)
	}
	return nil
}

func extensionEgressAddressAllowed(address netip.Addr) bool {
	policy := extensionEgressAddressPolicy.Load()
	return policy != nil && (*policy)(address) && !resolver.IsFakeIP(address.Unmap())
}

func extensionEgressDialMetadata(metadata *C.Metadata) *C.Metadata {
	_, present, err := decodeExtensionEgressCarrier(metadata)
	if !present || err != nil {
		return metadata
	}
	// Only the outbound adapter receives the pinned address. The original
	// metadata and the HTTP transport above this connection retain the hostname
	// used for rule matching, Host, SNI, and certificate verification.
	pinned := metadata.Clone()
	if pinned.DstIP.IsValid() {
		pinned.Host = ""
	}
	pinned.SpecialRules = ""
	metadata.SpecialRules = ""
	return pinned
}

func managedSystemEgressDialMetadata(metadata *C.Metadata) *C.Metadata {
	present, err := decodeManagedSystemEgressCarrier(metadata)
	if !present || err != nil {
		return metadata
	}
	pinned := metadata.Clone()
	if pinned.DstIP.IsValid() {
		pinned.Host = ""
	}
	pinned.SpecialRules = ""
	metadata.SpecialRules = ""
	return pinned
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

// ResolveMetadata exposes rule evaluation to fork-owned packages.
//
// The interception engine needs the same answer the core would have reached for
// a destination, because its upstream must obey the operator's routing exactly
// as an uncaptured connection would. Exporting the existing function is how that
// stays one implementation rather than two that drift.
func ResolveMetadata(metadata *C.Metadata) (C.Proxy, C.Rule, error) {
	return resolveMetadata(metadata)
}
