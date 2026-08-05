package engine

import (
	"errors"
	"fmt"
	"net/netip"
	"sort"
	"strings"
	"sync/atomic"

	C "github.com/metacubex/mihomo/constant"
)

var (
	errTrafficPolicyUnavailable = errors.New("interception traffic policy is unavailable")
	errEgressUnauthorized       = errors.New("transformed traffic has no authorized egress binding")
)

type egressGroupSource struct {
	valid     func(string) bool
	available func() []string
}

type egressGroupRegistry struct {
	current atomic.Pointer[egressGroupSource]
}

func (r *egressGroupRegistry) set(valid func(string) bool, available func() []string) {
	if r == nil {
		return
	}
	if valid == nil {
		r.current.Store(nil)
		return
	}
	r.current.Store(&egressGroupSource{valid: valid, available: available})
}

func (r *egressGroupRegistry) valid(name string) bool {
	if name == "" {
		return true
	}
	if r == nil {
		// Unit-assembled engines predate the live mihomo binding. Production
		// engines always install a source before they are published.
		return true
	}
	source := r.current.Load()
	return source != nil && source.valid != nil && source.valid(name)
}

func (r *egressGroupRegistry) available() []string {
	if r == nil {
		return []string{}
	}
	source := r.current.Load()
	if source == nil || source.available == nil {
		return []string{}
	}
	groups := source.available()
	out := append(make([]string, 0, len(groups)), groups...)
	sort.Strings(out)
	return out
}

// SetEgressGroupSource installs the live, narrow view of mihomo egress groups.
// The source must expose only DIRECT and real proxy groups, never leaf nodes.
func (e *Engine) SetEgressGroupSource(valid func(string) bool, available func() []string) {
	if e == nil {
		return
	}
	if e.egressGroups == nil {
		e.egressGroups = &egressGroupRegistry{}
	}
	e.egressGroups.set(valid, available)
}

// SetTrafficPolicyChangeCallback installs a notification used to invalidate
// decisions cached outside the engine, notably DNS steering answers.
func (e *Engine) SetTrafficPolicyChangeCallback(callback func()) {
	if e != nil {
		e.trafficChanged = callback
	}
}

// SetClientBoundarySource installs the live mihomo fixed-prefix readiness
// check. It is set before the engine is published and read lock-free afterward.
func (e *Engine) SetClientBoundarySource(ready func() bool) {
	if e != nil {
		e.clientBoundaryReady = ready
	}
}

func (e *Engine) clientBoundaryIsReady() bool {
	return e == nil || e.clientBoundaryReady == nil || e.clientBoundaryReady()
}

// InvalidateEgressTransports retires every idle upstream connection after the
// live mihomo group set changes. In-flight work may finish, but a later request
// cannot reuse a connection authorized under the removed group.
func (e *Engine) InvalidateEgressTransports() {
	if e != nil && e.proxy != nil {
		e.proxy.closeUpstreamTransports()
	}
}

// AvailableEgressGroups returns the operator choices accepted by this engine.
func (e *Engine) AvailableEgressGroups() []string {
	if e == nil {
		return []string{}
	}
	return e.egressGroups.available()
}

func (e *Engine) validEgressGroup(name string) bool {
	return e == nil || e.egressGroups.valid(name)
}

func (e *Engine) moduleEgressReady(module Module) bool {
	if !module.Enabled || module.EgressGroupRequired && module.EgressGroup == "" {
		return false
	}
	return module.EgressGroup == "" || e.validEgressGroup(module.EgressGroup)
}

func (e *Engine) readyCaptureHostPatterns(cfg Config) []string {
	patterns := make([]string, 0)
	if !cfg.MITM.Enabled || !e.clientBoundaryIsReady() {
		return patterns
	}
	policy, err := trafficPolicyForConfig(cfg)
	if err != nil {
		return patterns
	}
	byID := make(map[string]Module, len(cfg.Modules))
	for _, module := range cfg.Modules {
		byID[module.ID] = module
	}
	seen := make(map[string]struct{})
	for _, id := range cfg.ExecutionOrder {
		module, exists := byID[id]
		if !exists || !module.Enabled {
			continue
		}
		moduleReady := e.moduleEgressReady(module)
		for _, pattern := range module.CaptureHosts {
			if _, duplicate := seen[pattern]; duplicate {
				continue
			}
			seen[pattern] = struct{}{}
			probe := pattern
			if strings.HasPrefix(pattern, "*.") {
				probe = "runtime-ready." + strings.TrimPrefix(pattern, "*.")
			}
			if moduleReady && e.captureDestinationReady(policy, probe) {
				patterns = append(patterns, pattern)
			}
		}
	}
	return uniqueSorted(patterns)
}

func (e *Engine) captureDestinationReady(policy *compiledTrafficPolicy, host string) bool {
	metadata := &C.Metadata{Type: C.INNER, NetWork: C.TCP, Host: canonicalHost(host), DstPort: 443}
	_, matched, err := e.selectDestinationEgress(policy, metadata)
	return matched && err == nil
}

// TrafficPolicy exposes the immutable runtime policy backed by the engine's
// atomically published configuration snapshot.
func (e *Engine) TrafficPolicy() C.TrafficPolicy {
	if e == nil {
		return nil
	}
	return e
}

var _ C.TrafficPolicy = (*Engine)(nil)

// ClientPolicyActive reports whether the fixed-prefix boundary is needed for
// this snapshot. With the master off, ordinary mihomo routing is untouched.
func (e *Engine) ClientPolicyActive() bool {
	policy, err := e.compiledTrafficPolicy()
	return err == nil && policy.enabled && (len(policy.client) > 0 || len(policy.egress) > 0)
}

type compiledClientTrafficRule struct {
	action       C.ClientRouteAction
	domain       string
	domainSuffix string
	prefix       netip.Prefix
	keywordsAny  []string
	keywordsAll  []string
	network      C.NetWork
	port         uint16
}

type clientTrafficInput struct {
	host    string
	dstIP   netip.Addr
	network C.NetWork
	port    uint16
}

func (r compiledClientTrafficRule) matches(input clientTrafficInput) bool {
	if r.network != C.ALLNet && r.network != input.network {
		return false
	}
	if r.port != 0 && r.port != input.port {
		return false
	}
	if len(r.keywordsAny) > 0 {
		matched := false
		for _, keyword := range r.keywordsAny {
			if strings.Contains(input.host, keyword) {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}
	for _, keyword := range r.keywordsAll {
		if !strings.Contains(input.host, keyword) {
			return false
		}
	}
	switch {
	case r.domain != "":
		return input.host == r.domain
	case r.domainSuffix != "":
		return input.host == r.domainSuffix || strings.HasSuffix(input.host, "."+r.domainSuffix)
	case r.prefix.IsValid():
		return input.dstIP.IsValid() && r.prefix.Contains(input.dstIP.Unmap())
	default:
		return input.host != ""
	}
}

type compiledModuleEgress struct {
	id           string
	group        string
	required     bool
	network      bool
	captureHosts *compiledHostMatcher
	mappingHosts map[string]struct{}
	mappingIPs   map[netip.Addr]struct{}
}

func (m compiledModuleEgress) authorizes(metadata *C.Metadata, allowNetwork bool) bool {
	if metadata == nil || metadata.DstPort == 0 {
		return false
	}
	if allowNetwork && m.network {
		return metadata.Valid()
	}
	if metadata.NetWork != C.TCP {
		return false
	}
	if metadata.DstPort != 80 && metadata.DstPort != 443 {
		return false
	}
	host := canonicalHost(metadata.RuleHost())
	if host != "" {
		if m.captureHosts.matchCanonical(host) {
			return true
		}
		_, exists := m.mappingHosts[host]
		return exists
	}
	if !metadata.DstIP.IsValid() {
		return false
	}
	_, exists := m.mappingIPs[metadata.DstIP.Unmap()]
	return exists
}

type compiledTrafficPolicy struct {
	enabled    bool
	client     []compiledClientTrafficRule
	egress     []compiledModuleEgress
	egressByID map[string]int
}

func compileTrafficPolicy(cfg Config) (*compiledTrafficPolicy, error) {
	policy := &compiledTrafficPolicy{
		enabled:    cfg.MITM.Enabled,
		client:     make([]compiledClientTrafficRule, 0),
		egress:     make([]compiledModuleEgress, 0),
		egressByID: make(map[string]int),
	}
	byID := make(map[string]Module, len(cfg.Modules))
	for _, module := range cfg.Modules {
		byID[module.ID] = module
	}
	for _, id := range cfg.ExecutionOrder {
		module, exists := byID[id]
		if !exists || !module.Enabled {
			continue
		}
		for index, rule := range module.RoutingRules {
			compiled, err := compileClientTrafficRule(rule)
			if err != nil {
				return nil, fmt.Errorf("extension %q routing rule %d: %w", module.ID, index, err)
			}
			policy.client = append(policy.client, compiled)
		}
		binding := compiledModuleEgress{
			id:           module.ID,
			group:        module.EgressGroup,
			required:     module.EgressGroupRequired,
			network:      module.Network,
			captureHosts: newCompiledHostMatcher(module.CaptureHosts),
			mappingHosts: make(map[string]struct{}),
			mappingIPs:   make(map[netip.Addr]struct{}),
		}
		for _, mapping := range module.HostMappings {
			if mapping.resolverForm() {
				continue
			}
			target := canonicalHost(mapping.Target)
			if address, err := netip.ParseAddr(target); err == nil {
				binding.mappingIPs[address.Unmap()] = struct{}{}
			} else if target != "" {
				binding.mappingHosts[target] = struct{}{}
			}
		}
		policy.egressByID[module.ID] = len(policy.egress)
		policy.egress = append(policy.egress, binding)
	}
	return policy, nil
}

func compileClientTrafficRule(rule RoutingRule) (compiledClientTrafficRule, error) {
	compiled := compiledClientTrafficRule{network: C.ALLNet}
	switch rule.Action {
	case "direct":
		compiled.action = C.ClientRouteDirect
	case "reject":
		compiled.action = C.ClientRouteReject
	default:
		return compiledClientTrafficRule{}, errors.New("unsupported action")
	}
	if rule.Domain != nil {
		compiled.domain = *rule.Domain
	}
	if rule.DomainSuffix != nil {
		compiled.domainSuffix = *rule.DomainSuffix
	}
	if rule.IPCIDR != nil {
		prefix, err := netip.ParsePrefix(*rule.IPCIDR)
		if err != nil {
			return compiledClientTrafficRule{}, fmt.Errorf("invalid CIDR: %w", err)
		}
		compiled.prefix = prefix.Masked()
	}
	if rule.DomainKeywords != nil {
		compiled.keywordsAny = append([]string(nil), (*rule.DomainKeywords)...)
	}
	if rule.AllDomainKeywords != nil {
		compiled.keywordsAll = append([]string(nil), (*rule.AllDomainKeywords)...)
	}
	if rule.Network != nil {
		switch *rule.Network {
		case "tcp":
			compiled.network = C.TCP
		case "udp":
			compiled.network = C.UDP
		default:
			return compiledClientTrafficRule{}, errors.New("unsupported network")
		}
	}
	if rule.DestinationPort != nil {
		compiled.port = uint16(*rule.DestinationPort)
	}
	return compiled, nil
}

func (e *Engine) compiledTrafficPolicy() (*compiledTrafficPolicy, error) {
	if e == nil || e.config == nil {
		return nil, errTrafficPolicyUnavailable
	}
	cfg, err := e.config.Current()
	if err != nil {
		return nil, err
	}
	return trafficPolicyForConfig(cfg)
}

func trafficPolicyForConfig(cfg Config) (*compiledTrafficPolicy, error) {
	if cfg.runtime != nil && cfg.runtime.traffic != nil {
		return cfg.runtime.traffic, nil
	}
	return compileTrafficPolicy(cfg)
}

// RouteClient evaluates reviewed global rules in extension execution order.
func (e *Engine) RouteClient(metadata *C.Metadata) C.ClientRouteAction {
	if metadata == nil || metadata.Type == C.INNER {
		return C.ClientRouteNone
	}
	policy, err := e.compiledTrafficPolicy()
	if err != nil || !policy.enabled {
		return C.ClientRouteNone
	}
	input := clientTrafficInput{
		host: canonicalHost(metadata.RuleHost()), dstIP: metadata.DstIP,
		network: metadata.NetWork, port: metadata.DstPort,
	}
	for _, rule := range policy.client {
		if rule.matches(input) {
			return rule.action
		}
	}
	// A cached gateway answer can outlive an out-of-band group removal. Do not
	// let that traffic fall through to ordinary routing after capture readiness
	// has been withdrawn; reject it until the selected group returns.
	if input.network == C.TCP && (input.port == 80 || input.port == 443) {
		for _, binding := range policy.egress {
			if !binding.captureHosts.matchCanonical(input.host) {
				continue
			}
			if !e.clientBoundaryIsReady() ||
				binding.required && binding.group == "" ||
				binding.group != "" && !e.validEgressGroup(binding.group) {
				return C.ClientRouteReject
			}
			if _, matched, err := e.selectDestinationEgress(policy, metadata); !matched || err != nil {
				return C.ClientRouteReject
			}
			break
		}
	}
	return C.ClientRouteNone
}

// SelectEgress resolves one transformed flow to operator-owned state.
func (e *Engine) SelectEgress(metadata *C.Metadata, owner string, ownerOnly bool) (string, error) {
	if metadata == nil || metadata.Type != C.INNER {
		return "", fmt.Errorf("%w: egress is only valid for INNER traffic", errEgressUnauthorized)
	}
	policy, err := e.compiledTrafficPolicy()
	if err != nil {
		return "", err
	}
	if !policy.enabled {
		return "", fmt.Errorf("%w: interception is disabled", errEgressUnauthorized)
	}
	if ownerOnly {
		index, exists := policy.egressByID[owner]
		if !exists || !policy.egress[index].authorizes(metadata, true) {
			return "", fmt.Errorf("%w: extension %q does not authorize %s", errEgressUnauthorized, owner, metadata.RemoteAddress())
		}
		return e.selectModuleEgress(policy.egress[index])
	}
	if group, matched, err := e.selectDestinationEgress(policy, metadata); matched || err != nil {
		return group, err
	}
	// A cross-origin main request carries the module that authorized its broad
	// network target, but destination bindings still get first refusal above.
	if owner != "" {
		index, exists := policy.egressByID[owner]
		if !exists || !policy.egress[index].authorizes(metadata, true) {
			return "", fmt.Errorf("%w: extension %q does not authorize %s", errEgressUnauthorized, owner, metadata.RemoteAddress())
		}
		return e.selectModuleEgress(policy.egress[index])
	}
	return "", fmt.Errorf("%w: %s", errEgressUnauthorized, metadata.RemoteAddress())
}

func (e *Engine) selectDestinationEgress(policy *compiledTrafficPolicy, metadata *C.Metadata) (string, bool, error) {
	if policy == nil {
		return "", false, errTrafficPolicyUnavailable
	}
	// Explicit bindings win over the terminal operator route. Execution order
	// resolves overlaps within each tier.
	for _, bound := range []bool{true, false} {
		for _, binding := range policy.egress {
			if (binding.group != "") != bound || !binding.authorizes(metadata, false) {
				continue
			}
			group, err := e.selectModuleEgress(binding)
			return group, true, err
		}
	}
	return "", false, nil
}

func (e *Engine) selectModuleEgress(binding compiledModuleEgress) (string, error) {
	if binding.required && binding.group == "" {
		return "", fmt.Errorf("%w: extension %q requires an egress group", errEgressUnauthorized, binding.id)
	}
	if binding.group != "" && !e.validEgressGroup(binding.group) {
		return "", fmt.Errorf("%w: extension %q egress group %q is unavailable", errEgressUnauthorized, binding.id, binding.group)
	}
	return binding.group, nil
}
