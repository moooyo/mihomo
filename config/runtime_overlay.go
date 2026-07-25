package config

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/metacubex/mihomo/component/overlay"
	C "github.com/metacubex/mihomo/constant"
	RC "github.com/metacubex/mihomo/rules/common"
	T "github.com/metacubex/mihomo/tunnel"
)

// OverlayProcessorKey is the proxy-level flag that marks an outbound as an
// external traffic processor.
//
// It is read straight off the raw mapping rather than plumbed through
// outbound.BasicOption because the only thing that has to know is the config
// layer, and adding a field to all thirty proxy constructors would put a
// rebase burden on the highest-churn directory in the tree for no gain.
const OverlayProcessorKey = "runtime-overlay-processor"

// unwrapRule strips the statistics/disable decorator that top-level rules
// carry, so a caller can inspect the concrete rule underneath.
func unwrapRule(r C.Rule) C.Rule {
	if w, ok := r.(C.RuleWrapper); ok {
		return w.Unwrap()
	}
	return r
}

// anchorLayout is where the two anchors sit in a rule list and what the layout
// implies about which listeners carry processor traffic.
type anchorLayout struct {
	Owner string
	// EgressIndex and ClientIndex are indices into the top-level rule list.
	EgressIndex int
	ClientIndex int
	// EgressListeners are the inbound names named by the terminator that must
	// immediately follow the egress anchor. They are derived from the config
	// rather than hardcoded: the terminator is the config's own declaration of
	// which listener carries processor-originated traffic.
	EgressListeners []string
	// Present is false when the rule list contains no anchors at all.
	Present bool
}

const (
	denyReject     = "REJECT"
	denyRejectDrop = "REJECT-DROP"
)

func isDenyAdapter(name string) bool {
	return name == denyReject || name == denyRejectDrop
}

// findAnchorLayout locates the anchors and checks the structural invariants
// that make them enforceable.
//
// The required layout is exactly the one Section 6.2 describes:
//
//	<deny-only system guards>
//	RUNTIME-OVERLAY,<owner>,egress
//	IN-NAME,<processor listener>,REJECT
//	<deny-only system guards>
//	RUNTIME-OVERLAY,<owner>,client
//	<operator rules and terminal MATCH>
//
// "Deny-only" before the egress anchor is stricter than the review's "deny or
// qualified so it cannot match processor traffic". The stricter form is chosen
// because the weaker one is not decidable: a rule matching on an arbitrary
// hostname cannot be proven unreachable by processor traffic without
// enumerating hostnames. An operator whose allow rule must stay simply moves it
// below the terminator, where the terminator already denies processor traffic
// to it — which is the fix the review asks for anyway.
func findAnchorLayout(rules []C.Rule) (anchorLayout, error) {
	var layout anchorLayout
	egressIdx, clientIdx := -1, -1

	for i, r := range rules {
		a, ok := unwrapRule(r).(*RC.RuntimeOverlay)
		if !ok {
			continue
		}
		switch a.Stage() {
		case overlay.StageEgress:
			if egressIdx >= 0 {
				return layout, fmt.Errorf("%w: duplicate egress anchor at rule %d (first at %d)", overlay.ErrAnchorInvalid, i, egressIdx)
			}
			egressIdx = i
		case overlay.StageClient:
			if clientIdx >= 0 {
				return layout, fmt.Errorf("%w: duplicate client anchor at rule %d (first at %d)", overlay.ErrAnchorInvalid, i, clientIdx)
			}
			clientIdx = i
		}
		if layout.Owner == "" {
			layout.Owner = a.Owner()
		} else if layout.Owner != a.Owner() {
			return layout, fmt.Errorf("%w: anchors name different owners (%q and %q)", overlay.ErrAnchorInvalid, layout.Owner, a.Owner())
		}
	}

	if egressIdx < 0 && clientIdx < 0 {
		return layout, nil
	}
	if egressIdx < 0 {
		return layout, fmt.Errorf("%w: the client anchor is present but the egress anchor is missing", overlay.ErrAnchorInvalid)
	}
	if clientIdx < 0 {
		return layout, fmt.Errorf("%w: the egress anchor is present but the client anchor is missing", overlay.ErrAnchorInvalid)
	}
	if clientIdx < egressIdx {
		return layout, fmt.Errorf("%w: the client anchor (rule %d) must come after the egress anchor (rule %d)", overlay.ErrAnchorInvalid, clientIdx, egressIdx)
	}

	// The terminator must be the very next rule. Any gap is a rule that
	// processor traffic reaches after failing the overlay's capability check
	// but before being denied.
	if egressIdx+1 >= len(rules) {
		return layout, fmt.Errorf("%w: the egress anchor is the last rule; it must be immediately followed by an IN-NAME deny terminator", overlay.ErrAnchorInvalid)
	}
	term := unwrapRule(rules[egressIdx+1])
	if term.RuleType() != C.InName || !isDenyAdapter(term.Adapter()) {
		return layout, fmt.Errorf("%w: rule %d must be an IN-NAME deny terminator immediately after the egress anchor, found %s -> %s",
			overlay.ErrAnchorInvalid, egressIdx+1, term.RuleType(), term.Adapter())
	}
	layout.EgressListeners = strings.Split(term.Payload(), "/")

	for i := 0; i < egressIdx; i++ {
		if !isDenyAdapter(unwrapRule(rules[i]).Adapter()) {
			return layout, fmt.Errorf("%w: rule %d (%s -> %s) precedes the egress anchor but is not a deny rule; "+
				"a processor-originated connection would reach it without ever meeting the anchor. Move it below the IN-NAME terminator",
				overlay.ErrAnchorInvalid, i, unwrapRule(rules[i]).RuleType(), unwrapRule(rules[i]).Adapter())
		}
	}
	for i := egressIdx + 2; i < clientIdx; i++ {
		if !isDenyAdapter(unwrapRule(rules[i]).Adapter()) {
			return layout, fmt.Errorf("%w: rule %d (%s -> %s) sits between the egress terminator and the client anchor; "+
				"only deny system guards may occupy that slot",
				overlay.ErrAnchorInvalid, i, unwrapRule(rules[i]).RuleType(), unwrapRule(rules[i]).Adapter())
		}
	}

	layout.EgressIndex = egressIdx
	layout.ClientIndex = clientIdx
	layout.Present = true
	return layout, nil
}

// validateRuntimeOverlay enforces the anchor layout and the bypass closure.
//
// It runs at the end of ParseRawConfig because that is the only point where
// rules, listeners, tunnels, hosts, sniffer and mode are all populated —
// parseRules runs well before tunnels are even parsed.
//
// requireAnchors is true when a generation is persisted. In that case a config
// without anchors is refused outright: applying it would leave the process
// enforcing a durable overlay it has no way to evaluate.
func validateRuntimeOverlay(rawCfg *RawConfig, cfg *Config, requireAnchors bool) error {
	layout, err := findAnchorLayout(cfg.Rules)
	if err != nil {
		return err
	}
	for name, sub := range cfg.SubRules {
		for i, r := range sub {
			if _, ok := unwrapRule(r).(*RC.RuntimeOverlay); ok {
				return fmt.Errorf("%w: sub-rule %q entry %d is an overlay anchor; anchors are only valid in the top-level rule list",
					overlay.ErrAnchorInvalid, name, i)
			}
		}
	}

	if !layout.Present {
		if requireAnchors {
			return fmt.Errorf("%w: a runtime-overlay generation is persisted but this configuration declares no anchors", overlay.ErrAnchorInvalid)
		}
		return nil
	}

	// From here on the configuration opts into the overlay, so the whole
	// closure applies whether or not a generation happens to be active. A
	// config that cannot enforce the anchors must not be applied and then
	// discovered to be unsafe at commit time.
	if cfg.General.Mode != T.Rule {
		return fmt.Errorf("%w: mode is %s; the runtime overlay is only enforceable in rule mode, because Direct and Global return before any rule is evaluated",
			overlay.ErrModeConflict, cfg.General.Mode)
	}

	if err := validateOverlayListeners(rawCfg); err != nil {
		return err
	}
	if err := validateOverlayTunnels(cfg); err != nil {
		return err
	}
	if err := validateOverlayBypassOutbounds(cfg); err != nil {
		return err
	}
	return nil
}

// validateOverlayListeners refuses any listener-level routing override.
//
// A listener's `proxy:` and `rule:` fields become metadata.SpecialProxy and
// metadata.SpecialRules, both of which short-circuit before the anchored rule
// list is ever consulted. The check is deliberately global rather than scoped
// to "in-scope" listeners: mihomo cannot know which listeners the coordinator
// considers client ingress, and a global refusal is both enforceable and
// trivially satisfiable.
func validateOverlayListeners(rawCfg *RawConfig) error {
	for i, mapping := range rawCfg.Listeners {
		name, _ := normalizedKey(mapping, "name").(string)
		if name == "" {
			name = fmt.Sprintf("#%d", i)
		}
		for _, key := range []string{"proxy", "rule"} {
			if v := normalizedKey(mapping, key); v != nil && v != "" {
				return fmt.Errorf("%w: listener %s sets %q=%v, which bypasses rule matching entirely while the runtime overlay is enabled",
					overlay.ErrModeConflict, name, key, v)
			}
		}
	}
	return nil
}

// validateOverlayTunnels refuses a top-level tunnels: entry with a proxy
// target.
//
// This carrier deserves its own check because it is a single token away from a
// total bypass: LC.Tunnel's compact string form accepts
// "tcp,addr,target,proxyname" and the optional fourth field silently becomes
// Proxy, which sets SpecialProxy unconditionally on every accepted connection.
func validateOverlayTunnels(cfg *Config) error {
	for i, t := range cfg.Tunnels {
		if t.Proxy != "" {
			return fmt.Errorf("%w: tunnels[%d] (%s -> %s) targets proxy %q, which bypasses rule matching entirely while the runtime overlay is enabled",
				overlay.ErrModeConflict, i, t.Address, t.Target, t.Proxy)
		}
	}
	return nil
}

// validateOverlayBypassOutbounds refuses routing primitives that can re-enter
// matching outside the anchored list.
//
// A rematch outbound sets RematchName or SpecialRules from inside an otherwise
// ordinary match result, and a PASS-RULE target escapes a sub-rule list. Both
// are reachable without any listener-level configuration, so blocking the
// listener carriers alone is not sufficient.
func validateOverlayBypassOutbounds(cfg *Config) error {
	for name, p := range cfg.Proxies {
		if p.Type() == C.Rematch {
			return fmt.Errorf("%w: proxy %q is a rematch outbound, which can redirect matching into a rule list that contains no anchors",
				overlay.ErrModeConflict, name)
		}
	}
	for i, r := range cfg.Rules {
		if unwrapRule(r).Adapter() == "PASS-RULE" {
			return fmt.Errorf("%w: rule %d targets PASS-RULE, which re-enters matching outside the anchored list", overlay.ErrModeConflict, i)
		}
	}
	for name, sub := range cfg.SubRules {
		for i, r := range sub {
			if unwrapRule(r).Adapter() == "PASS-RULE" {
				return fmt.Errorf("%w: sub-rule %q entry %d targets PASS-RULE, which re-enters matching outside the anchored list",
					overlay.ErrModeConflict, name, i)
			}
		}
	}
	return nil
}

// normalizedKey reads a mapping key tolerating the underscore/dash spelling the
// listener decoder normalises.
func normalizedKey(mapping map[string]any, key string) any {
	if v, ok := mapping[key]; ok {
		return v
	}
	alt := strings.ReplaceAll(key, "-", "_")
	if v, ok := mapping[alt]; ok {
		return v
	}
	return nil
}

// validateOverlayProcessorIsolation rejects the remaining routes by which a
// processor target could become ordinary selectable policy.
//
// Withholding the name from AllProxies and proxyList closes the automatic
// paths — GLOBAL, include-all groups, the reserved provider. It does not close
// the explicit ones: a group can still name the processor in its literal
// proxies list, and a dialer-proxy edge can still chain through it.
func validateOverlayProcessorIsolation(cfg *RawConfig, processors map[string]struct{}) error {
	if len(processors) == 0 {
		return nil
	}
	isProcessor := func(name string) bool {
		_, ok := processors[name]
		return ok
	}

	for i, mapping := range cfg.ProxyGroup {
		groupName, _ := mapping["name"].(string)
		if groupName == "" {
			groupName = fmt.Sprintf("#%d", i)
		}
		for _, key := range []string{"proxies", "empty-fallback"} {
			switch v := normalizedKey(mapping, key).(type) {
			case string:
				if isProcessor(v) {
					return fmt.Errorf("%w: proxy group %q names the runtime-overlay processor %q in %s", overlay.ErrModeConflict, groupName, v, key)
				}
			case []any:
				for _, item := range v {
					if s, ok := item.(string); ok && isProcessor(s) {
						return fmt.Errorf("%w: proxy group %q names the runtime-overlay processor %q in %s", overlay.ErrModeConflict, groupName, s, key)
					}
				}
			}
		}
	}

	for i, mapping := range cfg.Proxy {
		name, _ := mapping["name"].(string)
		if name == "" {
			name = fmt.Sprintf("#%d", i)
		}
		dialer, _ := normalizedKey(mapping, "dialer-proxy").(string)
		if dialer == "" {
			continue
		}
		if isProcessor(dialer) {
			return fmt.Errorf("%w: proxy %q chains through the runtime-overlay processor %q via dialer-proxy", overlay.ErrModeConflict, name, dialer)
		}
		if isProcessor(name) {
			return fmt.Errorf("%w: runtime-overlay processor %q sets dialer-proxy %q; a processor must dial directly", overlay.ErrModeConflict, name, dialer)
		}
	}
	return nil
}

// overlayProcessorNames returns the proxies flagged as external processors.
//
// A flagged proxy stays in the proxies map so rules can still target it, but is
// withheld from both AllProxies and proxyList. Withholding from only one is a
// common mistake with a silent failure mode: AllProxies feeds
// include-all-proxies groups, while proxyList feeds the reserved compatible
// provider and the auto-created GLOBAL selector.
func overlayProcessorNames(cfg *RawConfig) map[string]struct{} {
	out := map[string]struct{}{}
	for _, mapping := range cfg.Proxy {
		flag, _ := normalizedKey(mapping, OverlayProcessorKey).(bool)
		if !flag {
			continue
		}
		if name, ok := mapping["name"].(string); ok && name != "" {
			out[name] = struct{}{}
		}
	}
	return out
}

// OverlayClosureDigest computes the core configuration revision input.
//
// It must be taken before parseProxies runs, because proxyGroupsDagSort
// reorders the proxy-group slice in place: the same YAML would otherwise hash
// differently depending on its dependency topology.
func OverlayClosureDigest(cfg *RawConfig) (overlay.DependencyClosureDigest, error) {
	groups := append([]map[string]any(nil), cfg.ProxyGroup...)
	sort.SliceStable(groups, func(i, j int) bool {
		a, _ := groups[i]["name"].(string)
		b, _ := groups[j]["name"].(string)
		return a < b
	})

	providers := make(map[string]any, len(cfg.ProxyProvider))
	for k, v := range cfg.ProxyProvider {
		providers[k] = v
	}

	hosts := make(map[string]any, len(cfg.Hosts))
	for k, v := range cfg.Hosts {
		hosts[k] = v
	}

	part := func(v any) (string, error) {
		raw, err := json.Marshal(v)
		if err != nil {
			return "", fmt.Errorf("overlay closure: %w", err)
		}
		return overlay.HashStrings("closure-part/v1", string(raw)), nil
	}

	var (
		d   overlay.DependencyClosureDigest
		err error
	)
	d.Mode = overlay.HashStrings("closure-mode/v1", cfg.Mode.String())
	if d.Sniffer, err = part(cfg.Sniffer); err != nil {
		return d, err
	}
	if d.Listeners, err = part(cfg.Listeners); err != nil {
		return d, err
	}
	if d.Tunnels, err = part(cfg.Tunnels); err != nil {
		return d, err
	}
	if d.Hosts, err = part(hosts); err != nil {
		return d, err
	}
	if d.Rules, err = part(struct {
		Rules    []string            `json:"rules"`
		SubRules map[string][]string `json:"subRules"`
	}{cfg.Rule, cfg.SubRules}); err != nil {
		return d, err
	}
	if d.Groups, err = part(struct {
		Groups    []map[string]any `json:"groups"`
		Providers map[string]any   `json:"providers"`
		Proxies   []map[string]any `json:"proxies"`
	}{groups, providers, cfg.Proxy}); err != nil {
		return d, err
	}
	if d.Resolver, err = part(cfg.DNS); err != nil {
		return d, err
	}
	return d, nil
}

// HasOverlayAnchors reports whether the rule list carries both anchors for an
// owner. Structural validity is checked separately by findAnchorLayout; this is
// only the presence question, which the executor asks after recovery.
func HasOverlayAnchors(rules []C.Rule, owner string) bool {
	var client, egress bool
	for _, r := range rules {
		a, ok := unwrapRule(r).(*RC.RuntimeOverlay)
		if !ok || a.Owner() != owner {
			continue
		}
		switch a.Stage() {
		case overlay.StageClient:
			client = true
		case overlay.StageEgress:
			egress = true
		}
	}
	return client && egress
}
