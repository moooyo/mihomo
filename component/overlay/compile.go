package overlay

import (
	"fmt"
	"net/netip"
	"strings"

	"github.com/metacubex/mihomo/component/wildcard"
)

// MatchInput is the minimal projection of connection metadata the overlay
// needs. Taking a narrow struct rather than the full metadata keeps this
// package a leaf that the rule and tunnel layers depend on, and makes the
// matcher independently testable without constructing a connection.
type MatchInput struct {
	// Host is the routing hostname, already lowercased by the caller. It is
	// empty for a connection whose destination is a bare address.
	Host string
	// DstIP is the destination address if one is already known. The overlay
	// never triggers a resolution to fill it in: doing so would leak the
	// destination to the resolver before the policy decision is made.
	DstIP   netip.Addr
	DstPort uint16
	Network Network
	// InName is the inbound listener name, used by the egress stage to confirm
	// a request really arrived on the processor's own listener.
	InName string
	// InUser is the authenticated inbound credential, which is the opaque
	// egress capability the processor presents.
	InUser string
}

type compiledRule struct {
	kind      SelectorKind
	value     string
	dotSuffix string // "." + value, precomputed for the suffix test
	prefix    netip.Prefix
	network   Network
	ports     []PortRange
	// keywordsAny requires at least one match; keywordsAll requires all of
	// them. Both are lowercased at compile time so matching is a plain
	// substring scan.
	keywordsAny []string
	keywordsAll []string
	action      ClientAction
	// target is the resolved proxy name for a capture rule.
	target string
}

// matchesKeywords applies the keyword constraints.
//
// Constraints, not alternatives: they narrow whatever the primary selector
// already matched. A rule with keywords and no host to test them against does
// not match, because "unknown" is not "satisfied".
func (r *compiledRule) matchesKeywords(host string) bool {
	if len(r.keywordsAny) == 0 && len(r.keywordsAll) == 0 {
		return true
	}
	if host == "" {
		return false
	}
	if len(r.keywordsAny) > 0 {
		hit := false
		for _, kw := range r.keywordsAny {
			if strings.Contains(host, kw) {
				hit = true
				break
			}
		}
		if !hit {
			return false
		}
	}
	for _, kw := range r.keywordsAll {
		if !strings.Contains(host, kw) {
			return false
		}
	}
	return true
}

func (r *compiledRule) matches(in *MatchInput) bool {
	if r.network != NetworkAny && r.network != in.Network {
		return false
	}
	if len(r.ports) > 0 {
		ok := false
		for _, p := range r.ports {
			if p.Contains(in.DstPort) {
				ok = true
				break
			}
		}
		if !ok {
			return false
		}
	}
	if !r.matchesKeywords(in.Host) {
		return false
	}
	switch r.kind {
	case SelectorDomain:
		return in.Host != "" && in.Host == r.value
	case SelectorDomainSuffix:
		return in.Host != "" && (in.Host == r.value || strings.HasSuffix(in.Host, r.dotSuffix))
	case SelectorDomainKeyword:
		return in.Host != "" && strings.Contains(in.Host, r.value)
	case SelectorDomainWildcard:
		return in.Host != "" && wildcard.Match(r.value, in.Host)
	case SelectorIPCIDR:
		// Deliberately no-resolve. An unresolved destination simply does not
		// match an address rule.
		if !in.DstIP.IsValid() {
			return false
		}
		return r.prefix.Contains(in.DstIP.Unmap())
	case SelectorAny:
		// The keyword constraints above already did the work, and validation
		// guarantees there is at least one. A hostname is still required: a
		// bare-address connection has nothing to match keywords against.
		return in.Host != ""
	}
	return false
}

// ClientDecision is the result of evaluating the client stage.
type ClientDecision struct {
	// Matched is false when no client rule applied, in which case rule
	// resolution continues past the anchor into the operator's own rules.
	Matched bool
	Action  ClientAction
	// Target is the processor proxy name when Action is capture.
	Target string
	// RuleIndex is the index of the matching rule, for diagnostics.
	RuleIndex int
}

// CompiledClient is the immutable, ready-to-match client stage of one
// generation.
type CompiledClient struct {
	rules []compiledRule
}

// Len reports the compiled rule count.
func (c *CompiledClient) Len() int {
	if c == nil {
		return 0
	}
	return len(c.rules)
}

// Match walks the client stage in submission order and returns the first hit.
// First-match is the whole contract here: the coordinator orders extension
// rules deliberately and a reordering is a different policy with a different
// digest.
func (c *CompiledClient) Match(in *MatchInput) ClientDecision {
	if c == nil {
		return ClientDecision{}
	}
	for i := range c.rules {
		if c.rules[i].matches(in) {
			return ClientDecision{
				Matched:   true,
				Action:    c.rules[i].action,
				Target:    c.rules[i].target,
				RuleIndex: i,
			}
		}
	}
	return ClientDecision{}
}

// compiledBinding is one destination-scoped egress decision with its allowlist
// reduced to matchers.
type compiledBinding struct {
	binding      EgressBinding
	destinations []compiledRule
}

func (b *compiledBinding) permits(in *MatchInput) bool {
	for i := range b.destinations {
		if b.destinations[i].matches(in) {
			return true
		}
	}
	return false
}

// compiledCapability is one capability with every binding's allowlist reduced
// to matchers.
type compiledCapability struct {
	capability EgressCapability
	bindings   []compiledBinding
}

// resolve reports which binding, if any, authorizes the requested endpoint.
//
// The allowlist is the endpoint half of "a capability constrains endpoint and
// egress". Without it a capability would authorize the operator's egress group
// for any destination at all, which is strictly more than the per-destination
// rules it replaces granted.
//
// First match wins. The coordinator emits disjoint destination sets so no
// endpoint should reach a second binding, but the order is honoured rather than
// assumed away: a policy whose outcome depends on iteration order is not one.
func (c *compiledCapability) resolve(in *MatchInput) (EgressBinding, bool) {
	for i := range c.bindings {
		if c.bindings[i].permits(in) {
			return c.bindings[i].binding, true
		}
	}
	return EgressBinding{}, false
}

// CompiledEgress is the immutable capability table of one generation.
type CompiledEgress struct {
	byID map[string]*compiledCapability
}

// Lookup resolves an opaque capability. A capability that is not in the table
// is not merely unknown, it is unauthorized: the caller must fail closed rather
// than fall through.
func (e *CompiledEgress) Lookup(id string) (EgressCapability, bool) {
	if e == nil || id == "" {
		return EgressCapability{}, false
	}
	c, ok := e.byID[id]
	if !ok {
		return EgressCapability{}, false
	}
	return c.capability, true
}

// authorize resolves a capability and checks it against the request. It returns
// false when the capability is unknown, is presented on the wrong listener, or
// has no binding covering the requested endpoint. The binding it returns is the
// egress decision: the caller must not read a group off the capability, which
// no longer carries one.
func (e *CompiledEgress) authorize(in *MatchInput) (EgressCapability, EgressBinding, bool) {
	if e == nil || in.InUser == "" {
		return EgressCapability{}, EgressBinding{}, false
	}
	c, ok := e.byID[in.InUser]
	if !ok {
		return EgressCapability{}, EgressBinding{}, false
	}
	// The egress stage sits before the client stage. Honouring a capability
	// presented on any other inbound would let an ordinary client skip client
	// matching entirely by authenticating with the credential.
	if c.capability.Listener != "" && c.capability.Listener != in.InName {
		return EgressCapability{}, EgressBinding{}, false
	}
	binding, ok := c.resolve(in)
	if !ok {
		return EgressCapability{}, EgressBinding{}, false
	}
	return c.capability, binding, true
}

// IDs returns the capability identifiers, for readback and for wiring the
// processor listener's authenticator.
func (e *CompiledEgress) IDs() []string {
	if e == nil {
		return nil
	}
	out := make([]string, 0, len(e.byID))
	for id := range e.byID {
		out = append(out, id)
	}
	return out
}

// Compiled is one generation reduced to its matching form. It is built once at
// stage time and never mutated afterwards, so every reader of a published
// snapshot sees a consistent policy without holding a lock.
type Compiled struct {
	Document *Document
	Digests  Digests
	Client   *CompiledClient
	Egress   *CompiledEgress
	// ResolverProfiles is indexed by profile name.
	ResolverProfiles map[string]ResolverProfile
	// ResolverSetDigest lets the commit path detect a resolver profile change
	// without comparing the profiles themselves.
	ResolverSetDigest string
	CapabilitySet     string
}

// Compile validates the document against the live processor declarations and
// reduces it to its matching form.
//
// processorProxies maps a declared processor target name onto the proxy that
// implements it. A capture rule whose processor is not present here cannot be
// enforced, so compilation fails rather than producing an overlay that silently
// falls through to the operator's rules.
func Compile(d *Document, q Quotas, processorProxies map[string]string) (*Compiled, error) {
	if err := d.Validate(q); err != nil {
		return nil, err
	}

	targetByID := make(map[string]string, len(d.ProcessorTargets))
	for _, p := range d.ProcessorTargets {
		if processorProxies != nil {
			if _, ok := processorProxies[p.Name]; !ok {
				return nil, fmt.Errorf("%w: processor target %q names proxy %q, which is not declared as a runtime-overlay processor", ErrDependencyMissing, p.ID, p.Name)
			}
		}
		targetByID[p.ID] = p.Name
	}

	rules := make([]compiledRule, 0, len(d.Client.Rules))
	for i, r := range d.Client.Rules {
		cr := compiledRule{
			kind:        r.Kind,
			network:     r.Network,
			ports:       append([]PortRange(nil), r.Ports...),
			keywordsAny: lowerAll(r.KeywordsAny),
			keywordsAll: lowerAll(r.KeywordsAll),
			action:      r.Action,
		}
		switch r.Kind {
		case SelectorAny:
			// No primary payload to compile.
		case SelectorIPCIDR:
			p, err := netip.ParsePrefix(r.Value)
			if err != nil {
				return nil, fmt.Errorf("%w: client.rules[%d] has an unparsable prefix %q: %s", ErrInvalidDocument, i, r.Value, err)
			}
			cr.prefix = p.Masked()
		default:
			cr.value = strings.ToLower(r.Value)
			cr.dotSuffix = "." + cr.value
		}
		if r.Action == ActionCapture {
			cr.target = targetByID[r.Processor]
		}
		rules = append(rules, cr)
	}

	byID := make(map[string]*compiledCapability, len(d.Egress.Capabilities))
	for _, c := range d.Egress.Capabilities {
		compiledBindings := make([]compiledBinding, 0, len(c.Bindings))
		for b, bind := range c.Bindings {
			compiledDests := make([]compiledRule, 0, len(bind.Destinations))
			for j, dest := range bind.Destinations {
				cr := compiledRule{kind: dest.Kind, ports: append([]PortRange(nil), dest.Ports...)}
				if dest.Kind == SelectorIPCIDR {
					p, err := netip.ParsePrefix(dest.Value)
					if err != nil {
						return nil, fmt.Errorf("%w: capability %q binding %d destination %d has an unparsable prefix %q: %s",
							ErrInvalidDocument, c.ID, b, j, dest.Value, err)
					}
					cr.prefix = p.Masked()
				} else {
					cr.value = strings.ToLower(dest.Value)
					cr.dotSuffix = "." + cr.value
				}
				compiledDests = append(compiledDests, cr)
			}
			compiledBindings = append(compiledBindings, compiledBinding{binding: bind, destinations: compiledDests})
		}
		byID[c.ID] = &compiledCapability{capability: c, bindings: compiledBindings}
	}

	profiles := make(map[string]ResolverProfile, len(d.ResolverProfiles))
	for _, p := range d.ResolverProfiles {
		profiles[p.Name] = p
	}

	// Copy the document so a later mutation of the caller's value cannot reach
	// a published generation.
	doc := *d
	doc.Client.Rules = append([]ClientRule(nil), d.Client.Rules...)
	doc.Egress.Capabilities = append([]EgressCapability(nil), d.Egress.Capabilities...)
	doc.ProcessorTargets = append([]ProcessorTarget(nil), d.ProcessorTargets...)
	doc.ResolverProfiles = append([]ResolverProfile(nil), d.ResolverProfiles...)

	return &Compiled{
		Document:          &doc,
		Digests:           ComputeDigests(&doc),
		Client:            &CompiledClient{rules: rules},
		Egress:            &CompiledEgress{byID: byID},
		ResolverProfiles:  profiles,
		ResolverSetDigest: ResolverProfileSetDigest(doc.ResolverProfiles),
		CapabilitySet:     CapabilitySetDigest(doc.Egress.Capabilities),
	}, nil
}

// lowerAll lowercases a keyword list so matching can be a plain substring scan
// against the already-lowercased host.
func lowerAll(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	out := make([]string, len(in))
	for i, v := range in {
		out[i] = strings.ToLower(v)
	}
	return out
}
