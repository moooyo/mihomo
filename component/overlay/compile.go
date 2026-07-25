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
	action    ClientAction
	// target is the resolved proxy name for a capture rule.
	target string
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

// CompiledEgress is the immutable capability table of one generation.
type CompiledEgress struct {
	byID map[string]EgressCapability
}

// Lookup resolves an opaque capability. A capability that is not in the table
// is not merely unknown, it is unauthorized: the caller must fail closed rather
// than fall through.
func (e *CompiledEgress) Lookup(id string) (EgressCapability, bool) {
	if e == nil || id == "" {
		return EgressCapability{}, false
	}
	c, ok := e.byID[id]
	return c, ok
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
			kind:    r.Kind,
			network: r.Network,
			ports:   append([]PortRange(nil), r.Ports...),
			action:  r.Action,
		}
		switch r.Kind {
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

	byID := make(map[string]EgressCapability, len(d.Egress.Capabilities))
	for _, c := range d.Egress.Capabilities {
		byID[c.ID] = c
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
