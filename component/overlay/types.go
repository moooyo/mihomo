// Package overlay implements the runtime policy overlay: a typed,
// generation-versioned, durably persisted policy source that an external
// coordinator commits through a machine-only control socket.
//
// The overlay exists so that an external traffic processor can be wired into
// mihomo's routing without rewriting the operator-owned configuration file on
// every policy change. It contributes two things to rule resolution, spliced in
// at two explicit anchor rules:
//
//   - a client stage: ordered typed direct/reject rules followed by capture
//     rules that steer selected traffic at the processor;
//   - an egress stage: opaque capability lookup that maps processor-originated
//     connections back onto an operator-selected egress group.
//
// Every behaviour-changing field belongs to exactly one immutable generation.
// A generation is published by one atomic snapshot swap, which is the live
// linearization point for client matching, egress capability resolution,
// authoritative readback and the read-only generation endpoint the processor
// polls. Nothing in this package mutates a published generation in place.
//
// This package holds only the data model, its digests, the durable store and
// the snapshot holder. It must not import tunnel, config, hub or adapter; the
// rule and tunnel integration depend on this package, never the reverse.
package overlay

import (
	"fmt"
	"strings"
	"time"
)

// SchemaVersion is the overlay document schema understood by this build. A
// durable artifact written by a newer schema is refused rather than guessed at.
const SchemaVersion = 1

// State is the lifecycle position of one generation.
//
//	STAGED   --commit---------> ACTIVE
//	STAGED   --abort----------> REVOKED
//	ACTIVE   --graceful-------> DRAINING
//	ACTIVE   --revoke---------> REVOKED
//	DRAINING --deadline-------> REVOKED
//	REVOKED  --no dependents--> (garbage collected)
type State string

const (
	// StateStaged is persisted and validated but carries no usable client-match
	// or egress capability. It is the only state Abort accepts.
	StateStaged State = "STAGED"
	// StateActive is installed by the live swap. At most one generation is
	// active at a time.
	StateActive State = "ACTIVE"
	// StateDraining still resolves egress capabilities so already-started
	// transactions can finish, but produces no new client matches.
	StateDraining State = "DRAINING"
	// StateRevoked has no capabilities at all.
	StateRevoked State = "REVOKED"
)

func (s State) Valid() bool {
	switch s {
	case StateStaged, StateActive, StateDraining, StateRevoked:
		return true
	}
	return false
}

// TransitionMode selects what happens to the superseded generation when a new
// one commits.
type TransitionMode string

const (
	// TransitionGraceful moves the previous generation to DRAINING until its
	// per-protocol deadline.
	TransitionGraceful TransitionMode = "graceful"
	// TransitionRevoke removes the previous generation's capabilities in the
	// same live swap.
	TransitionRevoke TransitionMode = "revoke"
)

func (t TransitionMode) Valid() bool {
	return t == TransitionGraceful || t == TransitionRevoke
}

// Stage identifies which of the two anchors an overlay evaluation belongs to.
type Stage string

const (
	// StageClient reads only the single active generation.
	StageClient Stage = "client"
	// StageEgress additionally resolves capabilities belonging to explicitly
	// draining generations.
	StageEgress Stage = "egress"
)

func (s Stage) Valid() bool { return s == StageClient || s == StageEgress }

// ParseStage maps an anchor rule's stage token.
func ParseStage(s string) (Stage, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "client":
		return StageClient, nil
	case "egress":
		return StageEgress, nil
	}
	return "", fmt.Errorf("%w: unknown runtime-overlay stage %q (want client or egress)", ErrInvalidDocument, s)
}

// ClientAction is the typed action a client-stage rule may carry. The overlay
// deliberately cannot name an arbitrary proxy group here; capture steers at a
// declared processor and everything else is a terminal allow/deny.
type ClientAction string

const (
	ActionDirect  ClientAction = "direct"
	ActionReject  ClientAction = "reject"
	ActionCapture ClientAction = "capture"
)

func (a ClientAction) Valid() bool {
	switch a {
	case ActionDirect, ActionReject, ActionCapture:
		return true
	}
	return false
}

// SelectorKind names the single primary matcher a client rule carries.
type SelectorKind string

const (
	SelectorDomain         SelectorKind = "domain"
	SelectorDomainSuffix   SelectorKind = "domain-suffix"
	SelectorDomainKeyword  SelectorKind = "domain-keyword"
	SelectorDomainWildcard SelectorKind = "domain-wildcard"
	SelectorIPCIDR         SelectorKind = "ip-cidr"
	// SelectorAny carries no primary selector of its own. It exists so a rule
	// whose only constraints are keywords can be expressed without inventing a
	// fake domain to hang them on. A rule using it must carry at least one
	// keyword constraint, or it would match every connection.
	SelectorAny SelectorKind = "any"
)

func (k SelectorKind) Valid() bool {
	switch k {
	case SelectorDomain, SelectorDomainSuffix, SelectorDomainKeyword,
		SelectorDomainWildcard, SelectorIPCIDR, SelectorAny:
		return true
	}
	return false
}

// Network constrains a rule to one L4 protocol. The empty value matches both.
type Network string

const (
	NetworkAny Network = ""
	NetworkTCP Network = "tcp"
	NetworkUDP Network = "udp"
)

func (n Network) Valid() bool {
	switch n {
	case NetworkAny, NetworkTCP, NetworkUDP:
		return true
	}
	return false
}

// PortRange is an inclusive destination port range.
type PortRange struct {
	From uint16 `json:"from"`
	To   uint16 `json:"to"`
}

func (p PortRange) Contains(port uint16) bool { return port >= p.From && port <= p.To }

// ClientRule is one typed entry in the client stage. Exactly one selector kind
// is set; Value carries its payload.
//
// A rule with SelectorIPCIDR never triggers a DNS resolution: the overlay
// evaluates it only against an address the metadata already carries. Forcing a
// resolve here would let a capture rule leak the client's destination to the
// resolver before the policy decision is made.
type ClientRule struct {
	Kind    SelectorKind `json:"kind"`
	Value   string       `json:"value"`
	Network Network      `json:"network,omitempty"`
	Ports   []PortRange  `json:"ports,omitempty"`
	// KeywordsAny narrows the rule to hosts containing at least one of these
	// substrings; KeywordsAll requires every one of them. They are additional
	// constraints on the primary selector, not alternatives to it.
	//
	// Real reviewed policy combines them — "this suffix, but only when the host
	// also mentions one of these tokens" is a common shape — and a typed model
	// that cannot express it silently drops a deny the operator approved.
	KeywordsAny []string     `json:"keywordsAny,omitempty"`
	KeywordsAll []string     `json:"keywordsAll,omitempty"`
	Action      ClientAction `json:"action"`
	// Processor is required when Action is capture and must name a processor
	// declared in ProcessorTargets.
	Processor string `json:"processor,omitempty"`
	// Owner records which extension contributed the rule. It is diagnostic
	// only and never affects matching.
	Owner string `json:"owner,omitempty"`
}

// ClientOverlay is the ordered client-stage rule list. Order is significant and
// is preserved exactly as the coordinator submitted it: first match wins.
type ClientOverlay struct {
	Rules []ClientRule `json:"rules"`
}

// EgressCapability maps one opaque credential onto one fixed egress policy.
// The processor never names a group; it presents a capability and mihomo
// resolves it server-side against the generation that issued it.
type EgressCapability struct {
	// ID is the opaque credential the processor presents. With the SOCKS5
	// transport this is the authenticated inbound username.
	ID string `json:"id"`
	// Group is the operator-selected proxy group or outbound this capability
	// resolves to.
	Group string `json:"group"`
	// AllowDirect permits the resolved leaf to be DIRECT. When false a
	// generation whose group resolves to DIRECT fails closed instead.
	AllowDirect bool `json:"allowDirect"`
	// PublicOnly requires the destination to resolve to a globally routable
	// address and forces pinned-IP dialing, so an authorized hostname cannot
	// rebind onto a private one between authorization and dial.
	PublicOnly bool `json:"publicOnly"`
	// ResolverProfile names the generation-bound resolver profile used for
	// origin resolution. Empty means the core resolver.
	ResolverProfile string `json:"resolverProfile,omitempty"`
	// Owner is diagnostic only.
	Owner string `json:"owner,omitempty"`
}

// EgressOverlay is the capability table for one generation. Lookup is by
// capability ID and is exact; there is no prefix or wildcard form.
type EgressOverlay struct {
	Capabilities []EgressCapability `json:"capabilities"`
}

// ProcessorTarget declares one external processor. Name must match a proxy in
// the operator configuration that carries the runtime-overlay processor flag,
// which is what keeps it out of GLOBAL, include-all groups and URL tests.
type ProcessorTarget struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// ResolverProfile is a generation-bound origin resolution policy. Binding it to
// the generation is what stops the processor's origin resolution from becoming
// a second, unversioned commit point.
type ResolverProfile struct {
	Name        string   `json:"name"`
	Nameservers []string `json:"nameservers"`
	// PreferGo forces the profile's own nameservers instead of inheriting the
	// core resolver.
	PreferGo bool `json:"preferGo,omitempty"`
}

// Quotas bound one generation's cost. They are fixed by the fork rather than
// negotiated per generation so a coordinator bug cannot enlarge them.
type Quotas struct {
	MaxClientRules      int `json:"maxClientRules"`
	MaxCapabilities     int `json:"maxCapabilities"`
	MaxProcessorTargets int `json:"maxProcessorTargets"`
	MaxResolverProfiles int `json:"maxResolverProfiles"`
}

// DefaultQuotas are the fork's fixed limits.
func DefaultQuotas() Quotas {
	return Quotas{
		MaxClientRules:      4096,
		MaxCapabilities:     64,
		MaxProcessorTargets: 8,
		MaxResolverProfiles: 8,
	}
}

// DrainDeadlines bound how long a DRAINING generation keeps resolving
// capabilities, per protocol. Every value is finite: DRAINING is never
// open-ended, and the longest of these is what a revoke actually costs.
type DrainDeadlines struct {
	TCP       time.Duration `json:"tcp"`
	UDP       time.Duration `json:"udp"`
	HTTP1     time.Duration `json:"http1"`
	HTTP2     time.Duration `json:"http2"`
	HTTP3     time.Duration `json:"http3"`
	WebSocket time.Duration `json:"websocket"`
}

// DefaultDrainDeadlines answers Section 16 question 9 with concrete values.
// They are deliberately short: a drain window is a period in which a superseded
// policy is still enforceable, so its cost is measured in stale policy, not in
// convenience.
func DefaultDrainDeadlines() DrainDeadlines {
	return DrainDeadlines{
		TCP:       30 * time.Second,
		UDP:       30 * time.Second,
		HTTP1:     30 * time.Second,
		HTTP2:     60 * time.Second,
		HTTP3:     60 * time.Second,
		WebSocket: 300 * time.Second,
	}
}

// Max returns the longest deadline, which is when a draining generation is
// unconditionally revoked.
func (d DrainDeadlines) Max() time.Duration {
	m := d.TCP
	for _, v := range []time.Duration{d.UDP, d.HTTP1, d.HTTP2, d.HTTP3, d.WebSocket} {
		if v > m {
			m = v
		}
	}
	return m
}

// Document is the complete desired state for one generation, exactly as the
// coordinator submits it. It is immutable once staged: a change of any field
// below is a new generation, including changes that do not alter capture rules,
// because otherwise the processor bundle or the DNS selector becomes an
// untracked second commit point.
type Document struct {
	SchemaVersion int    `json:"schemaVersion"`
	Owner         string `json:"owner"`

	GenerationID       string `json:"generationId"`
	ParentGenerationID string `json:"parentGenerationId,omitempty"`
	DocumentRevision   uint64 `json:"documentRevision"`

	Client           ClientOverlay     `json:"client"`
	Egress           EgressOverlay     `json:"egress"`
	ProcessorTargets []ProcessorTarget `json:"processorTargets"`
	ResolverProfiles []ResolverProfile `json:"resolverProfiles,omitempty"`

	// SidecarBundleDigest and CertificateHostSetDigest are opaque to mihomo.
	// They are carried so readback and the processor's own generation check can
	// agree on exactly which artifacts belong to this generation.
	SidecarBundleDigest      string `json:"sidecarBundleDigest,omitempty"`
	CertificateHostSetDigest string `json:"certificateHostSetDigest,omitempty"`

	// TransitionMode selects what happens to the generation this one
	// supersedes.
	TransitionMode TransitionMode `json:"transitionMode"`
}

// Validate checks structural well-formedness and quota compliance. It does not
// check anything that depends on the live configuration — group existence,
// anchor placement and processor proxy declaration are validated at commit,
// against the configuration the commit will run under.
func (d *Document) Validate(q Quotas) error {
	if d.SchemaVersion != SchemaVersion {
		return fmt.Errorf("%w: schema version %d is not %d", ErrUnsupportedSchema, d.SchemaVersion, SchemaVersion)
	}
	if err := validateID("owner", d.Owner); err != nil {
		return err
	}
	if err := validateID("generationId", d.GenerationID); err != nil {
		return err
	}
	if d.ParentGenerationID != "" {
		if err := validateID("parentGenerationId", d.ParentGenerationID); err != nil {
			return err
		}
		if d.ParentGenerationID == d.GenerationID {
			return fmt.Errorf("%w: parentGenerationId equals generationId", ErrInvalidDocument)
		}
	}
	if !d.TransitionMode.Valid() {
		return fmt.Errorf("%w: transitionMode %q is not graceful or revoke", ErrInvalidDocument, d.TransitionMode)
	}

	if len(d.Client.Rules) > q.MaxClientRules {
		return fmt.Errorf("%w: %d client rules exceeds the limit of %d", ErrQuotaExceeded, len(d.Client.Rules), q.MaxClientRules)
	}
	if len(d.Egress.Capabilities) > q.MaxCapabilities {
		return fmt.Errorf("%w: %d capabilities exceeds the limit of %d", ErrQuotaExceeded, len(d.Egress.Capabilities), q.MaxCapabilities)
	}
	if len(d.ProcessorTargets) > q.MaxProcessorTargets {
		return fmt.Errorf("%w: %d processor targets exceeds the limit of %d", ErrQuotaExceeded, len(d.ProcessorTargets), q.MaxProcessorTargets)
	}
	if len(d.ResolverProfiles) > q.MaxResolverProfiles {
		return fmt.Errorf("%w: %d resolver profiles exceeds the limit of %d", ErrQuotaExceeded, len(d.ResolverProfiles), q.MaxResolverProfiles)
	}

	processors := make(map[string]struct{}, len(d.ProcessorTargets))
	names := make(map[string]struct{}, len(d.ProcessorTargets))
	for i, p := range d.ProcessorTargets {
		if err := validateID(fmt.Sprintf("processorTargets[%d].id", i), p.ID); err != nil {
			return err
		}
		if p.Name == "" {
			return fmt.Errorf("%w: processorTargets[%d].name is empty", ErrInvalidDocument, i)
		}
		if _, dup := processors[p.ID]; dup {
			return fmt.Errorf("%w: duplicate processor target id %q", ErrInvalidDocument, p.ID)
		}
		if _, dup := names[p.Name]; dup {
			return fmt.Errorf("%w: duplicate processor target name %q", ErrInvalidDocument, p.Name)
		}
		processors[p.ID] = struct{}{}
		names[p.Name] = struct{}{}
	}

	profiles := make(map[string]struct{}, len(d.ResolverProfiles))
	for i, p := range d.ResolverProfiles {
		if err := validateID(fmt.Sprintf("resolverProfiles[%d].name", i), p.Name); err != nil {
			return err
		}
		if _, dup := profiles[p.Name]; dup {
			return fmt.Errorf("%w: duplicate resolver profile %q", ErrInvalidDocument, p.Name)
		}
		if len(p.Nameservers) == 0 {
			return fmt.Errorf("%w: resolverProfiles[%d] has no nameservers", ErrInvalidDocument, i)
		}
		profiles[p.Name] = struct{}{}
	}

	for i := range d.Client.Rules {
		if err := d.Client.Rules[i].validate(i, processors); err != nil {
			return err
		}
	}

	seen := make(map[string]struct{}, len(d.Egress.Capabilities))
	for i, c := range d.Egress.Capabilities {
		if err := validateID(fmt.Sprintf("egress.capabilities[%d].id", i), c.ID); err != nil {
			return err
		}
		if _, dup := seen[c.ID]; dup {
			return fmt.Errorf("%w: duplicate capability id %q", ErrInvalidDocument, c.ID)
		}
		seen[c.ID] = struct{}{}
		if c.Group == "" {
			return fmt.Errorf("%w: egress.capabilities[%d] (%s) has no group", ErrInvalidDocument, i, c.ID)
		}
		if c.ResolverProfile != "" {
			if _, ok := profiles[c.ResolverProfile]; !ok {
				return fmt.Errorf("%w: capability %q names unknown resolver profile %q", ErrInvalidDocument, c.ID, c.ResolverProfile)
			}
		}
	}
	return nil
}

// maxRuleKeywords bounds the keyword constraints on one rule. Matching is a
// linear substring scan per keyword, so an unbounded list would be a per-packet
// cost the coordinator could set arbitrarily high.
const maxRuleKeywords = 16

func (r *ClientRule) validate(idx int, processors map[string]struct{}) error {
	if !r.Kind.Valid() {
		return fmt.Errorf("%w: client.rules[%d] has unknown kind %q", ErrInvalidDocument, idx, r.Kind)
	}
	if r.Kind == SelectorAny {
		if r.Value != "" {
			return fmt.Errorf("%w: client.rules[%d] uses kind %q but carries a value", ErrInvalidDocument, idx, SelectorAny)
		}
		// Without a keyword constraint this would match every connection, which
		// is never what a reviewed extension rule means.
		if len(r.KeywordsAny) == 0 && len(r.KeywordsAll) == 0 {
			return fmt.Errorf("%w: client.rules[%d] uses kind %q with no keyword constraint, which would match everything",
				ErrInvalidDocument, idx, SelectorAny)
		}
	} else if r.Value == "" {
		return fmt.Errorf("%w: client.rules[%d] has an empty value", ErrInvalidDocument, idx)
	}
	if len(r.KeywordsAny)+len(r.KeywordsAll) > maxRuleKeywords {
		return fmt.Errorf("%w: client.rules[%d] carries %d keyword constraints, the limit is %d",
			ErrQuotaExceeded, idx, len(r.KeywordsAny)+len(r.KeywordsAll), maxRuleKeywords)
	}
	for _, kw := range append(append([]string(nil), r.KeywordsAny...), r.KeywordsAll...) {
		if kw == "" {
			return fmt.Errorf("%w: client.rules[%d] has an empty keyword constraint", ErrInvalidDocument, idx)
		}
	}
	if !r.Network.Valid() {
		return fmt.Errorf("%w: client.rules[%d] has unknown network %q", ErrInvalidDocument, idx, r.Network)
	}
	if !r.Action.Valid() {
		return fmt.Errorf("%w: client.rules[%d] has unknown action %q", ErrInvalidDocument, idx, r.Action)
	}
	for _, p := range r.Ports {
		if p.From == 0 || p.To == 0 || p.From > p.To {
			return fmt.Errorf("%w: client.rules[%d] has an invalid port range %d-%d", ErrInvalidDocument, idx, p.From, p.To)
		}
	}
	switch r.Action {
	case ActionCapture:
		if r.Processor == "" {
			return fmt.Errorf("%w: client.rules[%d] captures but names no processor", ErrInvalidDocument, idx)
		}
		if _, ok := processors[r.Processor]; !ok {
			return fmt.Errorf("%w: client.rules[%d] names unknown processor %q", ErrInvalidDocument, idx, r.Processor)
		}
	default:
		if r.Processor != "" {
			return fmt.Errorf("%w: client.rules[%d] action %q must not name a processor", ErrInvalidDocument, idx, r.Action)
		}
	}
	return nil
}

// maxIDLen bounds every opaque identifier the coordinator supplies. The limit
// exists because these strings reach filenames, log lines and readback
// responses.
const maxIDLen = 128

// ValidateOwner checks an overlay owner name, which appears both in anchor rule
// lines and in generation documents. The two must agree, so they share one
// definition of what a legal owner is.
func ValidateOwner(v string) error { return validateID("owner", v) }

func validateID(field, v string) error {
	if v == "" {
		return fmt.Errorf("%w: %s is empty", ErrInvalidDocument, field)
	}
	if len(v) > maxIDLen {
		return fmt.Errorf("%w: %s exceeds %d bytes", ErrInvalidDocument, field, maxIDLen)
	}
	for i := 0; i < len(v); i++ {
		c := v[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		case c == '-', c == '_', c == '.':
		default:
			return fmt.Errorf("%w: %s contains an illegal byte %q; allowed are [A-Za-z0-9._-]", ErrInvalidDocument, field, string(c))
		}
	}
	// A leading dot or a path traversal segment would escape the store
	// directory when the ID is used as a filename.
	if v == "." || v == ".." || strings.HasPrefix(v, ".") {
		return fmt.Errorf("%w: %s %q is not a usable path segment", ErrInvalidDocument, field, v)
	}
	return nil
}
