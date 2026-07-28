package overlay

import (
	"net/netip"
	"sync/atomic"
	"time"
)

// ProcessorState is what the processor and the dashboard see. It answers one
// question: may traffic that the overlay selects actually be processed right
// now?
type ProcessorState string

const (
	// ProcessorDisabled means no generation is active.
	ProcessorDisabled ProcessorState = "disabled"
	// ProcessorQuarantined means a generation is active but the process has not
	// yet confirmed processor readiness since boot. Capture matches reject;
	// ordinary non-capture routing is unaffected.
	ProcessorQuarantined ProcessorState = "quarantined"
	// ProcessorNotReady means readiness was established and then lost — a lease
	// expired or the processor's digests stopped matching the generation.
	// Capture matches reject. The generation stays active: lease expiry changes
	// readiness, not desired state.
	ProcessorNotReady ProcessorState = "not-ready"
	// ProcessorDegraded means the generation is enforceable but a dependency it
	// names has gone missing out of band. Captures continue to fail closed.
	ProcessorDegraded ProcessorState = "degraded"
	// ProcessorReady means capture and egress are fully live.
	ProcessorReady ProcessorState = "ready"
)

// Serviceable reports whether capture traffic may actually reach the processor.
func (s ProcessorState) Serviceable() bool { return s == ProcessorReady }

type drainingGeneration struct {
	compiled *Compiled
	deadline time.Time
}

// Snapshot is the immutable runtime state that one atomic swap publishes. It is
// the single live linearization point: client matching, egress capability
// resolution, authoritative readback and the processor's read-only generation
// endpoint all load this same pointer. There is no separately published
// processor view or client table, because a second publication path is a second
// commit point and would reintroduce exactly the split-brain this design exists
// to remove.
type Snapshot struct {
	bootEpoch       string
	processInstance string

	coreRevision  uint64
	resolverEpoch uint64

	active   *Compiled
	draining []drainingGeneration
	staged   map[string]*Compiled

	state ProcessorState
	// lease is the live readiness attestation, or nil once it has lapsed.
	lease *Lease
	// lastLease survives expiry so readback can report "expired" rather than
	// "none". The distinction matters to a coordinator: never-attested and
	// stopped-attesting call for different recovery.
	lastLease *Lease
	depErrors []string
	deadlines DrainDeadlines

	createdAt time.Time
}

// EmptySnapshot is the state before any generation has been committed.
func EmptySnapshot(bootEpoch, processInstance string) *Snapshot {
	return &Snapshot{
		bootEpoch:       bootEpoch,
		processInstance: processInstance,
		state:           ProcessorDisabled,
		staged:          map[string]*Compiled{},
		deadlines:       DefaultDrainDeadlines(),
		createdAt:       time.Now(),
	}
}

func (s *Snapshot) BootEpoch() string          { return s.bootEpoch }
func (s *Snapshot) ProcessInstance() string    { return s.processInstance }
func (s *Snapshot) CoreRevision() uint64       { return s.coreRevision }
func (s *Snapshot) ResolverEpoch() uint64      { return s.resolverEpoch }
func (s *Snapshot) State() ProcessorState      { return s.state }
func (s *Snapshot) Deadlines() DrainDeadlines  { return s.deadlines }
func (s *Snapshot) DependencyErrors() []string { return append([]string(nil), s.depErrors...) }

// Active returns the active generation, or nil.
func (s *Snapshot) Active() *Compiled { return s.active }

// RequiresAnchors reports whether a generation is bound to this process, in
// which case a configuration that cannot evaluate the anchors must be refused
// rather than applied and then discovered to be unenforceable.
//
// Nil-safe: no overlay configured means no requirement.
func (s *Snapshot) RequiresAnchors() bool { return s != nil && s.active != nil }

// ActiveID returns the active generation id, or the empty string.
func (s *Snapshot) ActiveID() string {
	if s.active == nil {
		return ""
	}
	return s.active.Document.GenerationID
}

// Lease returns the current processor readiness lease, or nil.
func (s *Snapshot) Lease() *Lease { return s.lease }

// StagedIDs lists prepared generations. A staged generation deliberately has no
// usable data-plane capability at all: preparing is not arming.
func (s *Snapshot) StagedIDs() []string {
	out := make([]string, 0, len(s.staged))
	for id := range s.staged {
		out = append(out, id)
	}
	return out
}

// DrainingIDs lists generations whose capabilities still resolve.
func (s *Snapshot) DrainingIDs() []string {
	out := make([]string, 0, len(s.draining))
	for _, d := range s.draining {
		out = append(out, d.compiled.Document.GenerationID)
	}
	return out
}

// Staged returns a prepared generation by id.
func (s *Snapshot) Staged(id string) (*Compiled, bool) {
	c, ok := s.staged[id]
	return c, ok
}

// MatchClient evaluates the client anchor.
//
// The fail-closed rule lives here rather than in the caller: when the active
// generation selects traffic for capture but the processor is not serviceable,
// the decision becomes reject. It must never become "no match", because a no
// match falls through to the operator's ordinary rules and that is precisely
// the bypass the overlay exists to prevent.
func (s *Snapshot) MatchClient(in *MatchInput) ClientDecision {
	if s.active == nil {
		return ClientDecision{}
	}
	d := s.active.Client.Match(in)
	if !d.Matched {
		return d
	}
	if d.Action == ActionCapture && !s.state.Serviceable() {
		return ClientDecision{Matched: true, Action: ActionReject, RuleIndex: d.RuleIndex}
	}
	return d
}

// EgressResolution is the outcome of resolving an opaque processor capability.
type EgressResolution struct {
	GenerationID string
	Capability   EgressCapability
	// Binding is the destination-scoped decision that authorized this request.
	// It, not the capability, carries the egress group: one credential spans
	// every group the generation's extensions were bound to, and which one a
	// connection leaves through is decided by where it is going.
	Binding    EgressBinding
	Profile    ResolverProfile
	HasProfile bool
	// Draining is true when the capability belongs to a superseded generation
	// that is still inside its drain window.
	Draining bool
}

// ResolveEgress evaluates the egress anchor.
//
// Three things must hold together: the capability belongs to the active or an
// explicitly draining generation, it was presented on the processor's own
// listener, and it covers the requested endpoint. A prepared capability is
// rejected, which is what makes "prepare" safe to call speculatively.
//
// Any failure returns false and the request continues to the fixed egress
// reject terminator that must sit immediately after the anchor; it never
// continues into the client stage or the operator's rules.
func (s *Snapshot) ResolveEgress(in *MatchInput) (EgressResolution, bool) {
	if in.InUser == "" {
		return EgressResolution{}, false
	}
	if s.active != nil {
		if c, binding, ok := s.active.Egress.authorize(in); ok {
			if c.PublicOnly && forbiddenEgressScope(in.DstIP) {
				return EgressResolution{}, false
			}
			// A quarantined or not-ready generation has no live processor, so a
			// capability presented against it cannot be genuine.
			if !s.state.Serviceable() {
				return EgressResolution{}, false
			}
			return s.resolution(s.active, c, binding, false), true
		}
	}
	now := time.Now()
	for _, d := range s.draining {
		if now.After(d.deadline) {
			continue
		}
		if c, binding, ok := d.compiled.Egress.authorize(in); ok {
			if c.PublicOnly && forbiddenEgressScope(in.DstIP) {
				return EgressResolution{}, false
			}
			return s.resolution(d.compiled, c, binding, true), true
		}
	}
	return EgressResolution{}, false
}

// forbiddenEgressScope reports whether an address is one a public-only
// capability must never reach.
//
// This is the cheap half of the rebinding defence: it catches a destination
// whose address is already known. The expensive half — resolving through the
// generation's profile and dialing the validated address — needs per-adapter
// pinned-IP support and is not implemented, so this must not be read as a
// complete guarantee. It is still worth having: without it PublicOnly would be
// a field that claims a protection nothing provides.
func forbiddenEgressScope(addr netip.Addr) bool {
	if !addr.IsValid() {
		return false
	}
	a := addr.Unmap()
	switch {
	case a.IsLoopback(), a.IsPrivate(), a.IsLinkLocalUnicast(), a.IsLinkLocalMulticast(),
		a.IsInterfaceLocalMulticast(), a.IsMulticast(), a.IsUnspecified():
		return true
	}
	// Carrier-grade NAT, which is neither private nor globally routable.
	if a.Is4() && a.As4()[0] == 100 && a.As4()[1]&0xc0 == 64 {
		return true
	}
	return false
}

func (s *Snapshot) resolution(c *Compiled, cap EgressCapability, binding EgressBinding, draining bool) EgressResolution {
	r := EgressResolution{
		GenerationID: c.Document.GenerationID,
		Capability:   cap,
		Binding:      binding,
		Draining:     draining,
	}
	if cap.ResolverProfile != "" {
		if p, ok := c.ResolverProfiles[cap.ResolverProfile]; ok {
			r.Profile, r.HasProfile = p, true
		}
	}
	return r
}

// CapabilityGeneration reports which generation issued a capability, for
// tagging a connection tracker so revocation can enumerate and close it later.
func (s *Snapshot) CapabilityGeneration(id string) (string, bool) {
	if id == "" {
		return "", false
	}
	if s.active != nil {
		if _, ok := s.active.Egress.Lookup(id); ok {
			return s.active.Document.GenerationID, true
		}
	}
	for _, d := range s.draining {
		if _, ok := d.compiled.Egress.Lookup(id); ok {
			return d.compiled.Document.GenerationID, true
		}
	}
	return "", false
}

// LiveCapabilityIDs returns every capability that currently resolves, across
// the active and draining generations. The processor listener's authenticator
// is rebuilt from this on each swap, so a revoked credential stops
// authenticating rather than merely failing later at rule resolution.
func (s *Snapshot) LiveCapabilityIDs() []string {
	var out []string
	if s.active != nil && s.state.Serviceable() {
		out = append(out, s.active.Egress.IDs()...)
	}
	now := time.Now()
	for _, d := range s.draining {
		if now.After(d.deadline) {
			continue
		}
		out = append(out, d.compiled.Egress.IDs()...)
	}
	return out
}

// ActiveView is the authoritative read-only projection the processor polls at
// every generation-sensitive decision boundary.
//
// It returns more than a generation id on purpose. The processor must be able
// to prove that the view belongs to the mihomo process it is actually talking
// to and to the bundle it actually holds; an id alone would let a reply
// captured from a previous process be replayed after a restart.
type ActiveView struct {
	BootEpoch        string         `json:"bootEpoch"`
	ProcessInstance  string         `json:"processInstance"`
	ActiveGeneration string         `json:"activeGeneration"`
	OverallDigest    string         `json:"overallDigest,omitempty"`
	ProjectionDigest string         `json:"projectionDigest,omitempty"`
	BundleDigest     string         `json:"bundleDigest,omitempty"`
	CertHostSet      string         `json:"certificateHostSetDigest,omitempty"`
	ProcessorState   ProcessorState `json:"processorState"`
	CoreRevision     uint64         `json:"coreRevision"`
	ResolverEpoch    uint64         `json:"resolverEpoch"`
	LeaseID          string         `json:"leaseId,omitempty"`
	FencingToken     uint64         `json:"fencingToken,omitempty"`
	LeaseExpiresAt   int64          `json:"leaseExpiresAt,omitempty"`
	DrainingIDs      []string       `json:"drainingGenerations,omitempty"`
	DependencyErrors []string       `json:"dependencyErrors,omitempty"`
}

// View builds the authoritative projection.
func (s *Snapshot) View() ActiveView {
	v := ActiveView{
		BootEpoch:        s.bootEpoch,
		ProcessInstance:  s.processInstance,
		ProcessorState:   s.state,
		CoreRevision:     s.coreRevision,
		ResolverEpoch:    s.resolverEpoch,
		DrainingIDs:      s.DrainingIDs(),
		DependencyErrors: s.DependencyErrors(),
	}
	if s.active != nil {
		v.ActiveGeneration = s.active.Document.GenerationID
		v.OverallDigest = s.active.Digests.Overall
		v.ProjectionDigest = s.active.Digests.Projection
		v.BundleDigest = s.active.Digests.Bundle
		v.CertHostSet = s.active.Digests.CertificateHostSet
	}
	if s.lease != nil {
		v.LeaseID = s.lease.LeaseID
		v.FencingToken = s.lease.FencingToken
		v.LeaseExpiresAt = s.lease.ExpiresAt.Unix()
	}
	return v
}

// clone produces a mutable copy for building the next snapshot. Callers mutate
// the copy and publish it; the previous snapshot stays valid for every reader
// still holding it.
func (s *Snapshot) clone() *Snapshot {
	n := *s
	n.draining = append([]drainingGeneration(nil), s.draining...)
	n.staged = make(map[string]*Compiled, len(s.staged))
	for k, v := range s.staged {
		n.staged[k] = v
	}
	n.depErrors = append([]string(nil), s.depErrors...)
	n.createdAt = time.Now()
	return &n
}

// Holder owns the published snapshot pointer. Reads are lock-free; the writer
// serializes elsewhere, in the commit path, alongside configuration reload.
type Holder struct {
	p atomic.Pointer[Snapshot]
}

// NewHolder publishes an initial empty snapshot.
func NewHolder(bootEpoch, processInstance string) *Holder {
	h := &Holder{}
	h.p.Store(EmptySnapshot(bootEpoch, processInstance))
	return h
}

// Load returns the currently published snapshot. It never returns nil.
func (h *Holder) Load() *Snapshot { return h.p.Load() }

// Store publishes a new snapshot. This is the live linearization point.
func (h *Holder) Store(s *Snapshot) { h.p.Store(s) }
