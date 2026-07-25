package overlay

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/metacubex/mihomo/log"
)

// Hooks are the host callbacks the manager needs. They are function fields
// rather than an interface so this package stays a leaf: the config, tunnel and
// hub layers depend on the overlay, never the reverse.
type Hooks struct {
	// CoreRevision returns the current dependency-closure revision of the live
	// configuration. A commit carries the revision it expects; if the closure
	// moved in between, the commit conflicts instead of silently applying
	// against a configuration it was never validated for.
	CoreRevision func() uint64

	// ProcessorProxies returns the proxies declared as runtime-overlay
	// processors, keyed by proxy name. A capture target absent from this map
	// cannot be enforced.
	ProcessorProxies func() map[string]string

	// ValidateDependencies checks a compiled generation against the live
	// configuration: rule mode, anchor structure, in-scope listener routing,
	// group existence and recursion, resolver profiles.
	ValidateDependencies func(*Compiled) error

	// AdvanceResolverEpoch is invoked inside the commit, in the same critical
	// section as the swap, when the generation's resolver profile set differs
	// from the previous one.
	AdvanceResolverEpoch func(epoch uint64)

	// RevokeGeneration closes established connections and UDP associations
	// bound to a generation that has lost its capabilities.
	//
	// This is a sweep with bounded effect, not a barrier. Authorization itself
	// lives in the snapshot: a revoked capability stops resolving in
	// ResolveEgress, so a surviving connection cannot start new work even if
	// the sweep misses it.
	RevokeGeneration func(generationID string)
}

func (h Hooks) coreRevision() uint64 {
	if h.CoreRevision == nil {
		return 0
	}
	return h.CoreRevision()
}

func (h Hooks) processorProxies() map[string]string {
	if h.ProcessorProxies == nil {
		return nil
	}
	return h.ProcessorProxies()
}

func (h Hooks) validate(c *Compiled) error {
	if h.ValidateDependencies == nil {
		return nil
	}
	return h.ValidateDependencies(c)
}

// Readback is the authoritative answer to "what is actually live". A
// coordinator that lost a commit response reads this and rolls forward; it must
// never infer the outcome or blind-rollback.
//
// PersistedGeneration and ActiveGeneration are reported separately on purpose.
// The durable recovery decision is written before the live swap, so between the
// two there is a window in which they legitimately differ, and conflating them
// would make a crash in that window look like a failed commit.
type Readback struct {
	Enabled             bool           `json:"enabled"`
	ActiveGeneration    string         `json:"activeGeneration"`
	ActiveDigest        string         `json:"activeDigest,omitempty"`
	ActiveProjection    string         `json:"activeProjectionDigest,omitempty"`
	PersistedGeneration string         `json:"persistedGeneration"`
	CoreRevision        uint64         `json:"coreConfigRevision"`
	ResolverEpoch       uint64         `json:"resolverEpoch"`
	ProcessorState      ProcessorState `json:"processorState"`
	DependencyErrors    []string       `json:"dependencyErrors,omitempty"`
	ProcessorInstance   string         `json:"processorInstanceId,omitempty"`
	BundleDigest        string         `json:"sidecarBundleDigest,omitempty"`
	CapabilitySet       string         `json:"capabilitySetDigest,omitempty"`
	LeaseState          string         `json:"leaseState"`
	LeaseExpiresAt      int64          `json:"leaseExpiresAt,omitempty"`
	FencingToken        uint64         `json:"fencingToken,omitempty"`
	Prepared            []string       `json:"preparedGenerations"`
	Draining            []string       `json:"drainingGenerations"`
	BootEpoch           string         `json:"bootEpoch"`
	SchemaVersion       int            `json:"schemaVersion"`
}

// CommitResult is returned by a successful commit, including an idempotent
// repeat of one that already succeeded.
type CommitResult struct {
	ActiveGeneration string `json:"activeGeneration"`
	ActiveDigest     string `json:"activeDigest"`
	CoreRevision     uint64 `json:"coreConfigRevision"`
	ResolverEpoch    uint64 `json:"resolverEpoch"`
	// Repeated is true when the requested generation was already active and the
	// call was answered without a new swap.
	Repeated bool `json:"repeated"`
}

// Manager owns the durable store, the published snapshot and the lease
// registry. Every mutating path takes commitMu, which the host also takes
// around a full configuration reload; that is what serializes a commit against
// a reload rather than letting the two interleave.
type Manager struct {
	commitMu sync.Mutex

	store  *Store
	holder *Holder
	leases *LeaseRegistry
	hooks  Hooks
	quotas Quotas

	owner           string
	bootEpoch       string
	processInstance string

	resolverEpoch uint64

	sweepOnce sync.Once
	sweepStop chan struct{}
}

// NewManager builds a manager over an already-opened store.
func NewManager(store *Store, owner string, hooks Hooks) *Manager {
	boot := NewBootEpoch()
	inst := NewBootEpoch()
	return &Manager{
		store:           store,
		holder:          NewHolder(boot, inst),
		leases:          NewLeaseRegistry(DefaultLeaseTTL),
		hooks:           hooks,
		quotas:          DefaultQuotas(),
		owner:           owner,
		bootEpoch:       boot,
		processInstance: inst,
		sweepStop:       make(chan struct{}),
	}
}

// Owner reports the overlay owner this manager serves. The anchor rules name
// the same owner; a mismatch means the configuration and the overlay are not
// talking about the same thing.
func (m *Manager) Owner() string { return m.owner }

// Snapshot returns the live published snapshot.
func (m *Manager) Snapshot() *Snapshot { return m.holder.Load() }

// Holder exposes the snapshot pointer for the rule and tunnel layers.
func (m *Manager) Holder() *Holder { return m.holder }

// Leases exposes the readiness registry for the control socket.
func (m *Manager) Leases() *LeaseRegistry { return m.leases }

// Quotas reports the fork's fixed limits.
func (m *Manager) Quotas() Quotas { return m.quotas }

// Recover loads the durable recovery decision and installs the startup
// quarantine snapshot. It must run before client data-plane listeners open.
//
// The quarantine keeps ordinary non-capture routing available while making
// every known capture match reject and disabling every processor egress
// capability. That is the only safe answer to a restart: the client's DNS cache
// may still point at the gateway for capture hosts, so opening listeners with
// no overlay at all would create exactly the bypass window the design forbids.
func (m *Manager) Recover() error {
	m.commitMu.Lock()
	defer m.commitMu.Unlock()

	ptr, err := m.store.GetPointer()
	if err != nil {
		return err
	}
	if ptr.Active == "" {
		log.Infoln("[Overlay] no persisted generation; overlay is disabled")
		return nil
	}

	rec, err := m.store.GetGeneration(ptr.Active)
	if err != nil {
		// A corrupt or missing active artifact means the capture set cannot be
		// reconstructed. Refusing here is deliberate: the alternative is to
		// serve the ordinary path for hosts whose clients still resolve to the
		// gateway, which is an unguarded data plane.
		return fmt.Errorf("overlay: cannot reconstruct persisted generation %s: %w", ptr.Active, err)
	}

	compiled, err := Compile(&rec.Document, m.quotas, m.hooks.processorProxies())
	if err != nil {
		return fmt.Errorf("overlay: persisted generation %s no longer compiles: %w", ptr.Active, err)
	}

	next := m.holder.Load().clone()
	next.active = compiled
	next.state = ProcessorQuarantined
	next.coreRevision = ptr.CoreRevision
	next.resolverEpoch = m.resolverEpoch
	next.lease = nil
	next.draining = nil

	// Draining generations do not survive a boot epoch as usable capabilities.
	// Their artifacts remain so a later readback can explain them, but nothing
	// they issued authenticates against this process.
	for _, id := range ptr.Draining {
		if _, err := m.store.GetGeneration(id); err != nil {
			log.Warnln("[Overlay] draining generation %s is unreadable after restart: %v", id, err)
		}
	}

	m.holder.Store(next)
	log.Infoln("[Overlay] recovered generation %s in quarantine; capture traffic rejects until the processor presents a matching lease", ptr.Active)
	return nil
}

// Stage validates, compiles and durably persists a generation without giving it
// any data-plane capability. Staging is idempotent: submitting the identical
// document again returns success, and submitting a different document under an
// existing id conflicts.
func (m *Manager) Stage(doc *Document) (*Compiled, error) {
	m.commitMu.Lock()
	defer m.commitMu.Unlock()

	if doc.Owner != m.owner {
		return nil, fmt.Errorf("%w: document owner %q does not match this overlay's owner %q", ErrInvalidDocument, doc.Owner, m.owner)
	}

	compiled, err := Compile(doc, m.quotas, m.hooks.processorProxies())
	if err != nil {
		return nil, err
	}
	if err := m.hooks.validate(compiled); err != nil {
		return nil, err
	}

	if existing, err := m.store.GetGeneration(doc.GenerationID); err == nil {
		if existing.Digests.Overall != compiled.Digests.Overall {
			return nil, fmt.Errorf("%w: generation %s already exists with a different document", ErrWrongState, doc.GenerationID)
		}
		if existing.State != StateStaged {
			// Re-staging something already active is a no-op the coordinator can
			// safely observe; re-staging something revoked is not.
			if existing.State == StateActive {
				return compiled, nil
			}
			return nil, fmt.Errorf("%w: generation %s is %s and cannot be re-staged", ErrWrongState, doc.GenerationID, existing.State)
		}
	} else if !isNotFound(err) {
		return nil, err
	}

	rec := &Record{
		Document: *compiled.Document,
		Digests:  compiled.Digests,
		State:    StateStaged,
		StagedAt: time.Now().Unix(),
	}
	if err := m.store.PutGeneration(rec); err != nil {
		return nil, err
	}

	next := m.holder.Load().clone()
	next.staged[doc.GenerationID] = compiled
	m.holder.Store(next)

	log.Infoln("[Overlay] staged generation %s (%d client rules, %d capabilities)",
		doc.GenerationID, compiled.Client.Len(), len(compiled.Document.Egress.Capabilities))
	return compiled, nil
}

// Abort discards a staged generation. It accepts only STAGED: anything already
// active, draining or revoked must be superseded by a new generation, not
// erased.
func (m *Manager) Abort(generationID string) error {
	m.commitMu.Lock()
	defer m.commitMu.Unlock()

	rec, err := m.store.GetGeneration(generationID)
	if err != nil {
		return err
	}
	if rec.State != StateStaged {
		return fmt.Errorf("%w: generation %s is %s; abort accepts only %s", ErrWrongState, generationID, rec.State, StateStaged)
	}
	if err := m.store.DeleteGeneration(generationID); err != nil {
		return err
	}

	next := m.holder.Load().clone()
	delete(next.staged, generationID)
	m.holder.Store(next)
	log.Infoln("[Overlay] aborted staged generation %s", generationID)
	return nil
}

// CommitRequest carries the compare-and-swap preconditions.
type CommitRequest struct {
	GenerationID string
	// ExpectedActive is the generation the coordinator believes is active. The
	// empty string asserts that none is.
	ExpectedActive string
	// ExpectedCoreRevision is the dependency-closure revision the generation was
	// validated against. Zero disables the check, which is only appropriate for
	// the very first commit.
	ExpectedCoreRevision uint64
}

// Commit performs the compare-and-swap and publishes the generation.
//
// The durable recovery decision is written before the live swap. If the process
// dies in between, the running process never exposed a mixed state and restart
// rolls forward to the persisted generation; that asymmetry is the whole point
// of ordering it this way.
func (m *Manager) Commit(req CommitRequest) (*CommitResult, error) {
	m.commitMu.Lock()
	defer m.commitMu.Unlock()

	cur := m.holder.Load()
	currentActive := cur.ActiveID()

	// Idempotent repeat: the requested generation is already the active one.
	if currentActive != "" && currentActive == req.GenerationID {
		return &CommitResult{
			ActiveGeneration: currentActive,
			ActiveDigest:     cur.active.Digests.Overall,
			CoreRevision:     cur.coreRevision,
			ResolverEpoch:    cur.resolverEpoch,
			Repeated:         true,
		}, nil
	}
	if currentActive != req.ExpectedActive {
		return nil, fmt.Errorf("%w: active generation is %q, the request expected %q",
			ErrCASConflict, orNone(currentActive), orNone(req.ExpectedActive))
	}

	liveCore := m.hooks.coreRevision()
	if req.ExpectedCoreRevision != 0 && req.ExpectedCoreRevision != liveCore {
		return nil, fmt.Errorf("%w: core configuration revision is %d, the request expected %d",
			ErrCASConflict, liveCore, req.ExpectedCoreRevision)
	}

	rec, err := m.store.GetGeneration(req.GenerationID)
	if err != nil {
		return nil, err
	}
	if rec.State != StateStaged {
		return nil, fmt.Errorf("%w: generation %s is %s; commit accepts only %s",
			ErrWrongState, req.GenerationID, rec.State, StateStaged)
	}

	compiled, err := Compile(&rec.Document, m.quotas, m.hooks.processorProxies())
	if err != nil {
		return nil, err
	}
	// Revalidate against the configuration the commit will actually run under,
	// not the one staging saw.
	if err := m.hooks.validate(compiled); err != nil {
		return nil, err
	}

	// Inspect the readiness lease from local state. This deliberately does not
	// perform IPC: blocking on the processor while holding the commit lock would
	// let an unresponsive sidecar stall configuration reload.
	lease := m.leases.Current()
	state := ProcessorQuarantined
	if lease != nil && lease.Matches(compiled.Document) {
		state = ProcessorReady
	} else if lease != nil {
		state = ProcessorNotReady
	}

	now := time.Now()
	resolverEpoch := m.resolverEpoch
	resolverChanged := cur.active == nil || cur.active.ResolverSetDigest != compiled.ResolverSetDigest
	if resolverChanged {
		resolverEpoch++
	}

	// Persist the durable recovery decision and the generation's new state
	// before the swap.
	previous := cur.active
	draining := pruneDraining(cur.draining, now)
	var supersededID string
	if previous != nil {
		supersededID = previous.Document.GenerationID
		if compiled.Document.TransitionMode == TransitionGraceful {
			draining = append(draining, drainingGeneration{
				compiled: previous,
				deadline: now.Add(cur.deadlines.Max()),
			})
		}
	}

	ptr := &Pointer{
		Active:       compiled.Document.GenerationID,
		Draining:     drainingIDs(draining),
		CoreRevision: liveCore,
	}
	rec.State = StateActive
	rec.ActivatedAt = now.Unix()
	if err := m.store.PutGeneration(rec); err != nil {
		return nil, err
	}
	if err := m.store.PutPointer(ptr); err != nil {
		return nil, err
	}
	if previous != nil {
		if err := m.markState(supersededID, compiled.Document.TransitionMode); err != nil {
			log.Warnln("[Overlay] could not record superseded state for %s: %v", supersededID, err)
		}
	}

	if resolverChanged && m.hooks.AdvanceResolverEpoch != nil {
		// Advanced before the swap so no reader can observe the new generation
		// while the resolver is still able to answer from the old profile's
		// cache.
		m.hooks.AdvanceResolverEpoch(resolverEpoch)
	}
	m.resolverEpoch = resolverEpoch

	next := cur.clone()
	next.active = compiled
	next.state = state
	next.coreRevision = liveCore
	next.resolverEpoch = resolverEpoch
	next.lease = lease
	next.draining = draining
	next.depErrors = nil
	delete(next.staged, compiled.Document.GenerationID)

	// The live swap. Everything above is preparation; this single store is what
	// makes the new generation observable, atomically, to matching, egress
	// resolution, readback and the processor's generation endpoint.
	m.holder.Store(next)

	if previous != nil && compiled.Document.TransitionMode == TransitionRevoke {
		m.revoke(supersededID)
	}
	m.startSweeper()

	log.Infoln("[Overlay] committed generation %s (%s, transition=%s, core revision %d)",
		compiled.Document.GenerationID, state, compiled.Document.TransitionMode, liveCore)

	return &CommitResult{
		ActiveGeneration: compiled.Document.GenerationID,
		ActiveDigest:     compiled.Digests.Overall,
		CoreRevision:     liveCore,
		ResolverEpoch:    resolverEpoch,
	}, nil
}

// RegisterReadiness records a processor readiness heartbeat and re-evaluates
// whether the active generation is serviceable.
func (m *Manager) RegisterReadiness(processorID, processInstance, generationID, bundleDigest, certHostSet string, peerUID, peerGID int) (*Lease, error) {
	lease, err := m.leases.Register(processorID, processInstance, generationID, bundleDigest, certHostSet, peerUID, peerGID)
	if err != nil {
		return nil, err
	}

	m.commitMu.Lock()
	defer m.commitMu.Unlock()

	cur := m.holder.Load()
	if cur.active == nil {
		return lease, nil
	}
	state := ProcessorNotReady
	if lease.Matches(cur.active.Document) {
		state = ProcessorReady
	}
	if state == cur.state && cur.lease != nil && cur.lease.LeaseID == lease.LeaseID {
		return lease, nil
	}

	next := cur.clone()
	next.lease = lease
	next.state = state
	m.holder.Store(next)
	log.Infoln("[Overlay] processor readiness for generation %s is now %s", cur.active.Document.GenerationID, state)
	return lease, nil
}

// RefreshReadiness re-evaluates the processor state against the current lease.
// It is what turns a lapsed heartbeat into a fail-closed capture, and is driven
// by the sweeper rather than by traffic so the transition does not depend on
// something arriving.
func (m *Manager) RefreshReadiness() {
	m.commitMu.Lock()
	defer m.commitMu.Unlock()
	m.refreshReadinessLocked()
}

func (m *Manager) refreshReadinessLocked() {
	cur := m.holder.Load()
	if cur.active == nil {
		return
	}
	lease := m.leases.Current()
	state := ProcessorNotReady
	switch {
	case lease == nil && cur.state == ProcessorQuarantined:
		state = ProcessorQuarantined
	case lease != nil && lease.Matches(cur.active.Document):
		state = ProcessorReady
	}
	if state == cur.state {
		return
	}
	next := cur.clone()
	next.state = state
	next.lease = lease
	m.holder.Store(next)
	log.Warnln("[Overlay] processor state for generation %s changed to %s", cur.active.Document.GenerationID, state)
}

// MarkDegraded records dependency errors discovered out of band, for example a
// referenced group that disappeared. The generation stays active and its
// captures keep failing closed; substituting DIRECT would be worse than the
// outage.
func (m *Manager) MarkDegraded(errs []string) {
	m.commitMu.Lock()
	defer m.commitMu.Unlock()

	cur := m.holder.Load()
	if cur.active == nil {
		return
	}
	next := cur.clone()
	next.depErrors = append([]string(nil), errs...)
	if len(errs) > 0 {
		next.state = ProcessorDegraded
	} else if cur.state == ProcessorDegraded {
		next.state = ProcessorNotReady
	}
	m.holder.Store(next)
}

// Readback answers the authoritative status query.
func (m *Manager) Readback() Readback {
	cur := m.holder.Load()
	rb := Readback{
		Enabled:          true,
		ActiveGeneration: cur.ActiveID(),
		CoreRevision:     cur.coreRevision,
		ResolverEpoch:    cur.resolverEpoch,
		ProcessorState:   cur.state,
		DependencyErrors: cur.DependencyErrors(),
		Prepared:         cur.StagedIDs(),
		Draining:         cur.DrainingIDs(),
		BootEpoch:        cur.bootEpoch,
		SchemaVersion:    SchemaVersion,
		LeaseState:       "none",
	}
	if cur.active != nil {
		rb.ActiveDigest = cur.active.Digests.Overall
		rb.ActiveProjection = cur.active.Digests.Projection
		rb.CapabilitySet = cur.active.CapabilitySet
	}
	if l := cur.lease; l != nil {
		rb.ProcessorInstance = l.ProcessInstance
		rb.BundleDigest = l.BundleDigest
		rb.FencingToken = l.FencingToken
		rb.LeaseExpiresAt = l.ExpiresAt.Unix()
		if l.Expired(time.Now()) {
			rb.LeaseState = "expired"
		} else {
			rb.LeaseState = "valid"
		}
	}
	if ptr, err := m.store.GetPointer(); err == nil {
		rb.PersistedGeneration = ptr.Active
	}
	return rb
}

// Purge removes every durable artifact and returns the process to the disabled
// state. It is the downgrade contract's purge step, and it deliberately revokes
// before it deletes so nothing keeps serving from a snapshot whose artifacts are
// gone.
func (m *Manager) Purge() error {
	m.commitMu.Lock()
	defer m.commitMu.Unlock()

	cur := m.holder.Load()
	if cur.active != nil {
		m.revoke(cur.active.Document.GenerationID)
	}
	for _, id := range cur.DrainingIDs() {
		m.revoke(id)
	}

	next := EmptySnapshot(m.bootEpoch, m.processInstance)
	m.holder.Store(next)
	if err := m.store.Purge(); err != nil {
		return err
	}
	log.Warnln("[Overlay] purged all durable overlay state")
	return nil
}

// Close stops the background sweeper.
func (m *Manager) Close() {
	select {
	case <-m.sweepStop:
	default:
		close(m.sweepStop)
	}
}

func (m *Manager) startSweeper() {
	m.sweepOnce.Do(func() {
		go m.sweep(context.Background())
	})
}

// sweep enforces the drain deadlines and the readiness lease independently of
// traffic. A draining generation must lose its capabilities at its deadline
// even if nothing is currently asking, and a lapsed lease must fail captures
// closed even on an idle link.
func (m *Manager) sweep(ctx context.Context) {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-m.sweepStop:
			return
		case <-ticker.C:
			m.sweepOnce2()
		}
	}
}

func (m *Manager) sweepOnce2() {
	m.commitMu.Lock()
	defer m.commitMu.Unlock()

	cur := m.holder.Load()
	now := time.Now()

	var expired []string
	kept := cur.draining[:0:0]
	for _, d := range cur.draining {
		if now.After(d.deadline) {
			expired = append(expired, d.compiled.Document.GenerationID)
			continue
		}
		kept = append(kept, d)
	}
	if len(expired) > 0 {
		next := cur.clone()
		next.draining = kept
		m.holder.Store(next)
		for _, id := range expired {
			log.Infoln("[Overlay] drain deadline reached for generation %s; revoking", id)
			m.revoke(id)
			if err := m.markStateRevoked(id); err != nil {
				log.Warnln("[Overlay] could not mark %s revoked: %v", id, err)
			}
		}
		if ptr, err := m.store.GetPointer(); err == nil {
			ptr.Draining = drainingIDs(kept)
			if err := m.store.PutPointer(ptr); err != nil {
				log.Warnln("[Overlay] could not update recovery pointer after drain: %v", err)
			}
		}
	}

	m.refreshReadinessLocked()
}

func (m *Manager) revoke(generationID string) {
	if generationID == "" || m.hooks.RevokeGeneration == nil {
		return
	}
	m.hooks.RevokeGeneration(generationID)
}

func (m *Manager) markState(generationID string, mode TransitionMode) error {
	rec, err := m.store.GetGeneration(generationID)
	if err != nil {
		return err
	}
	if mode == TransitionGraceful {
		rec.State = StateDraining
	} else {
		rec.State = StateRevoked
		rec.RevokedAt = time.Now().Unix()
	}
	return m.store.PutGeneration(rec)
}

func (m *Manager) markStateRevoked(generationID string) error {
	rec, err := m.store.GetGeneration(generationID)
	if err != nil {
		return err
	}
	rec.State = StateRevoked
	rec.RevokedAt = time.Now().Unix()
	return m.store.PutGeneration(rec)
}

func pruneDraining(in []drainingGeneration, now time.Time) []drainingGeneration {
	out := make([]drainingGeneration, 0, len(in))
	for _, d := range in {
		if now.After(d.deadline) {
			continue
		}
		out = append(out, d)
	}
	return out
}

func drainingIDs(in []drainingGeneration) []string {
	out := make([]string, 0, len(in))
	for _, d := range in {
		out = append(out, d.compiled.Document.GenerationID)
	}
	return out
}

func orNone(s string) string {
	if s == "" {
		return "<none>"
	}
	return s
}

func isNotFound(err error) bool {
	return err != nil && CodeOf(err) == CodeNotFound
}
