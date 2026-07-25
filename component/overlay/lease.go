package overlay

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"sync"
	"sync/atomic"
	"time"
)

// Lease is the processor's readiness attestation.
//
// It attests one thing only: that this exact processor instance holds the exact
// prepared bundle and certificate set for a generation, and can serve it if
// mihomo publishes that generation as active. It does not activate anything.
// Lease expiry therefore changes readiness, never desired state — the
// generation stays active and its matching traffic starts rejecting.
type Lease struct {
	ProcessorID     string    `json:"processorId"`
	ProcessInstance string    `json:"processInstance"`
	GenerationID    string    `json:"generationId"`
	BundleDigest    string    `json:"bundleDigest"`
	CertHostSet     string    `json:"certificateHostSetDigest"`
	LeaseID         string    `json:"leaseId"`
	FencingToken    uint64    `json:"fencingToken"`
	ExpiresAt       time.Time `json:"expiresAt"`

	// PeerUID and PeerGID record the OS identity of the process that
	// established the lease. They are informational on platforms without peer
	// credentials.
	PeerUID int `json:"peerUid"`
	PeerGID int `json:"peerGid"`
}

// Expired reports whether the lease has lapsed.
func (l *Lease) Expired(now time.Time) bool {
	return l == nil || !now.Before(l.ExpiresAt)
}

// Matches reports whether the lease attests the exact artifacts a generation
// requires. A processor holding a different bundle is not a ready processor for
// this generation, even though it is alive and heartbeating.
func (l *Lease) Matches(d *Document) bool {
	if l == nil || d == nil {
		return false
	}
	if l.GenerationID != d.GenerationID {
		return false
	}
	if d.SidecarBundleDigest != "" && l.BundleDigest != d.SidecarBundleDigest {
		return false
	}
	if d.CertificateHostSetDigest != "" && l.CertHostSet != d.CertificateHostSetDigest {
		return false
	}
	return true
}

// DefaultLeaseTTL is how long one readiness heartbeat is honoured.
const DefaultLeaseTTL = 15 * time.Second

// LeaseRegistry issues and tracks readiness leases. Fencing tokens are
// monotonic within a boot epoch and the boot epoch itself is fresh per process,
// so a lease minted by a previous mihomo process can never be replayed against
// this one.
type LeaseRegistry struct {
	mu      sync.Mutex
	current *Lease
	fencing atomic.Uint64
	ttl     time.Duration
}

// NewLeaseRegistry creates a registry with the given heartbeat lifetime.
func NewLeaseRegistry(ttl time.Duration) *LeaseRegistry {
	if ttl <= 0 {
		ttl = DefaultLeaseTTL
	}
	return &LeaseRegistry{ttl: ttl}
}

// Register establishes or refreshes the readiness lease.
//
// A change of process instance mints a new fencing token: the previous
// processor's in-flight work is no longer covered, which is what lets the
// commit path tell a restart apart from a heartbeat.
func (r *LeaseRegistry) Register(processorID, processInstance, generationID, bundleDigest, certHostSet string, peerUID, peerGID int) (*Lease, error) {
	if err := validateID("processorId", processorID); err != nil {
		return nil, err
	}
	if err := validateID("processInstance", processInstance); err != nil {
		return nil, err
	}
	if err := validateID("generationId", generationID); err != nil {
		return nil, err
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	now := time.Now()
	reuse := r.current != nil &&
		r.current.ProcessorID == processorID &&
		r.current.ProcessInstance == processInstance &&
		r.current.GenerationID == generationID &&
		r.current.BundleDigest == bundleDigest &&
		r.current.CertHostSet == certHostSet &&
		!r.current.Expired(now)

	if reuse {
		refreshed := *r.current
		refreshed.ExpiresAt = now.Add(r.ttl)
		r.current = &refreshed
		return &refreshed, nil
	}

	id, err := randomID()
	if err != nil {
		return nil, err
	}
	lease := &Lease{
		ProcessorID:     processorID,
		ProcessInstance: processInstance,
		GenerationID:    generationID,
		BundleDigest:    bundleDigest,
		CertHostSet:     certHostSet,
		LeaseID:         id,
		FencingToken:    r.fencing.Add(1),
		ExpiresAt:       now.Add(r.ttl),
		PeerUID:         peerUID,
		PeerGID:         peerGID,
	}
	r.current = lease
	return lease, nil
}

// Current returns the live lease, or nil when none is valid.
func (r *LeaseRegistry) Current() *Lease {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.current.Expired(time.Now()) {
		return nil
	}
	l := *r.current
	return &l
}

// Revoke drops the lease, for example when the processor reports shutdown.
func (r *LeaseRegistry) Revoke(leaseID string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.current == nil {
		return nil
	}
	if leaseID != "" && r.current.LeaseID != leaseID {
		return fmt.Errorf("%w: lease %q is not current", ErrWrongState, leaseID)
	}
	r.current = nil
	return nil
}

func randomID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("overlay: generate identifier: %w", err)
	}
	return hex.EncodeToString(b[:]), nil
}

// NewBootEpoch mints the per-process epoch. Every lease, fencing token, UDP
// association and connection handle minted under a previous epoch is invalid,
// while immutable generation artifacts and durable capability mappings survive
// and are reconstructed in quarantine.
func NewBootEpoch() string {
	id, err := randomID()
	if err != nil {
		// A failing CSPRNG is not recoverable here, and a predictable epoch
		// would defeat replay protection, so fall back to something that is at
		// least unique per process start rather than to a constant.
		return fmt.Sprintf("t%d", time.Now().UnixNano())
	}
	return id
}
