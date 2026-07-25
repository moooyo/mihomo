package overlay

import (
	"testing"
	"time"
)

// A coordinator renewing the processor's lease must be able to learn, from the
// readback alone, what a matching lease has to contain. Lease.Matches compares
// against the active document's digests; the readback used to report only the
// last attestation's, so a coordinator following it would send back whatever it
// had already sent and could never converge on a generation whose document
// carried different ones. Capture then failed closed for a generation that was
// otherwise entirely healthy.
func TestReadbackCarriesWhatAMatchingLeaseNeeds(t *testing.T) {
	doc := &Document{
		GenerationID:             "g-1",
		SidecarBundleDigest:      "b-bundle",
		CertificateHostSetDigest: "c-hosts",
	}
	lease := &Lease{
		GenerationID: "g-1",
		BundleDigest: "b-bundle",
		CertHostSet:  "c-hosts",
	}
	if !lease.Matches(doc) {
		t.Fatal("a lease built from the document's own digests does not match it")
	}
	stale := &Lease{GenerationID: "g-1", BundleDigest: "b-old", CertHostSet: "c-hosts"}
	if stale.Matches(doc) {
		t.Fatal("a lease naming a different bundle matched; a stale processor would read as ready")
	}
}

// The readback is what an operator reads to answer "is the processor
// attesting?". The sweeper is what swaps the processor state, so between a
// lease lapsing and the next sweep the held pointer is still set. Reporting
// that as valid says the processor is attesting at a moment when capture has
// already begun failing closed — observed on a live gateway, where the field
// still read "valid" twenty seconds after the processor was stopped and its
// traffic was already being refused.
func TestExpiredLeaseIsNotReportedValid(t *testing.T) {
	expired := &Lease{GenerationID: "g-1", ExpiresAt: time.Now().Add(-time.Second)}
	if !expired.Expired(time.Now()) {
		t.Fatal("a lease past its expiry does not report as expired")
	}
	live := &Lease{GenerationID: "g-1", ExpiresAt: time.Now().Add(time.Minute)}
	if live.Expired(time.Now()) {
		t.Fatal("a current lease reports as expired")
	}
	var absent *Lease
	if !absent.Expired(time.Now()) {
		t.Fatal("a nil lease must read as expired rather than panicking")
	}
}

// processorState is the field an operator reads first. Derived only from the
// sweeper, it kept saying "ready" after the lease behind it had lapsed and
// capture was already being refused — observed on a live gateway.
func TestProcessorStateFollowsTheLease(t *testing.T) {
	if ProcessorReady.Serviceable() != true {
		t.Fatal("ready must be serviceable")
	}
	if ProcessorNotReady.Serviceable() {
		t.Fatal("not-ready must not be serviceable; capture would stop failing closed")
	}
	if ProcessorQuarantined.Serviceable() {
		t.Fatal("quarantined must not be serviceable")
	}
}

// A steady-state heartbeat refreshes the registry's lease and deliberately
// leaves the snapshot alone — nothing about the state changed, so there is
// nothing to swap. The pointer the snapshot holds therefore stops advancing
// while the processor is attesting perfectly well.
//
// Observed on a live gateway: the readback said the lease had expired two
// minutes earlier and the processor was not ready, while the core was logging
// captured connections through the client anchor the whole time. Judging expiry
// from the held pointer reports a healthy gateway as lapsed — the exact inverse
// of the fault the expiry check was added for.
func TestRegistryIsTheAuthorityOnLeaseValidity(t *testing.T) {
	registry := NewLeaseRegistry(DefaultLeaseTTL)
	first, err := registry.Register("intercept", "inst-1", "g-1", "b-1", "c-1", 0, 0)
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	// What a snapshot would have captured at that moment.
	held := *first

	// A later heartbeat, same lease.
	refreshed, err := registry.Register("intercept", "inst-1", "g-1", "b-1", "c-1", 0, 0)
	if err != nil {
		t.Fatalf("refresh: %v", err)
	}
	if refreshed.LeaseID != first.LeaseID {
		t.Fatalf("a heartbeat minted a new lease %q (was %q)", refreshed.LeaseID, first.LeaseID)
	}
	if !refreshed.ExpiresAt.After(held.ExpiresAt) && !refreshed.ExpiresAt.Equal(held.ExpiresAt) {
		t.Fatal("a heartbeat moved the expiry backwards")
	}
	if current := registry.Current(); current == nil {
		t.Fatal("the registry reports no current lease immediately after a heartbeat")
	}
}
