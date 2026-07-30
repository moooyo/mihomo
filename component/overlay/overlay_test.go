package overlay

import (
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func testDocument(id string) *Document {
	return &Document{
		SchemaVersion:    SchemaVersion,
		Owner:            "5gpn",
		GenerationID:     id,
		DocumentRevision: 1,
		TransitionMode:   TransitionRevoke,
		ProcessorTargets: []ProcessorTarget{{ID: "intercept", Name: "MODULE-INTERCEPT"}},
		Client: ClientOverlay{Rules: []ClientRule{
			{Kind: SelectorDomain, Value: "ads.example.com", Action: ActionReject},
			{Kind: SelectorDomainSuffix, Value: "bilibili.com", Action: ActionCapture, Processor: "intercept",
				Ports: []PortRange{{From: 443, To: 443}}},
			{Kind: SelectorIPCIDR, Value: "203.0.113.0/24", Action: ActionDirect},
		}},
		Egress: EgressOverlay{Capabilities: []EgressCapability{{
			ID: "module-up-1", Listener: "intercept-egress", PublicOnly: true,
			Bindings: []EgressBinding{{
				Group: "Proxies",
				Destinations: []DestinationRule{
					{Kind: SelectorDomainSuffix, Value: "bilibili.com", Ports: []PortRange{{From: 80, To: 80}, {From: 443, To: 443}}},
				},
			}},
		}}},
	}
}

func mustCompile(t *testing.T, d *Document) *Compiled {
	t.Helper()
	c, err := Compile(d, DefaultQuotas(), map[string]string{"MODULE-INTERCEPT": "MODULE-INTERCEPT"})
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	return c
}

func TestDocumentValidateRejectsUnknownProcessor(t *testing.T) {
	d := testDocument("g1")
	d.Client.Rules[1].Processor = "nope"
	if err := d.Validate(DefaultQuotas()); !errors.Is(err, ErrInvalidDocument) {
		t.Fatalf("want ErrInvalidDocument, got %v", err)
	}
}

func TestDocumentValidateRejectsPathTraversalID(t *testing.T) {
	for _, id := range []string{"../escape", ".hidden", "with/slash", ""} {
		d := testDocument("g1")
		d.GenerationID = id
		if err := d.Validate(DefaultQuotas()); err == nil {
			t.Fatalf("generation id %q was accepted", id)
		}
	}
}

func TestDocumentValidateEnforcesQuotas(t *testing.T) {
	d := testDocument("g1")
	q := DefaultQuotas()
	q.MaxClientRules = 1
	if err := d.Validate(q); !errors.Is(err, ErrQuotaExceeded) {
		t.Fatalf("want ErrQuotaExceeded, got %v", err)
	}
}

func TestCompileRejectsUndeclaredProcessorProxy(t *testing.T) {
	d := testDocument("g1")
	_, err := Compile(d, DefaultQuotas(), map[string]string{})
	if !errors.Is(err, ErrDependencyMissing) {
		t.Fatalf("want ErrDependencyMissing, got %v", err)
	}
}

// A capture rule that reordered is a different policy, so it must produce a
// different digest — otherwise shadow comparison during migration would call
// two different first-match behaviours identical.
func TestDigestIsOrderSensitive(t *testing.T) {
	a := testDocument("g1")
	b := testDocument("g1")
	b.Client.Rules[0], b.Client.Rules[1] = b.Client.Rules[1], b.Client.Rules[0]
	if ComputeDigests(a).Projection == ComputeDigests(b).Projection {
		t.Fatal("reordering the client rules did not change the projection digest")
	}
}

// The canonical encoder is length-prefixed precisely so field contents cannot
// be shifted across a boundary to forge a collision.
func TestDigestResistsFieldBoundaryCollision(t *testing.T) {
	a := testDocument("g1")
	a.Client.Rules = []ClientRule{{Kind: SelectorDomain, Value: "ab", Owner: "c", Action: ActionReject}}
	b := testDocument("g1")
	b.Client.Rules = []ClientRule{{Kind: SelectorDomain, Value: "a", Owner: "bc", Action: ActionReject}}
	if ComputeDigests(a).Projection == ComputeDigests(b).Projection {
		t.Fatal("field boundary shift produced an identical digest")
	}
}

// Two documents differing only in fields mihomo never enforces must share a
// projection digest but differ overall.
func TestProjectionIgnoresProcessorOnlyFields(t *testing.T) {
	a := testDocument("g1")
	b := testDocument("g1")
	b.SidecarBundleDigest = "deadbeef"
	da, db := ComputeDigests(a), ComputeDigests(b)
	if da.Projection != db.Projection {
		t.Fatal("bundle digest leaked into the mihomo projection")
	}
	if da.Overall == db.Overall {
		t.Fatal("bundle digest did not change the overall digest")
	}
}

func TestClientMatchFirstMatchWins(t *testing.T) {
	c := mustCompile(t, testDocument("g1"))
	snap := EmptySnapshot("boot", "inst")
	snap.active = c
	snap.state = ProcessorReady

	cases := []struct {
		name   string
		in     MatchInput
		want   ClientAction
		target string
	}{
		{"exact reject", MatchInput{Host: "ads.example.com", Network: NetworkTCP}, ActionReject, ""},
		{"suffix capture on port", MatchInput{Host: "www.bilibili.com", DstPort: 443, Network: NetworkTCP}, ActionCapture, "MODULE-INTERCEPT"},
		{"cidr direct", MatchInput{DstIP: netip.MustParseAddr("203.0.113.7"), Network: NetworkTCP}, ActionDirect, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			d := snap.MatchClient(&tc.in)
			if !d.Matched || d.Action != tc.want {
				t.Fatalf("got matched=%v action=%q, want %q", d.Matched, d.Action, tc.want)
			}
			if tc.target != "" && d.Target != tc.target {
				t.Fatalf("target = %q, want %q", d.Target, tc.target)
			}
		})
	}
}

// The port constraint must actually constrain: a suffix capture rule scoped to
// 443 must not match port 80, or the overlay would capture more than the
// operator authorized.
func TestClientMatchRespectsPortConstraint(t *testing.T) {
	c := mustCompile(t, testDocument("g1"))
	snap := EmptySnapshot("boot", "inst")
	snap.active = c
	snap.state = ProcessorReady

	d := snap.MatchClient(&MatchInput{Host: "www.bilibili.com", DstPort: 80, Network: NetworkTCP})
	if d.Matched {
		t.Fatalf("port 80 matched a rule scoped to 443: %+v", d)
	}
}

// This is the single most important behaviour in the package: a capture that
// cannot be serviced must become a reject, never a fall-through. A
// fall-through reaches the operator's ordinary rules, which is the bypass the
// whole design exists to prevent.
func TestCaptureFailsClosedWhenProcessorUnserviceable(t *testing.T) {
	c := mustCompile(t, testDocument("g1"))
	for _, state := range []ProcessorState{ProcessorQuarantined, ProcessorNotReady, ProcessorDegraded, ProcessorDisabled} {
		snap := EmptySnapshot("boot", "inst")
		snap.active = c
		snap.state = state

		d := snap.MatchClient(&MatchInput{Host: "www.bilibili.com", DstPort: 443, Network: NetworkTCP})
		if !d.Matched {
			t.Fatalf("state %s: capture fell through to the operator rules", state)
		}
		if d.Action != ActionReject {
			t.Fatalf("state %s: action = %q, want reject", state, d.Action)
		}
	}
}

// A non-capture client rule is a policy decision the operator authorized
// independently of the processor, so it must survive the processor being down.
func TestDenyRulesSurviveProcessorOutage(t *testing.T) {
	c := mustCompile(t, testDocument("g1"))
	snap := EmptySnapshot("boot", "inst")
	snap.active = c
	snap.state = ProcessorNotReady

	d := snap.MatchClient(&MatchInput{Host: "ads.example.com", Network: NetworkTCP})
	if !d.Matched || d.Action != ActionReject {
		t.Fatalf("got %+v, want a reject", d)
	}
}

func TestEgressResolvesOnlyLiveCapabilities(t *testing.T) {
	c := mustCompile(t, testDocument("g1"))
	snap := EmptySnapshot("boot", "inst")
	snap.active = c
	snap.state = ProcessorReady

	if _, ok := snap.ResolveEgress((egressProbe("module-up-1"))); !ok {
		t.Fatal("live capability did not resolve")
	}
	if _, ok := snap.ResolveEgress((egressProbe("unknown"))); ok {
		t.Fatal("unknown capability resolved")
	}
	if _, ok := snap.ResolveEgress(&MatchInput{}); ok {
		t.Fatal("empty capability resolved")
	}

	// A quarantined generation has no live processor, so a capability
	// presented against it cannot be genuine.
	snap.state = ProcessorQuarantined
	if _, ok := snap.ResolveEgress((egressProbe("module-up-1"))); ok {
		t.Fatal("capability resolved against a quarantined generation")
	}
}

// A staged generation must carry no data-plane capability at all: preparing is
// not arming, which is what makes prepare safe to call speculatively.
func TestStagedCapabilitiesAreNotUsable(t *testing.T) {
	mgr := newTestManager(t)
	if _, err := mgr.Stage(testDocument("g1")); err != nil {
		t.Fatalf("stage: %v", err)
	}
	snap := mgr.Snapshot()
	if _, ok := snap.ResolveEgress((egressProbe("module-up-1"))); ok {
		t.Fatal("a staged capability was usable before commit")
	}
	if snap.MatchClient(&MatchInput{Host: "www.bilibili.com", DstPort: 443, Network: NetworkTCP}).Matched {
		t.Fatal("a staged client rule matched before commit")
	}
}

// egressProbe is a request that a correctly-formed capability should authorize:
// right listener, permitted destination, permitted port.
func egressProbe(user string) *MatchInput {
	return &MatchInput{
		InUser: user, InName: "intercept-egress",
		Host: "www.bilibili.com", DstPort: 443, Network: NetworkTCP,
	}
}

func newTestManager(t *testing.T) *Manager {
	t.Helper()
	store, err := OpenStore(t.TempDir(), "5gpn")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	m := NewManager(store, "5gpn", Hooks{
		ProcessorProxies: func() map[string]string { return map[string]string{"MODULE-INTERCEPT": "MODULE-INTERCEPT"} },
	})
	t.Cleanup(m.Close)
	return m
}

func readyLease(t *testing.T, m *Manager, gen string) {
	t.Helper()
	if _, err := m.RegisterReadiness("proc", "inst1", gen, "", "", 0, 0); err != nil {
		t.Fatalf("register readiness: %v", err)
	}
}

func TestCommitCASConflicts(t *testing.T) {
	m := newTestManager(t)
	if _, err := m.Stage(testDocument("g1")); err != nil {
		t.Fatalf("stage: %v", err)
	}

	// The request claims something else is active; nothing is.
	_, err := m.Commit(CommitRequest{GenerationID: "g1", ExpectedActive: "g0"})
	if !errors.Is(err, ErrCASConflict) {
		t.Fatalf("want ErrCASConflict, got %v", err)
	}

	if _, err := m.Commit(CommitRequest{GenerationID: "g1"}); err != nil {
		t.Fatalf("commit: %v", err)
	}

	// Now g1 is active; a request still expecting nothing must conflict.
	if _, err := m.Stage(testDocument("g2")); err != nil {
		t.Fatalf("stage g2: %v", err)
	}
	if _, err := m.Commit(CommitRequest{GenerationID: "g2", ExpectedActive: ""}); !errors.Is(err, ErrCASConflict) {
		t.Fatalf("want ErrCASConflict, got %v", err)
	}
}

// A coordinator that lost the commit response repeats the identical call. It
// must get the same success, not a conflict, or it would roll back a commit
// that actually landed.
func TestCommitIsIdempotent(t *testing.T) {
	m := newTestManager(t)
	if _, err := m.Stage(testDocument("g1")); err != nil {
		t.Fatalf("stage: %v", err)
	}
	first, err := m.Commit(CommitRequest{GenerationID: "g1"})
	if err != nil {
		t.Fatalf("commit: %v", err)
	}
	second, err := m.Commit(CommitRequest{GenerationID: "g1"})
	if err != nil {
		t.Fatalf("repeat commit: %v", err)
	}
	if !second.Repeated {
		t.Fatal("repeat commit was not reported as repeated")
	}
	if first.ActiveDigest != second.ActiveDigest {
		t.Fatal("repeat commit reported a different digest")
	}
}

func TestAbortAcceptsOnlyStaged(t *testing.T) {
	m := newTestManager(t)
	if _, err := m.Stage(testDocument("g1")); err != nil {
		t.Fatalf("stage: %v", err)
	}
	if err := m.Abort("g1"); err != nil {
		t.Fatalf("abort staged: %v", err)
	}
	if _, err := m.Stage(testDocument("g1")); err != nil {
		t.Fatalf("restage: %v", err)
	}
	if _, err := m.Commit(CommitRequest{GenerationID: "g1"}); err != nil {
		t.Fatalf("commit: %v", err)
	}
	if err := m.Abort("g1"); !errors.Is(err, ErrWrongState) {
		t.Fatalf("want ErrWrongState aborting an active generation, got %v", err)
	}
}

func TestStageRejectsDifferentDocumentUnderSameID(t *testing.T) {
	m := newTestManager(t)
	if _, err := m.Stage(testDocument("g1")); err != nil {
		t.Fatalf("stage: %v", err)
	}
	d := testDocument("g1")
	d.DocumentRevision = 2
	if _, err := m.Stage(d); !errors.Is(err, ErrWrongState) {
		t.Fatalf("want ErrWrongState, got %v", err)
	}
}

// Recovery must reinstate the persisted generation in quarantine, not ready:
// nothing has attested that a processor holding the matching bundle is alive
// in this boot epoch.
func TestRecoverInstallsQuarantine(t *testing.T) {
	dir := t.TempDir()
	store, err := OpenStore(dir, "5gpn")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	hooks := Hooks{ProcessorProxies: func() map[string]string {
		return map[string]string{"MODULE-INTERCEPT": "MODULE-INTERCEPT"}
	}}
	first := NewManager(store, "5gpn", hooks)
	defer first.Close()
	if _, err := first.Stage(testDocument("g1")); err != nil {
		t.Fatalf("stage: %v", err)
	}
	readyLease(t, first, "g1")
	if _, err := first.Commit(CommitRequest{GenerationID: "g1"}); err != nil {
		t.Fatalf("commit: %v", err)
	}
	if first.Snapshot().State() != ProcessorReady {
		t.Fatalf("state after commit = %s, want ready", first.Snapshot().State())
	}

	// Simulate a restart: fresh store handle, fresh manager, same directory.
	store2, err := OpenStore(dir, "5gpn")
	if err != nil {
		t.Fatalf("reopen store: %v", err)
	}
	second := NewManager(store2, "5gpn", hooks)
	defer second.Close()
	if err := second.Recover(); err != nil {
		t.Fatalf("recover: %v", err)
	}
	snap := second.Snapshot()
	if snap.ActiveID() != "g1" {
		t.Fatalf("active after recovery = %q, want g1", snap.ActiveID())
	}
	if snap.State() != ProcessorQuarantined {
		t.Fatalf("state after recovery = %s, want quarantined", snap.State())
	}
	d := snap.MatchClient(&MatchInput{Host: "www.bilibili.com", DstPort: 443, Network: NetworkTCP})
	if !d.Matched || d.Action != ActionReject {
		t.Fatalf("quarantined capture = %+v, want reject", d)
	}
}

// A processor holding the wrong bundle is alive but not ready for this
// generation, and the difference has to be visible.
func TestLeaseDigestMismatchIsNotReady(t *testing.T) {
	m := newTestManager(t)
	d := testDocument("g1")
	d.SidecarBundleDigest = "expected"
	if _, err := m.Stage(d); err != nil {
		t.Fatalf("stage: %v", err)
	}
	if _, err := m.RegisterReadiness("proc", "inst1", "g1", "different", "", 0, 0); err != nil {
		t.Fatalf("readiness: %v", err)
	}
	if _, err := m.Commit(CommitRequest{GenerationID: "g1"}); err != nil {
		t.Fatalf("commit: %v", err)
	}
	if got := m.Snapshot().State(); got != ProcessorNotReady {
		t.Fatalf("state = %s, want not-ready", got)
	}
}

func TestStoreDetectsTampering(t *testing.T) {
	dir := t.TempDir()
	store, err := OpenStore(dir, "5gpn")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	d := testDocument("g1")
	rec := &Record{Document: *d, Digests: ComputeDigests(d), State: StateStaged, StagedAt: time.Now().Unix()}
	if err := store.PutGeneration(rec); err != nil {
		t.Fatalf("put: %v", err)
	}

	path := filepath.Join(dir, generationsDir, "g1.json")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	tampered := strings.Replace(string(raw), "ads.example.com", "ads.attacker.com", 1)
	if tampered == string(raw) {
		t.Fatal("test fixture did not contain the expected value")
	}
	if err := os.WriteFile(path, []byte(tampered), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	if _, err := store.GetGeneration("g1"); !errors.Is(err, ErrStoreCorrupt) {
		t.Fatalf("want ErrStoreCorrupt, got %v", err)
	}
}

func TestStoreRefusesNewerSchema(t *testing.T) {
	dir := t.TempDir()
	if _, err := OpenStore(dir, "5gpn"); err != nil {
		t.Fatalf("open: %v", err)
	}
	metaPath := filepath.Join(dir, metaFile)
	raw, _ := os.ReadFile(metaPath)
	bumped := strings.Replace(string(raw), `"storeSchema": 1`, `"storeSchema": 99`, 1)
	if err := os.WriteFile(metaPath, []byte(bumped), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	if _, err := OpenStore(dir, "5gpn"); !errors.Is(err, ErrUnsupportedSchema) {
		t.Fatalf("want ErrUnsupportedSchema, got %v", err)
	}
}

// The downgrade contract requires a purge to leave nothing a later upgrade
// could rediscover and resurrect.
func TestPurgeLeavesNothingToResurrect(t *testing.T) {
	dir := t.TempDir()
	store, _ := OpenStore(dir, "5gpn")
	hooks := Hooks{ProcessorProxies: func() map[string]string {
		return map[string]string{"MODULE-INTERCEPT": "MODULE-INTERCEPT"}
	}}
	m := NewManager(store, "5gpn", hooks)
	defer m.Close()
	if _, err := m.Stage(testDocument("g1")); err != nil {
		t.Fatalf("stage: %v", err)
	}
	if _, err := m.Commit(CommitRequest{GenerationID: "g1"}); err != nil {
		t.Fatalf("commit: %v", err)
	}
	if err := m.Purge(); err != nil {
		t.Fatalf("purge: %v", err)
	}

	store2, _ := OpenStore(dir, "5gpn")
	m2 := NewManager(store2, "5gpn", hooks)
	defer m2.Close()
	if err := m2.Recover(); err != nil {
		t.Fatalf("recover after purge: %v", err)
	}
	if id := m2.Snapshot().ActiveID(); id != "" {
		t.Fatalf("purged generation %q came back", id)
	}
}

// A graceful transition keeps the superseded generation's capabilities
// resolvable so already-started transactions finish; a revoke does not.
func TestTransitionModeControlsDraining(t *testing.T) {
	for _, tc := range []struct {
		mode      TransitionMode
		stillLive bool
	}{
		{TransitionGraceful, true},
		{TransitionRevoke, false},
	} {
		t.Run(string(tc.mode), func(t *testing.T) {
			m := newTestManager(t)
			g1 := testDocument("g1")
			if _, err := m.Stage(g1); err != nil {
				t.Fatalf("stage g1: %v", err)
			}
			readyLease(t, m, "g1")
			if _, err := m.Commit(CommitRequest{GenerationID: "g1"}); err != nil {
				t.Fatalf("commit g1: %v", err)
			}

			g2 := testDocument("g2")
			g2.ParentGenerationID = "g1"
			g2.TransitionMode = tc.mode
			g2.Egress.Capabilities = []EgressCapability{{
				ID: "module-up-2", Listener: "intercept-egress",
				Bindings: []EgressBinding{{
					Group:        "Proxies",
					Destinations: []DestinationRule{{Kind: SelectorDomainSuffix, Value: "bilibili.com"}},
				}},
			}}
			if _, err := m.Stage(g2); err != nil {
				t.Fatalf("stage g2: %v", err)
			}
			readyLease(t, m, "g2")
			if _, err := m.Commit(CommitRequest{GenerationID: "g2", ExpectedActive: "g1"}); err != nil {
				t.Fatalf("commit g2: %v", err)
			}

			_, live := m.Snapshot().ResolveEgress((egressProbe("module-up-1")))
			if live != tc.stillLive {
				t.Fatalf("old capability live = %v, want %v", live, tc.stillLive)
			}
			// The new generation's own capability must resolve either way.
			if _, ok := m.Snapshot().ResolveEgress((egressProbe("module-up-2"))); !ok {
				t.Fatal("new capability did not resolve")
			}
		})
	}
}

// A resolver profile change must advance the epoch in the same commit;
// anything else keeps serving the previous profile's cached answers.
func TestResolverEpochAdvancesOnProfileChange(t *testing.T) {
	var epochs []uint64
	store, _ := OpenStore(t.TempDir(), "5gpn")
	m := NewManager(store, "5gpn", Hooks{
		ProcessorProxies:     func() map[string]string { return map[string]string{"MODULE-INTERCEPT": "MODULE-INTERCEPT"} },
		AdvanceResolverEpoch: func(e uint64) { epochs = append(epochs, e) },
	})
	defer m.Close()

	g1 := testDocument("g1")
	g1.ResolverProfiles = []ResolverProfile{{Name: "trust", Nameservers: []string{"1.1.1.1"}}}
	g1.Egress.Capabilities[0].ResolverProfile = "trust"
	if _, err := m.Stage(g1); err != nil {
		t.Fatalf("stage g1: %v", err)
	}
	if _, err := m.Commit(CommitRequest{GenerationID: "g1"}); err != nil {
		t.Fatalf("commit g1: %v", err)
	}
	if len(epochs) != 1 {
		t.Fatalf("first commit advanced the epoch %d times, want 1", len(epochs))
	}

	// Same profiles: no advance.
	g2 := testDocument("g2")
	g2.ResolverProfiles = g1.ResolverProfiles
	g2.Egress.Capabilities[0].ResolverProfile = "trust"
	if _, err := m.Stage(g2); err != nil {
		t.Fatalf("stage g2: %v", err)
	}
	if _, err := m.Commit(CommitRequest{GenerationID: "g2", ExpectedActive: "g1"}); err != nil {
		t.Fatalf("commit g2: %v", err)
	}
	if len(epochs) != 1 {
		t.Fatalf("an unchanged profile set advanced the epoch (%v)", epochs)
	}

	// Changed profiles: advance.
	g3 := testDocument("g3")
	g3.ResolverProfiles = []ResolverProfile{{Name: "trust", Nameservers: []string{"8.8.8.8"}}}
	g3.Egress.Capabilities[0].ResolverProfile = "trust"
	if _, err := m.Stage(g3); err != nil {
		t.Fatalf("stage g3: %v", err)
	}
	if _, err := m.Commit(CommitRequest{GenerationID: "g3", ExpectedActive: "g2"}); err != nil {
		t.Fatalf("commit g3: %v", err)
	}
	if len(epochs) != 2 {
		t.Fatalf("a changed profile set did not advance the epoch (%v)", epochs)
	}
}

// Readback reports the persisted and the live generation separately so a
// coordinator can tell a crash between persist and swap apart from a failed
// commit.
func TestReadbackDistinguishesPersistedFromActive(t *testing.T) {
	m := newTestManager(t)
	if _, err := m.Stage(testDocument("g1")); err != nil {
		t.Fatalf("stage: %v", err)
	}
	rb := m.Readback()
	if rb.ActiveGeneration != "" || rb.PersistedGeneration != "" {
		t.Fatalf("staging changed readback: %+v", rb)
	}
	if len(rb.Prepared) != 1 || rb.Prepared[0] != "g1" {
		t.Fatalf("prepared = %v, want [g1]", rb.Prepared)
	}
	if _, err := m.Commit(CommitRequest{GenerationID: "g1"}); err != nil {
		t.Fatalf("commit: %v", err)
	}
	rb = m.Readback()
	if rb.ActiveGeneration != "g1" || rb.PersistedGeneration != "g1" {
		t.Fatalf("after commit: active=%q persisted=%q", rb.ActiveGeneration, rb.PersistedGeneration)
	}
}

func TestOwnerMismatchIsRejected(t *testing.T) {
	m := newTestManager(t)
	d := testDocument("g1")
	d.Owner = "someone-else"
	if _, err := m.Stage(d); !errors.Is(err, ErrInvalidDocument) {
		t.Fatalf("want ErrInvalidDocument, got %v", err)
	}
}

func TestDrainDeadlinesAreFinite(t *testing.T) {
	d := DefaultDrainDeadlines()
	for name, v := range map[string]time.Duration{
		"tcp": d.TCP, "udp": d.UDP, "http1": d.HTTP1,
		"http2": d.HTTP2, "http3": d.HTTP3, "websocket": d.WebSocket,
	} {
		if v <= 0 {
			t.Fatalf("%s deadline is %v; DRAINING must never be open-ended", name, v)
		}
	}
	if d.Max() != d.WebSocket {
		t.Fatalf("Max() = %v, want the websocket deadline %v", d.Max(), d.WebSocket)
	}
}

// Recovery runs before the host has published anything about the live
// configuration. It must still recompile a generation that names a processor,
// or every restart of a deployment that uses capture fails to come up at all.
func TestRecoverWithoutHostProcessorListing(t *testing.T) {
	dir := t.TempDir()
	store, err := OpenStore(dir, "5gpn")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	declared := Hooks{ProcessorProxies: func() map[string]string {
		return map[string]string{"MODULE-INTERCEPT": "MODULE-INTERCEPT"}
	}}
	first := NewManager(store, "5gpn", declared)
	defer first.Close()
	if _, err := first.Stage(testDocument("g1")); err != nil {
		t.Fatalf("stage: %v", err)
	}
	if _, err := first.Commit(CommitRequest{GenerationID: "g1"}); err != nil {
		t.Fatalf("commit: %v", err)
	}

	// Restart with a hook that reports nothing, standing in for the window
	// before the configuration is applied.
	store2, _ := OpenStore(dir, "5gpn")
	second := NewManager(store2, "5gpn", Hooks{
		ProcessorProxies: func() map[string]string { return nil },
	})
	defer second.Close()
	if err := second.Recover(); err != nil {
		t.Fatalf("recovery refused a generation naming a processor: %v", err)
	}
	if second.Snapshot().ActiveID() != "g1" {
		t.Fatalf("active after recovery = %q, want g1", second.Snapshot().ActiveID())
	}
}

// "Never attested" and "attested then stopped" call for different coordinator
// recovery, so readback must not collapse them into one value.
func TestReadbackDistinguishesNeverReadyFromExpired(t *testing.T) {
	store, _ := OpenStore(t.TempDir(), "5gpn")
	m := NewManager(store, "5gpn", Hooks{
		ProcessorProxies: func() map[string]string { return map[string]string{"MODULE-INTERCEPT": "MODULE-INTERCEPT"} },
	})
	defer m.Close()
	// A very short TTL so the lease lapses without a long sleep.
	m.leases = NewLeaseRegistry(time.Millisecond)

	if _, err := m.Stage(testDocument("g1")); err != nil {
		t.Fatalf("stage: %v", err)
	}
	if _, err := m.Commit(CommitRequest{GenerationID: "g1"}); err != nil {
		t.Fatalf("commit: %v", err)
	}
	if got := m.Readback().LeaseState; got != "none" {
		t.Fatalf("before any attestation: leaseState = %q, want none", got)
	}

	if _, err := m.RegisterReadiness("proc", "inst", "g1", "", "", 0, 0); err != nil {
		t.Fatalf("readiness: %v", err)
	}
	time.Sleep(5 * time.Millisecond)
	m.RefreshReadiness()

	rb := m.Readback()
	if rb.LeaseState != "expired" {
		t.Fatalf("after expiry: leaseState = %q, want expired", rb.LeaseState)
	}
	if rb.ProcessorInstance != "inst" {
		t.Fatalf("the lapsed attestation's instance was lost: %q", rb.ProcessorInstance)
	}
	// Lease expiry changes readiness, not desired state.
	if rb.ActiveGeneration != "g1" {
		t.Fatalf("expiry changed the active generation to %q", rb.ActiveGeneration)
	}
	if rb.ProcessorState != ProcessorNotReady {
		t.Fatalf("processorState = %q, want not-ready", rb.ProcessorState)
	}
}

// A capability constrains endpoint and egress, not egress alone. The rules it
// replaces were per-destination and per-port with everything else falling to a
// deny terminator, so a capability that authorized a group for any destination
// would grant a compromised processor strictly more than it had before.
func TestCapabilityConstrainsTheDestination(t *testing.T) {
	c := mustCompile(t, testDocument("g1"))
	snap := EmptySnapshot("boot", "inst")
	snap.active = c
	snap.state = ProcessorReady

	permitted := &MatchInput{
		InUser: "module-up-1", InName: "intercept-egress",
		Host: "www.bilibili.com", DstPort: 443, Network: NetworkTCP,
	}
	if _, ok := snap.ResolveEgress(permitted); !ok {
		t.Fatal("a permitted destination was refused")
	}

	for name, probe := range map[string]*MatchInput{
		"destination outside the allowlist": {
			InUser: "module-up-1", InName: "intercept-egress",
			Host: "unrelated.test", DstPort: 443, Network: NetworkTCP,
		},
		"permitted host on an unlisted port": {
			InUser: "module-up-1", InName: "intercept-egress",
			Host: "www.bilibili.com", DstPort: 8080, Network: NetworkTCP,
		},
		"no destination at all": {
			InUser: "module-up-1", InName: "intercept-egress", Network: NetworkTCP,
		},
	} {
		t.Run(name, func(t *testing.T) {
			if _, ok := snap.ResolveEgress(probe); ok {
				t.Fatal("the capability authorized a destination outside its allowlist")
			}
		})
	}
}

// The egress stage is evaluated before the client stage, so a capability
// honoured on an ordinary inbound would let a client skip client matching
// entirely by authenticating with the credential.
func TestCapabilityIsBoundToItsListener(t *testing.T) {
	c := mustCompile(t, testDocument("g1"))
	snap := EmptySnapshot("boot", "inst")
	snap.active = c
	snap.state = ProcessorReady

	wrongListener := &MatchInput{
		InUser: "module-up-1", InName: "client-in",
		Host: "www.bilibili.com", DstPort: 443, Network: NetworkTCP,
	}
	if _, ok := snap.ResolveEgress(wrongListener); ok {
		t.Fatal("a capability was honoured on an inbound it is not bound to")
	}
}

// A capability with an empty allowlist authorizes nothing, so accepting the
// document would publish a capability that can never be used — fail at
// validation instead of at every dial.
func TestCapabilityWithNoDestinationsIsRejected(t *testing.T) {
	d := testDocument("g1")
	d.Egress.Capabilities[0].Bindings[0].Destinations = nil
	if err := d.Validate(DefaultQuotas()); err == nil {
		t.Fatal("a capability with an empty destination allowlist was accepted")
	}
	d = testDocument("g1")
	d.Egress.Capabilities[0].Listener = ""
	if err := d.Validate(DefaultQuotas()); err == nil {
		t.Fatal("a capability with no listener was accepted")
	}
}

// The destination allowlist is part of the authorization, so a change to it
// must be a different generation.
func TestDestinationAllowlistIsInTheDigest(t *testing.T) {
	a := testDocument("g1")
	b := testDocument("g1")
	b.Egress.Capabilities[0].Bindings[0].Destinations = append(b.Egress.Capabilities[0].Bindings[0].Destinations,
		DestinationRule{Kind: SelectorDomain, Value: "extra.test"})
	if ComputeDigests(a).Projection == ComputeDigests(b).Projection {
		t.Fatal("widening the destination allowlist did not change the digest")
	}
}

// PublicOnly must actually deny something, or it is a field that claims a
// protection nothing provides. This is the half that is implementable without
// per-adapter pinned dialing: a destination whose address is already known.
func TestPublicOnlyRefusesNonGlobalDestinations(t *testing.T) {
	d := testDocument("g1")
	d.Egress.Capabilities[0].Bindings[0].Destinations = []DestinationRule{
		{Kind: SelectorIPCIDR, Value: "0.0.0.0/0"},
		{Kind: SelectorDomainSuffix, Value: "bilibili.com"},
	}
	c := mustCompile(t, d)
	snap := EmptySnapshot("boot", "inst")
	snap.active = c
	snap.state = ProcessorReady

	for name, addr := range map[string]string{
		"loopback":   "127.0.0.1",
		"private":    "10.0.0.5",
		"link-local": "169.254.169.254",
		"cgnat":      "100.64.0.1",
	} {
		t.Run(name, func(t *testing.T) {
			if _, ok := snap.ResolveEgress(&MatchInput{
				InUser: "module-up-1", InName: "intercept-egress",
				DstIP: netip.MustParseAddr(addr), DstPort: 443, Network: NetworkTCP,
			}); ok {
				t.Fatalf("a public-only capability reached %s", addr)
			}
		})
	}

	if _, ok := snap.ResolveEgress(&MatchInput{
		InUser: "module-up-1", InName: "intercept-egress",
		DstIP: netip.MustParseAddr("203.0.113.7"), DstPort: 443, Network: NetworkTCP,
	}); !ok {
		t.Fatal("a public-only capability was refused a globally routable destination")
	}
}

// A gateway that restarts and resumes an existing generation never commits, so
// the readiness sweeper has to be running on that path too. It is what fails
// captures closed when a lease lapses on an idle link, without waiting for
// traffic to arrive and notice.
//
// Nothing here calls RefreshReadiness. That is the whole point: the function
// was already correct and already covered, and the only test driving it called
// it by hand, so it proved the function worked rather than that anything ran
// it. On the recovery path nothing did.
func TestRecoveredGenerationSweepsReadinessWithoutACommit(t *testing.T) {
	dir := t.TempDir()
	hooks := Hooks{ProcessorProxies: func() map[string]string {
		return map[string]string{"MODULE-INTERCEPT": "MODULE-INTERCEPT"}
	}}

	store, err := OpenStore(dir, "5gpn")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	first := NewManager(store, "5gpn", hooks)
	if _, err := first.Stage(testDocument("g1")); err != nil {
		t.Fatalf("stage: %v", err)
	}
	readyLease(t, first, "g1")
	if _, err := first.Commit(CommitRequest{GenerationID: "g1"}); err != nil {
		t.Fatalf("commit: %v", err)
	}
	first.Close()

	// The restart. This manager only ever recovers.
	store2, err := OpenStore(dir, "5gpn")
	if err != nil {
		t.Fatalf("reopen store: %v", err)
	}
	second := NewManager(store2, "5gpn", hooks)
	defer second.Close()
	second.leases = NewLeaseRegistry(20 * time.Millisecond)
	second.sweepInterval = time.Millisecond
	if err := second.Recover(); err != nil {
		t.Fatalf("recover: %v", err)
	}

	if _, err := second.RegisterReadiness("proc", "inst1", "g1", "", "", 0, 0); err != nil {
		t.Fatalf("register readiness: %v", err)
	}
	if got := second.Snapshot().State(); got != ProcessorReady {
		t.Fatalf("state after attestation = %s, want ready", got)
	}

	// Assert the held state, not the readback. Readback rewrites the state it
	// reports when the lease is gone, so reading it here would pass whether or
	// not the sweeper ever ran — which is exactly how this went unnoticed.
	deadline := time.Now().Add(2 * time.Second)
	for {
		if second.Snapshot().State() == ProcessorNotReady {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("the lapsed lease never moved the held state off %s; the sweeper is not running after a recovery",
				second.Snapshot().State())
		}
		time.Sleep(2 * time.Millisecond)
	}
}

// One credential, several groups. This is the whole point of binding the group
// to the destination rather than to the capability: a processor whose
// extensions were bound to different egress groups presents the single
// credential it authenticates with, and mihomo decides which group each
// connection leaves through from where it is going.
//
// The alternative -- a credential per group -- would put that choice in the
// processor, which is exactly what "the processor never names a group" forbids.
func TestOneCredentialResolvesEachDestinationToItsOwnGroup(t *testing.T) {
	d := testDocument("g1")
	d.Egress.Capabilities = []EgressCapability{{
		ID: "module-up-1", Listener: "intercept-egress",
		Bindings: []EgressBinding{
			{Group: "Proxies", Destinations: []DestinationRule{
				{Kind: SelectorDomain, Value: "proxied.test", Ports: []PortRange{{From: 443, To: 443}}},
			}},
			{Group: "DIRECT", AllowDirect: true, Destinations: []DestinationRule{
				{Kind: SelectorDomain, Value: "unproxied.test", Ports: []PortRange{{From: 443, To: 443}}},
			}},
		},
	}}
	c := mustCompile(t, d)
	snap := EmptySnapshot("boot", "inst")
	snap.active = c
	snap.state = ProcessorReady

	for host, want := range map[string]string{
		"proxied.test":   "Proxies",
		"unproxied.test": "DIRECT",
	} {
		res, ok := snap.ResolveEgress(&MatchInput{
			Host: host, InUser: "module-up-1", InName: "intercept-egress",
			DstPort: 443, Network: NetworkTCP,
		})
		if !ok {
			t.Fatalf("%s was not authorized by the one credential that covers it", host)
		}
		if res.Binding.Group != want {
			t.Fatalf("%s resolved to group %q, want %q", host, res.Binding.Group, want)
		}
		if res.Capability.ID != "module-up-1" {
			t.Fatalf("%s resolved capability %q", host, res.Capability.ID)
		}
	}

	// A destination in no binding is still refused. Spanning groups must not
	// have widened what the credential reaches.
	if _, ok := snap.ResolveEgress(&MatchInput{
		Host: "elsewhere.test", InUser: "module-up-1", InName: "intercept-egress",
		DstPort: 443, Network: NetworkTCP,
	}); ok {
		t.Fatal("a destination outside every binding was authorized")
	}
}

// Which binding covers a destination is part of the authorization, so moving a
// destination between groups must be a different generation.
func TestBindingGroupIsInTheDigest(t *testing.T) {
	a := testDocument("g1")
	b := testDocument("g1")
	b.Egress.Capabilities[0].Bindings[0].Group = "Other"
	if ComputeDigests(a).Projection == ComputeDigests(b).Projection {
		t.Fatal("re-pointing a binding at another group did not change the digest")
	}
	if CapabilitySetDigest(a.Egress.Capabilities) == CapabilitySetDigest(b.Egress.Capabilities) {
		t.Fatal("re-pointing a binding at another group did not change the capability set digest")
	}
}

// A binding with no group, or a capability with no bindings, authorizes
// nothing. Both must fail at validation rather than at every dial.
func TestCapabilityWithNoUsableBindingIsRejected(t *testing.T) {
	d := testDocument("g1")
	d.Egress.Capabilities[0].Bindings = nil
	if err := d.Validate(DefaultQuotas()); err == nil {
		t.Fatal("a capability with no bindings was accepted")
	}
	d = testDocument("g1")
	d.Egress.Capabilities[0].Bindings[0].Group = ""
	if err := d.Validate(DefaultQuotas()); err == nil {
		t.Fatal("a binding with no group was accepted")
	}
}

// The destination quota bounds the credential, not the binding: splitting the
// same allowlist across more bindings must not buy a larger one.
func TestDestinationQuotaCountsEveryBinding(t *testing.T) {
	q := DefaultQuotas()
	half := q.MaxCapabilityDestinations/2 + 1
	fill := func(n int) []DestinationRule {
		out := make([]DestinationRule, 0, n)
		for i := 0; i < n; i++ {
			out = append(out, DestinationRule{Kind: SelectorDomain, Value: fmt.Sprintf("h%d.test", i)})
		}
		return out
	}
	d := testDocument("g1")
	d.Egress.Capabilities[0].Bindings = []EgressBinding{
		{Group: "Proxies", Destinations: fill(half)},
		{Group: "DIRECT", AllowDirect: true, Destinations: fill(half)},
	}
	if err := d.Validate(q); err == nil {
		t.Fatalf("%d destinations across two bindings passed a limit of %d", 2*half, q.MaxCapabilityDestinations)
	}
}

// A store this build cannot reconstruct must not take the gateway down.
//
// Recovery used to return an error here, and the host turns that into a fatal
// config error: the process exits, systemd restarts it, it exits again, and DNS
// and the console go with it for as long as the store stays broken. The reason
// was sound -- quarantine rejects the generation's own capture matches, and with
// no readable document there are none to reject, so refusing was the only
// fail-closed answer available. Sealing is the answer that was missing.
func TestRecoverSealsInsteadOfRefusingToStart(t *testing.T) {
	dir := t.TempDir()
	store, err := OpenStore(dir, "5gpn")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	hooks := Hooks{ProcessorProxies: func() map[string]string {
		return map[string]string{"MODULE-INTERCEPT": "MODULE-INTERCEPT"}
	}}
	first := NewManager(store, "5gpn", hooks)
	defer first.Close()
	if _, err := first.Stage(testDocument("g1")); err != nil {
		t.Fatalf("stage: %v", err)
	}
	readyLease(t, first, "g1")
	if _, err := first.Commit(CommitRequest{GenerationID: "g1"}); err != nil {
		t.Fatalf("commit: %v", err)
	}

	// Corrupt the artifact the pointer names, leaving the pointer intact. This
	// is the shape an upgrade produces when the document schema moves.
	for _, name := range []string{
		filepath.Join(dir, "5gpn", "generations", "g1.json"),
		filepath.Join(dir, "generations", "g1.json"),
	} {
		if _, statErr := os.Stat(name); statErr == nil {
			if err := os.WriteFile(name, []byte("{\"corrupt\":true}"), 0o600); err != nil {
				t.Fatalf("corrupt generation: %v", err)
			}
		}
	}

	store2, err := OpenStore(dir, "5gpn")
	if err != nil {
		t.Fatalf("reopen store: %v", err)
	}
	second := NewManager(store2, "5gpn", hooks)
	defer second.Close()
	if err := second.Recover(); err != nil {
		t.Fatalf("recover returned %v; an unreadable store must be served through, "+
			"not turned into a fatal that crash-loops the gateway", err)
	}

	snap := second.Snapshot()
	// Fail CLOSED, not open. With no document, "captured" is exactly what cannot
	// be known, so everything reaching the anchor rejects. Returning no-match
	// would drop captured hosts onto the operator's own rules -- the bypass the
	// anchors exist to prevent, and the reason refusing to start looked correct.
	for _, host := range []string{"www.bilibili.com", "unrelated.example.com"} {
		d := snap.MatchClient(&MatchInput{Host: host, DstPort: 443, Network: NetworkTCP})
		if !d.Matched || d.Action != ActionReject {
			t.Fatalf("sealed match for %s = %+v, want reject", host, d)
		}
	}
	// And no capability resolves, so a processor credential buys nothing either.
	if _, ok := snap.ResolveEgress(&MatchInput{
		Host: "origin.test", InUser: "module-up-1", InName: "intercept-egress",
		DstPort: 443, Network: NetworkTCP,
	}); ok {
		t.Fatal("a sealed snapshot authorized an egress capability")
	}
}

// Sealing is a holding state, not a latch: the commit that supplies a document
// is exactly what it was waiting for, and traffic must flow again after it.
func TestCommitClearsTheSeal(t *testing.T) {
	m := newTestManager(t)
	defer m.Close()

	sealed := m.holder.Load().clone()
	sealed.sealed = true
	m.holder.Store(sealed)
	if d := m.Snapshot().MatchClient(&MatchInput{Host: "anything.test", DstPort: 443, Network: NetworkTCP}); !d.Matched || d.Action != ActionReject {
		t.Fatalf("seal fixture is not rejecting: %+v", d)
	}

	if _, err := m.Stage(testDocument("g1")); err != nil {
		t.Fatalf("stage: %v", err)
	}
	readyLease(t, m, "g1")
	if _, err := m.Commit(CommitRequest{GenerationID: "g1"}); err != nil {
		t.Fatalf("commit: %v", err)
	}

	snap := m.Snapshot()
	if d := snap.MatchClient(&MatchInput{Host: "unrelated.example.com", DstPort: 443, Network: NetworkTCP}); d.Matched {
		t.Fatalf("still rejecting unrelated traffic after a commit: %+v", d)
	}
	if d := snap.MatchClient(&MatchInput{Host: "www.bilibili.com", DstPort: 443, Network: NetworkTCP}); !d.Matched || d.Action != ActionCapture {
		t.Fatalf("captured host after commit = %+v, want capture", d)
	}
}

// An extension's network permission names no host, so the binding that carries
// it cannot name one either. These pin the three properties that keep that from
// becoming an accident: it is explicit, it is alone, and it is last.
func TestUnboundedEgressBindingAuthorizesAnyDestination(t *testing.T) {
	d := testDocument("g1")
	d.Egress.Capabilities[0].Bindings = append(d.Egress.Capabilities[0].Bindings, EgressBinding{
		Group: "Japan", Unbounded: true,
	})
	c := mustCompile(t, d)
	snap := EmptySnapshot("boot", "inst")
	snap.active = c
	snap.state = ProcessorReady

	// The allowlisted destination still resolves through its own binding, so an
	// unbounded binding beside it does not swallow the narrower decision.
	bind, ok := snap.ResolveEgress(egressProbe("module-up-1"))
	if !ok || bind.Binding.Group != "Proxies" {
		t.Fatalf("allowlisted destination resolved to %+v, %t", bind, ok)
	}

	// Anything else reaches the unbounded binding instead of failing closed.
	elsewhere := &MatchInput{
		InUser: "module-up-1", InName: "intercept-egress",
		Host: "weatherkit.pages.dev", DstPort: 443, Network: NetworkTCP,
	}
	bind, ok = snap.ResolveEgress(elsewhere)
	if !ok || bind.Binding.Group != "Japan" {
		t.Fatalf("unlisted destination resolved to %+v, %t", bind, ok)
	}

	// The listener check is not relaxed by it.
	wrongListener := *elsewhere
	wrongListener.InName = "other"
	if _, ok := snap.ResolveEgress(&wrongListener); ok {
		t.Fatal("an unbounded binding authorized the wrong listener")
	}
}

func TestUnboundedEgressBindingMustBeExplicitAloneAndLast(t *testing.T) {
	t.Parallel()
	for name, mutate := range map[string]func(*Document){
		"with destinations": func(d *Document) {
			d.Egress.Capabilities[0].Bindings[0].Unbounded = true
		},
		"not last": func(d *Document) {
			caps := &d.Egress.Capabilities[0]
			caps.Bindings = append([]EgressBinding{{Group: "Japan", Unbounded: true}}, caps.Bindings...)
		},
		"still empty when bounded": func(d *Document) {
			d.Egress.Capabilities[0].Bindings[0].Destinations = nil
		},
	} {
		t.Run(name, func(t *testing.T) {
			d := testDocument("g1")
			mutate(d)
			if err := d.Validate(DefaultQuotas()); err == nil {
				t.Fatal("document was accepted")
			}
		})
	}
}

// A widened policy must not hash as an unchanged one.
func TestUnboundedBindingChangesTheCapabilityDigest(t *testing.T) {
	bounded := testDocument("g1")
	unbounded := testDocument("g1")
	unbounded.Egress.Capabilities[0].Bindings = []EgressBinding{{Group: "Proxies", Unbounded: true}}
	if CapabilitySetDigest(bounded.Egress.Capabilities) == CapabilitySetDigest(unbounded.Egress.Capabilities) {
		t.Fatal("an unbounded binding hashed the same as an allowlisted one")
	}
}

// A coordinator reads back, then commits with what it read. Readback must
// therefore report the LIVE core revision, not the one recorded in the active
// snapshot.
//
// Reporting the snapshot's revision wedges the overlay permanently: after any
// reload that moves the dependency closure, every readback keeps returning the
// stale value, every commit CASes against it, and no routing change can land
// again until the process restarts. That is a silent, total loss of control
// over the data plane, so it is pinned here rather than left to review.
func TestReadbackReportsTheLiveCoreRevision(t *testing.T) {
	store, err := OpenStore(t.TempDir(), "5gpn")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	live := uint64(1)
	m := NewManager(store, "5gpn", Hooks{
		CoreRevision:     func() uint64 { return live },
		LiveCoreRevision: func() uint64 { return live },
		ProcessorProxies: func() map[string]string { return map[string]string{"MODULE-INTERCEPT": "MODULE-INTERCEPT"} },
	})
	t.Cleanup(m.Close)

	if _, err := m.Stage(testDocument("g1")); err != nil {
		t.Fatalf("stage g1: %v", err)
	}
	if _, err := m.Commit(CommitRequest{GenerationID: "g1", ExpectedCoreRevision: live}); err != nil {
		t.Fatalf("commit g1: %v", err)
	}
	if rb := m.Readback(); rb.CoreRevision != 1 || rb.ActiveCoreRevision != 1 {
		t.Fatalf("after commit: core=%d active=%d, want 1/1", rb.CoreRevision, rb.ActiveCoreRevision)
	}

	// The host reloads its configuration and the closure moves. The active
	// generation is still the one validated at revision 1.
	live = 4

	rb := m.Readback()
	if rb.CoreRevision != 4 {
		t.Fatalf("readback core revision = %d, want the live 4", rb.CoreRevision)
	}
	if rb.ActiveCoreRevision != 1 {
		t.Fatalf("active core revision = %d, want the 1 it was validated at", rb.ActiveCoreRevision)
	}

	// The whole point: a commit built from that readback has to be accepted.
	if _, err := m.Stage(testDocument("g2")); err != nil {
		t.Fatalf("stage g2: %v", err)
	}
	if _, err := m.Commit(CommitRequest{
		GenerationID:         "g2",
		ExpectedActive:       rb.ActiveGeneration,
		ExpectedCoreRevision: rb.CoreRevision,
	}); err != nil {
		t.Fatalf("a commit CAS'd on the readback must succeed, got %v", err)
	}
}
