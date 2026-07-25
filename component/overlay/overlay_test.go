package overlay

import (
	"errors"
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
			ID: "module-up-1", Listener: "intercept-egress", Group: "Proxies", PublicOnly: true,
			Destinations: []DestinationRule{
				{Kind: SelectorDomainSuffix, Value: "bilibili.com", Ports: []PortRange{{From: 80, To: 80}, {From: 443, To: 443}}},
			},
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
				ID: "module-up-2", Listener: "intercept-egress", Group: "Proxies",
				Destinations: []DestinationRule{{Kind: SelectorDomainSuffix, Value: "bilibili.com"}},
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
	d.Egress.Capabilities[0].Destinations = nil
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
	b.Egress.Capabilities[0].Destinations = append(b.Egress.Capabilities[0].Destinations,
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
	d.Egress.Capabilities[0].Destinations = []DestinationRule{
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
