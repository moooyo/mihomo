package common

import (
	"testing"

	"github.com/metacubex/mihomo/component/overlay"
	C "github.com/metacubex/mihomo/constant"
)

func buildSnapshot(t *testing.T, ready bool) *overlay.Holder {
	t.Helper()
	doc := &overlay.Document{
		SchemaVersion:    overlay.SchemaVersion,
		Owner:            "5gpn",
		GenerationID:     "g1",
		DocumentRevision: 1,
		TransitionMode:   overlay.TransitionRevoke,
		ProcessorTargets: []overlay.ProcessorTarget{{ID: "p", Name: "MODULE-INTERCEPT"}},
		Client: overlay.ClientOverlay{Rules: []overlay.ClientRule{
			{Kind: overlay.SelectorDomain, Value: "capture.test", Action: overlay.ActionCapture, Processor: "p"},
			{Kind: overlay.SelectorDomain, Value: "deny.test", Action: overlay.ActionReject},
		}},
		Egress: overlay.EgressOverlay{Capabilities: []overlay.EgressCapability{{
			ID: "cap-1", Listener: "intercept-egress",
			Bindings: []overlay.EgressBinding{{
				Group: "Proxies",
				Destinations: []overlay.DestinationRule{
					{Kind: overlay.SelectorDomain, Value: "origin.test",
						Ports: []overlay.PortRange{{From: 443, To: 443}}},
				},
			}},
		}}},
	}
	store, err := overlay.OpenStore(t.TempDir(), "5gpn")
	if err != nil {
		t.Fatalf("store: %v", err)
	}
	m := overlay.NewManager(store, "5gpn", overlay.Hooks{
		ProcessorProxies: func() map[string]string { return map[string]string{"MODULE-INTERCEPT": "MODULE-INTERCEPT"} },
	})
	t.Cleanup(m.Close)
	if _, err := m.Stage(doc); err != nil {
		t.Fatalf("stage: %v", err)
	}
	if ready {
		if _, err := m.RegisterReadiness("proc", "inst", "g1", "", "", 0, 0); err != nil {
			t.Fatalf("readiness: %v", err)
		}
	}
	if _, err := m.Commit(overlay.CommitRequest{GenerationID: "g1"}); err != nil {
		t.Fatalf("commit: %v", err)
	}
	return m.Holder()
}

func anchor(t *testing.T, stage string) *RuntimeOverlay {
	t.Helper()
	a, err := NewRuntimeOverlay("5gpn", stage, nil)
	if err != nil {
		t.Fatalf("anchor %s: %v", stage, err)
	}
	return a
}

func withBinding(t *testing.T, b *Binding) {
	t.Helper()
	prev := OverlayBinding()
	SetOverlayBinding(b)
	t.Cleanup(func() { SetOverlayBinding(prev) })
}

// tunnel silently skips a matched rule whose adapter is absent from the proxies
// map, so an anchor that names a vanished processor would fail OPEN and fall
// through to the operator's rules. It must return a deny instead.
func TestClientAnchorFailsClosedWhenProcessorProxyIsGone(t *testing.T) {
	holder := buildSnapshot(t, true)
	withBinding(t, &Binding{
		Owner:         "5gpn",
		Holder:        holder,
		AdapterExists: func(string) bool { return false },
	})

	matched, adapter := anchor(t, "client").Match(&C.Metadata{Host: "capture.test", NetWork: C.TCP}, C.RuleMatchHelper{})
	if !matched {
		t.Fatal("the anchor fell through when its processor proxy was missing")
	}
	if adapter != "REJECT" {
		t.Fatalf("adapter = %q, want REJECT", adapter)
	}
}

func TestClientAnchorCaptures(t *testing.T) {
	holder := buildSnapshot(t, true)
	withBinding(t, &Binding{
		Owner:         "5gpn",
		Holder:        holder,
		AdapterExists: func(string) bool { return true },
	})

	metadata := &C.Metadata{Host: "capture.test", NetWork: C.TCP}
	matched, adapter := anchor(t, "client").Match(metadata, C.RuleMatchHelper{})
	if !matched || adapter != "MODULE-INTERCEPT" {
		t.Fatalf("matched=%v adapter=%q", matched, adapter)
	}
	// The generation has to reach the tracker, or revocation cannot enumerate
	// the connections it needs to close.
	if metadata.OverlayGeneration != "g1" {
		t.Fatalf("OverlayGeneration = %q, want g1", metadata.OverlayGeneration)
	}
}

// An overlay that selects nothing must be invisible, or every anchored config
// would change the meaning of the operator's rules.
func TestClientAnchorFallsThroughOnNoMatch(t *testing.T) {
	holder := buildSnapshot(t, true)
	withBinding(t, &Binding{Owner: "5gpn", Holder: holder, AdapterExists: func(string) bool { return true }})

	matched, _ := anchor(t, "client").Match(&C.Metadata{Host: "unrelated.test", NetWork: C.TCP}, C.RuleMatchHelper{})
	if matched {
		t.Fatal("the client anchor matched traffic the overlay does not select")
	}
}

func TestEgressAnchorResolvesCapability(t *testing.T) {
	holder := buildSnapshot(t, true)
	withBinding(t, &Binding{Owner: "5gpn", Holder: holder, AdapterExists: func(string) bool { return true }})

	metadata := &C.Metadata{Host: "origin.test", DstPort: 443, NetWork: C.TCP, InName: "intercept-egress", InUser: "cap-1"}
	matched, adapter := anchor(t, "egress").Match(metadata, C.RuleMatchHelper{})
	if !matched || adapter != "Proxies" {
		t.Fatalf("matched=%v adapter=%q", matched, adapter)
	}
	if metadata.OverlayCapability != "cap-1" || metadata.OverlayGeneration != "g1" {
		t.Fatalf("capability=%q generation=%q", metadata.OverlayCapability, metadata.OverlayGeneration)
	}
}

// An unknown capability must not match, so the request continues to the fixed
// deny terminator the structural validator requires immediately after the
// anchor.
func TestEgressAnchorDoesNotMatchUnknownCapability(t *testing.T) {
	holder := buildSnapshot(t, true)
	withBinding(t, &Binding{Owner: "5gpn", Holder: holder, AdapterExists: func(string) bool { return true }})

	matched, _ := anchor(t, "egress").Match(
		&C.Metadata{Host: "origin.test", DstPort: 443, NetWork: C.TCP, InName: "intercept-egress", InUser: "forged"}, C.RuleMatchHelper{})
	if matched {
		t.Fatal("a forged capability matched the egress anchor")
	}
}

// A capability whose group vanished must deny rather than name a proxy tunnel
// would silently skip.
func TestEgressAnchorFailsClosedWhenGroupIsGone(t *testing.T) {
	holder := buildSnapshot(t, true)
	withBinding(t, &Binding{Owner: "5gpn", Holder: holder, AdapterExists: func(string) bool { return false }})

	matched, adapter := anchor(t, "egress").Match(
		&C.Metadata{Host: "origin.test", DstPort: 443, NetWork: C.TCP, InName: "intercept-egress", InUser: "cap-1"}, C.RuleMatchHelper{})
	if !matched || adapter != "REJECT" {
		t.Fatalf("matched=%v adapter=%q, want a REJECT", matched, adapter)
	}
}

// A quarantined generation has no live processor, so its captures deny and its
// capabilities do not resolve.
func TestQuarantinedGenerationDeniesCaptureAndEgress(t *testing.T) {
	holder := buildSnapshot(t, false)
	withBinding(t, &Binding{Owner: "5gpn", Holder: holder, AdapterExists: func(string) bool { return true }})

	matched, adapter := anchor(t, "client").Match(&C.Metadata{Host: "capture.test", NetWork: C.TCP}, C.RuleMatchHelper{})
	if !matched || adapter != "REJECT" {
		t.Fatalf("capture: matched=%v adapter=%q, want a REJECT", matched, adapter)
	}
	if m, _ := anchor(t, "egress").Match(
		&C.Metadata{Host: "origin.test", DstPort: 443, NetWork: C.TCP, InName: "intercept-egress", InUser: "cap-1"}, C.RuleMatchHelper{}); m {
		t.Fatal("a capability resolved against a generation with no ready processor")
	}
}

// An anchor whose owner does not match this process's overlay is inert. That is
// what makes a stale anchor left in an operator's config harmless.
func TestAnchorWithForeignOwnerIsInert(t *testing.T) {
	holder := buildSnapshot(t, true)
	withBinding(t, &Binding{Owner: "5gpn", Holder: holder, AdapterExists: func(string) bool { return true }})

	other, err := NewRuntimeOverlay("someone-else", "client", nil)
	if err != nil {
		t.Fatalf("anchor: %v", err)
	}
	if m, _ := other.Match(&C.Metadata{Host: "capture.test", NetWork: C.TCP}, C.RuleMatchHelper{}); m {
		t.Fatal("an anchor for a different owner matched")
	}
}

// With no overlay configured at all, every anchor is inert and the operator's
// rules decide everything.
func TestAnchorWithoutBindingIsInert(t *testing.T) {
	withBinding(t, nil)
	for _, stage := range []string{"client", "egress"} {
		if m, _ := anchor(t, stage).Match(&C.Metadata{Host: "capture.test", DstPort: 443, InName: "intercept-egress", InUser: "cap-1", NetWork: C.TCP}, C.RuleMatchHelper{}); m {
			t.Fatalf("%s anchor matched with no overlay bound", stage)
		}
	}
}

func TestRuntimeOverlayRuleTypesAreDistinct(t *testing.T) {
	if anchor(t, "client").RuleType() != C.RuntimeOverlayClient {
		t.Fatal("client anchor reports the wrong rule type")
	}
	if anchor(t, "egress").RuleType() != C.RuntimeOverlayEgress {
		t.Fatal("egress anchor reports the wrong rule type")
	}
	if C.RuntimeOverlayClient.String() == "Unknown" || C.RuntimeOverlayEgress.String() == "Unknown" {
		t.Fatal("the new rule types are missing from RuleType.String()")
	}
}
