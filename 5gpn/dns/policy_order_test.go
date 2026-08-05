package dns

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// A subscription is one rule that expands to tens of thousands of names, and
// classify takes the first match. So which of "my exception" and "the imported
// list" wins used to be decided by whichever sat earlier in one array -- a fair
// question to ask of a list the operator could see and reorder, and not a fair
// one once the console split the two kinds into separate dialogs where that
// shared index is invisible.
//
// The contract these tests pin: hand-written rules are evaluated before every
// subscription, order inside each group is the operator's, and the grouping is
// applied to the stored document rather than at match time -- so what a reader
// of dns.json sees is what runs.

func ruleIDs(rules []Rule) []string {
	out := make([]string, 0, len(rules))
	for _, r := range rules {
		out = append(out, r.ID)
	}
	return out
}

func sameIDs(t *testing.T, what string, got []Rule, want ...string) {
	t.Helper()
	ids := ruleIDs(got)
	if len(ids) != len(want) {
		t.Fatalf("%s: got %v, want %v", what, ids, want)
	}
	for i := range want {
		if ids[i] != want[i] {
			t.Fatalf("%s: got %v, want %v", what, ids, want)
		}
	}
}

// openForTest opens a service and shuts it down with the test. Open starts the
// subscription loop, so leaving one running leaks a goroutine into every later
// test in the package.
func openForTest(t *testing.T, dir string) *Service {
	t.Helper()
	svc, err := Open(dir)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		svc.Shutdown(ctx)
	})
	return svc
}

func TestOrderedGroupsHandRulesFirstAndIsStable(t *testing.T) {
	p := Policy{
		Fallback: FallbackAuto,
		Rules: []Rule{
			{ID: "sub-a", Kind: KindSubscription, Value: "https://example.com/a.txt"},
			{ID: "hand-a", Kind: KindDomain, Value: "one.example"},
			{ID: "sub-b", Kind: KindSubscription, Value: "https://example.com/b.txt"},
			{ID: "hand-b", Kind: KindDomainSuffix, Value: "two.example"},
		},
	}

	got := p.ordered()
	sameIDs(t, "ordered", got.Rules, "hand-a", "hand-b", "sub-a", "sub-b")

	// The operator's order inside each group survives: this is a partition, not
	// a sort. Re-grouping an already-grouped policy changes nothing.
	sameIDs(t, "idempotent", got.ordered().Rules, "hand-a", "hand-b", "sub-a", "sub-b")

	if p.rulesAreGrouped() {
		t.Error("rulesAreGrouped accepted a subscription sitting ahead of a hand-written rule")
	}
	if !got.rulesAreGrouped() {
		t.Error("rulesAreGrouped rejected a policy it had just grouped")
	}
}

// An empty policy, an all-hand policy and an all-subscription policy are all
// already grouped -- worth pinning because rulesAreGrouped gates a write on
// open, and a false negative there rewrites every document on every boot.
func TestRulesAreGroupedOnDegenerateLists(t *testing.T) {
	for _, tc := range []struct {
		name  string
		rules []Rule
	}{
		{"empty", nil},
		{"hand only", []Rule{{ID: "a", Kind: KindDomain}, {ID: "b", Kind: KindDomainKeyword}}},
		{"subscriptions only", []Rule{{ID: "a", Kind: KindSubscription}, {ID: "b", Kind: KindSubscription}}},
	} {
		if !(Policy{Rules: tc.rules}).rulesAreGrouped() {
			t.Errorf("%s: reported as ungrouped", tc.name)
		}
	}
}

// The behaviour the grouping exists for: a hand-written exception decides a
// name a subscription also covers, no matter which order it was written in.
func TestHandWrittenRuleOutranksASubscriptionCoveringTheSameName(t *testing.T) {
	dir := t.TempDir()
	// The list the operator subscribed to covers the whole domain.
	if err := os.WriteFile(subscriptionCachePath(dir, "gfwlist"), []byte("example.com\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	// Written the wrong way round on purpose: the subscription first.
	p := Policy{
		Fallback: FallbackAuto,
		Rules: []Rule{
			{ID: "gfwlist", Kind: KindSubscription, Value: "https://example.com/l.txt", Intent: IntentProxy, Enabled: true, Format: "plain", IntervalSeconds: 86400},
			{ID: "keepdirect", Kind: KindDomainSuffix, Value: "intranet.example.com", Intent: IntentDirect, Enabled: true},
		},
	}

	compiled, err := compile(p.ordered(), dir)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}

	verdict, rule := compiled.classify("intranet.example.com")
	if rule == nil || rule.ID != "keepdirect" {
		t.Fatalf("decided by %v, want the hand-written rule", rule)
	}
	if verdict.Verdict != "direct" {
		t.Errorf("verdict %q, want direct", verdict.Verdict)
	}

	// And the subscription still decides everything it alone covers.
	verdict, rule = compiled.classify("other.example.com")
	if rule == nil || rule.ID != "gfwlist" {
		t.Fatalf("decided by %v, want the subscription", rule)
	}
	if verdict.Verdict != "proxy" {
		t.Errorf("verdict %q, want proxy", verdict.Verdict)
	}
}

// Every writer goes through Update, so the grouping is applied there rather
// than in the console: the bot and a direct PUT get the same precedence.
func TestUpdateStoresRulesGrouped(t *testing.T) {
	svc := openForTest(t, t.TempDir())

	_, revision := svc.Document()
	doc, _, err := svc.Update(revision, func(d Document) (Document, error) {
		// Same reasons startService does this: a bound DoT listener drags a
		// certificate lineage into a test about rule order, and the default
		// document's fixed debug port is not bindable on every machine.
		d.Listen.DoT = ""
		d.Listen.Debug = freePort(t)
		d.Listen.Origin = freePort(t)
		d.Policy = Policy{
			Fallback: FallbackAuto,
			Rules: []Rule{
				{ID: "sub", Kind: KindSubscription, Value: "https://example.com/l.txt", Intent: IntentProxy, Enabled: true, Format: "plain", IntervalSeconds: 86400},
				{ID: "hand", Kind: KindDomain, Value: "one.example", Intent: IntentBlock, Enabled: true},
			},
		}
		return d, nil
	})
	if err != nil {
		t.Fatalf("Update: %v", err)
	}
	sameIDs(t, "stored", doc.Policy.Rules, "hand", "sub")
}

// A gateway configured while the two kinds were one interleaved list converges
// on open, not on the next write -- otherwise it would keep resolving in the
// old precedence for as long as nobody touched the policy, while the console
// showed the new one.
func TestOpenGroupsAnInterleavedDocument(t *testing.T) {
	dir := t.TempDir()
	seed := Document{
		Gateway:   "198.51.100.1",
		Upstreams: Upstreams{China: []string{"223.5.5.5:53"}, Trust: []string{"1.1.1.1:53"}},
		Policy: Policy{
			Fallback: FallbackAuto,
			Rules: []Rule{
				{ID: "sub", Kind: KindSubscription, Value: "https://example.com/l.txt", Intent: IntentProxy, Enabled: true, Format: "plain", IntervalSeconds: 86400},
				{ID: "hand", Kind: KindDomain, Value: "one.example", Intent: IntentBlock, Enabled: true},
			},
		},
	}
	raw, err := json.Marshal(seed)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "dns.json"), raw, 0o600); err != nil {
		t.Fatal(err)
	}

	svc := openForTest(t, dir)
	doc, _ := svc.Document()
	sameIDs(t, "after open", doc.Policy.Rules, "hand", "sub")

	// It converged on disk, not just in memory.
	again, _ := openForTest(t, dir).Document()
	sameIDs(t, "after reopen", again.Policy.Rules, "hand", "sub")
}
