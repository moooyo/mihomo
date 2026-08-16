package dns

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/metacubex/mihomo/5gpn/state"
)

func testSubscriptionRule(value, format string) Rule {
	return Rule{
		ID:              "test-list",
		Kind:            KindSubscription,
		Value:           value,
		Intent:          IntentProxy,
		Enabled:         true,
		Format:          format,
		IntervalSeconds: 3600,
	}
}

func newSubscriptionHarness(t *testing.T, rule Rule) (*subscriptions, *Service, subscriptionFetchToken, string) {
	t.Helper()
	dir := t.TempDir()
	rulesDir := filepath.Join(dir, "rules")
	if err := os.MkdirAll(rulesDir, 0o700); err != nil {
		t.Fatal(err)
	}
	doc, err := state.New(filepath.Join(dir, "dns.json"), Document{
		Policy: Policy{Rules: []Rule{rule}, Fallback: FallbackAuto},
	})
	if err != nil {
		t.Fatal(err)
	}
	svc := &Service{doc: doc, rulesDir: rulesDir}
	subs := &subscriptions{svc: svc, status: make(map[string]SubscriptionStatus)}
	_, revision := svc.Document()
	token := subscriptionFetchToken{revision: revision, ruleID: rule.ID, source: sourceOf(rule)}
	return subs, svc, token, subscriptionCachePath(rulesDir, rule.ID)
}

func TestSubscriptionEmptyOrWrongFormatPreservesCache(t *testing.T) {
	for _, tc := range []struct {
		name   string
		format string
		raw    []byte
	}{
		{name: "empty body", format: "plain", raw: nil},
		{name: "format drift", format: "dnsmasq", raw: []byte("example.com\n")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rule := testSubscriptionRule("https://lists.example/current", tc.format)
			subs, _, token, cachePath := newSubscriptionHarness(t, rule)
			const previous = "previous.example\n"
			if err := state.WriteFile(cachePath, []byte(previous)); err != nil {
				t.Fatal(err)
			}

			parsed, err := parseDomains(tc.format, tc.raw)
			if err != nil {
				t.Fatalf("parseDomains: %v", err)
			}
			if len(parsed) != 0 {
				t.Fatalf("test input parsed as %v, want no usable domains", parsed)
			}
			subs.downloadFn = func(context.Context, Rule) ([]string, error) {
				return parsed, nil
			}

			if subs.fetch(rule, token) {
				t.Error("an empty parsed result was published")
			}
			raw, err := os.ReadFile(cachePath)
			if err != nil {
				t.Fatal(err)
			}
			if string(raw) != previous {
				t.Fatalf("cache = %q, want previous complete cache %q", raw, previous)
			}
			status := subs.snapshot()
			if len(status) != 1 || status[0].Error == "" {
				t.Fatalf("status = %+v, want a recorded empty-list failure", status)
			}
		})
	}
}

func TestSubscriptionSourceChangeIsImmediatelyDue(t *testing.T) {
	oldRule := testSubscriptionRule("https://lists.example/old", "plain")
	subs, _, _, _ := newSubscriptionHarness(t, oldRule)
	subs.record(oldRule.ID, sourceOf(oldRule), SubscriptionStatus{
		RuleID: oldRule.ID, LastAttempt: time.Now(), LastSuccess: time.Now(), Entries: 42,
	}, true)
	if subs.due(oldRule) {
		t.Error("an unchanged source with a recent success is due")
	}

	for _, changed := range []Rule{
		func() Rule { r := oldRule; r.Value = "https://lists.example/new"; return r }(),
		func() Rule { r := oldRule; r.Format = "hosts"; return r }(),
	} {
		if !subs.due(changed) {
			t.Errorf("source change to %q/%q was not immediately due", changed.Value, changed.Format)
		}
		subs.record(changed.ID, sourceOf(changed), SubscriptionStatus{
			RuleID: changed.ID, LastAttempt: time.Now(), Error: "fetch failed",
		}, false)
		if !subs.due(changed) {
			t.Errorf("failed new source %q/%q stopped being due", changed.Value, changed.Format)
		}
	}
}

func TestSubscriptionStopCancelsCurrentFetchAndWaits(t *testing.T) {
	rule := testSubscriptionRule("https://lists.example/slow", "plain")
	_, svc, _, _ := newSubscriptionHarness(t, rule)
	ctx, cancel := context.WithCancel(context.Background())
	started := make(chan struct{})
	stopped := make(chan struct{})
	subs := &subscriptions{
		svc: svc, stop: make(chan struct{}), wake: make(chan struct{}, 1), done: make(chan struct{}),
		ctx: ctx, cancel: cancel, status: make(map[string]SubscriptionStatus),
		downloadFn: func(ctx context.Context, _ Rule) ([]string, error) {
			close(started)
			<-ctx.Done()
			close(stopped)
			return nil, ctx.Err()
		},
	}
	go subs.run()
	<-started
	subs.stopRun()
	select {
	case <-stopped:
	default:
		t.Fatal("stopRun returned before the current fetch observed cancellation")
	}
}

func TestSubscriptionStaleFetchCannotReplaceNewSourceCache(t *testing.T) {
	oldRule := testSubscriptionRule("https://lists.example/old", "plain")
	subs, svc, oldToken, cachePath := newSubscriptionHarness(t, oldRule)
	const previous = "previous.example\n"
	if err := state.WriteFile(cachePath, []byte(previous)); err != nil {
		t.Fatal(err)
	}

	started := make(chan struct{})
	releaseDownload := make(chan struct{})
	released := false
	defer func() {
		if !released {
			close(releaseDownload)
		}
	}()
	subs.downloadFn = func(context.Context, Rule) ([]string, error) {
		close(started)
		<-releaseDownload
		return []string{"stale.example"}, nil
	}
	fetched := make(chan bool, 1)
	go func() { fetched <- subs.fetch(oldRule, oldToken) }()

	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("stale fetch did not start")
	}

	newRule := oldRule
	newRule.Value = "https://lists.example/new"
	svc.updateMu.Lock()
	snapshot := svc.doc.Get()
	_, err := svc.doc.Update(snapshot.Revision, func(d Document) (Document, error) {
		d.Policy.Rules[0] = newRule
		return d, nil
	})
	svc.updateMu.Unlock()
	if err != nil {
		t.Fatal(err)
	}

	close(releaseDownload)
	released = true
	select {
	case changed := <-fetched:
		if changed {
			t.Error("fetch for the old document revision was published")
		}
	case <-time.After(time.Second):
		t.Fatal("stale fetch did not finish")
	}

	// Revision and source are independent checks. A token carrying the current
	// revision but the old source must still be refused.
	_, currentRevision := svc.Document()
	wrongSource := subscriptionFetchToken{revision: currentRevision, ruleID: oldRule.ID, source: sourceOf(oldRule)}
	published, err := subs.publish(wrongSource, []string{"also-stale.example"})
	if err != nil {
		t.Fatal(err)
	}
	if published {
		t.Error("a mismatched source was published under the current revision")
	}

	raw, err := os.ReadFile(cachePath)
	if err != nil {
		t.Fatal(err)
	}
	if string(raw) != previous {
		t.Fatalf("cache = %q, want preserved cache %q", raw, previous)
	}
	if !subs.due(newRule) {
		t.Error("the replacement source was not left immediately due")
	}
}
