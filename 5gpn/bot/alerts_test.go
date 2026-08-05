package bot

import (
	"strings"
	"testing"
	"time"
)

// Alerts are transitions. A monitor that reported a state every minute would be
// ignored inside a day, and the minute it started being true -- the only minute
// that mattered -- would look like the ninety before it.

func TestACertificateThatStopsCoveringAHostIsAnnouncedOnce(t *testing.T) {
	now := time.Now()
	healthy := Status{
		InterceptionInstalled: true, EnabledExtensions: 1,
		CertificateLoaded: true, CertificateCovers: true,
		CertificateNotAfter: now.Add(90 * 24 * time.Hour),
	}
	key, text := certificateCondition(healthy, now)
	if key != "ok" || text != "" {
		t.Fatalf("a healthy certificate produced %q/%q", key, text)
	}

	broken := healthy
	broken.CertificateCovers = false
	broken.MissingHosts = []string{"shop.example.com"}
	brokenKey, brokenText := certificateCondition(broken, now)
	if brokenKey == key {
		t.Fatal("losing coverage did not change the condition")
	}
	if !strings.Contains(brokenText, "shop.example.com") {
		t.Errorf("the alert does not name the host: %q", brokenText)
	}

	// The same state again is the same key, so nothing is re-announced.
	repeatKey, _ := certificateCondition(broken, now)
	if repeatKey != brokenKey {
		t.Errorf("the same condition produced two keys: %q then %q", brokenKey, repeatKey)
	}

	// A different missing set is a different incident and must be announced.
	worse := broken
	worse.MissingHosts = []string{"shop.example.com", "api.example.com"}
	if worseKey, _ := certificateCondition(worse, now); worseKey == brokenKey {
		t.Error("a wider gap in coverage was treated as the same incident")
	}
}

// A gateway that has enabled nothing has requested no capture host, so no leaf
// has been minted. Reporting that as a certificate failure would alert every
// gateway on its first day, about the state it shipped in.
func TestAnAbsentCertificateIsOnlyAnIncidentWhenSomethingNeedsIt(t *testing.T) {
	now := time.Now()
	idle := Status{InterceptionInstalled: true, EnabledExtensions: 0}
	if key, text := certificateCondition(idle, now); text != "" {
		t.Errorf("an idle gateway was alerted: %q/%q", key, text)
	}
	waiting := Status{InterceptionInstalled: true, EnabledExtensions: 2}
	if _, text := certificateCondition(waiting, now); text == "" {
		t.Error("an enabled extension with no certificate was not alerted")
	}
}

func TestAnExpiringCertificateIsAnnouncedBeforeItExpires(t *testing.T) {
	now := time.Now()
	soon := Status{
		InterceptionInstalled: true, EnabledExtensions: 1,
		CertificateLoaded: true, CertificateCovers: true,
		CertificateNotAfter: now.Add(3 * 24 * time.Hour),
	}
	key, text := certificateCondition(soon, now)
	if text == "" {
		t.Fatalf("a certificate expiring in three days produced no alert (key %q)", key)
	}
	distant := soon
	distant.CertificateNotAfter = now.Add(60 * 24 * time.Hour)
	if _, text := certificateCondition(distant, now); text != "" {
		t.Errorf("a certificate expiring in sixty days was alerted: %q", text)
	}
}

// Off with nothing installed is the state the gateway ships in, not an event.
func TestTheMasterSwitchIsOnlyAnEventWhenSomethingIsInstalled(t *testing.T) {
	if _, text := interceptionCondition(Status{Extensions: 0}); text != "" {
		t.Errorf("a gateway with no extensions was alerted: %q", text)
	}
	if _, text := interceptionCondition(Status{Extensions: 2}); text == "" {
		t.Error("installed extensions with the master off were not alerted")
	}
	if _, text := interceptionCondition(Status{Extensions: 2, InterceptionEnabled: true}); text != "" {
		t.Errorf("a working gateway was alerted: %q", text)
	}
}

// A refresh in flight during one check is not an incident, so a subscription
// has to be failing for several consecutive checks before it is announced.
func TestASubscriptionMustFailRepeatedlyBeforeItIsAnnounced(t *testing.T) {
	state := &alertState{failing: make(map[string]int)}
	failing := Status{Subscriptions: []Subscription{{Name: "ads", OK: false, Error: "timeout"}}}

	for i := 1; i < subscriptionFailureWindows; i++ {
		if _, text := subscriptionCondition(failing, state); text != "" {
			t.Fatalf("announced after %d windows: %q", i, text)
		}
	}
	key, text := subscriptionCondition(failing, state)
	if text == "" {
		t.Fatalf("never announced after %d windows (key %q)", subscriptionFailureWindows, key)
	}
	if !strings.Contains(text, "ads") {
		t.Errorf("the alert does not name the subscription: %q", text)
	}

	// Recovery clears the counter, so the next failure starts again from one
	// rather than announcing immediately.
	recovered := Status{Subscriptions: []Subscription{{Name: "ads", OK: true}}}
	if key, _ := subscriptionCondition(recovered, state); key != "ok" {
		t.Errorf("recovery produced key %q", key)
	}
	if _, text := subscriptionCondition(failing, state); text != "" {
		t.Errorf("a single failure after recovery was announced: %q", text)
	}
}

// A subscription removed from the document stops being counted, or its stale
// count would keep a removed rule in the alert forever.
func TestARemovedSubscriptionStopsBeingCounted(t *testing.T) {
	state := &alertState{failing: make(map[string]int)}
	failing := Status{Subscriptions: []Subscription{{Name: "ads", OK: false}}}
	for i := 0; i < subscriptionFailureWindows; i++ {
		subscriptionCondition(failing, state)
	}
	if key, _ := subscriptionCondition(Status{}, state); key != "ok" {
		t.Errorf("a removed subscription still reported %q", key)
	}
	if len(state.failing) != 0 {
		t.Errorf("the counter kept %d removed subscriptions", len(state.failing))
	}
}
