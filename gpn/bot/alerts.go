package bot

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"
)

// Transition-only alerts.
//
// The rule is that a notification names a change, never a state. A monitor that
// reported "the certificate does not cover shop.example.com" every minute would
// be ignored inside a day, and the one that mattered -- the minute it started
// being true -- would be indistinguishable from the ninety before it.
//
// What this deliberately does not claim to detect is the gateway's own death. A
// monitor inside the process cannot report that the process stopped, and a bot
// that goes quiet is indistinguishable from a gateway that is fine and a
// network that is down. An external heartbeat remains the only thing that
// answers that question, and pretending otherwise here would be worse than not
// answering it: an operator would believe silence meant health.

const (
	alertInitialDelay = 30 * time.Second
	alertInterval     = time.Minute
	// A certificate is worth naming before it is a problem. The renewal path is
	// event-driven and normally invisible, so the first sign of it having
	// stopped working is expiry.
	certificateWarningWindow = 14 * 24 * time.Hour
	// How many consecutive checks a subscription must be failing before it is
	// announced. A refresh in flight during one check is not an incident.
	subscriptionFailureWindows = 3
)

// alertState is everything a transition is measured against. Each field holds
// the last *announced* condition, so an alert that could not be delivered is
// retried rather than silently consumed.
type alertState struct {
	certificate  string
	interception string
	subscription string
	failing      map[string]int
}

func (s *Service) runAlerts(ctx context.Context, c *client, doc Document) {
	timer := time.NewTimer(alertInitialDelay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return
	case <-timer.C:
	}

	state := alertState{failing: make(map[string]int)}
	ticker := time.NewTicker(alertInterval)
	defer ticker.Stop()
	for {
		s.checkAlerts(ctx, c, doc.Admins, &state)
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

func (s *Service) checkAlerts(ctx context.Context, c *client, admins []int64, state *alertState) {
	status := s.currentStatus()

	// A gateway whose engine is not installed has nothing to say about
	// certificates or capture, and reporting "not installed" as a transition on
	// every restart would be noise.
	if status.InterceptionInstalled {
		if key, text := certificateCondition(status, time.Now()); key != state.certificate {
			if text == "" || s.notifyAdmins(ctx, c, admins, text) == nil {
				state.certificate = key
			}
		}
		if key, text := interceptionCondition(status); key != state.interception {
			if text == "" || s.notifyAdmins(ctx, c, admins, text) == nil {
				state.interception = key
			}
		}
	}

	if key, text := subscriptionCondition(status, state); key != state.subscription {
		if text == "" || s.notifyAdmins(ctx, c, admins, text) == nil {
			state.subscription = key
		}
	}
}

// certificateCondition names the current certificate condition and what to say
// when it becomes true. An empty text means the condition is worth remembering
// but not worth a message -- which is how a return to healthy re-arms the alert
// without announcing itself twice.
func certificateCondition(status Status, now time.Time) (key, text string) {
	switch {
	case !status.CertificateLoaded:
		// Not an incident on a gateway that has enabled nothing: no capture
		// host has been requested, so no leaf has been minted.
		if status.EnabledExtensions == 0 {
			return "none-needed", ""
		}
		return "absent", "interception certificate: none is loaded, but extensions are enabled. Capture will fail its handshake until the certificate oneshot mints one."
	case !status.CertificateCovers:
		hosts := append([]string(nil), status.MissingHosts...)
		sort.Strings(hosts)
		return "missing:" + strings.Join(hosts, ","), fmt.Sprintf(
			"interception certificate: does not cover %s. Clients reaching those hosts will see a trust error and the gateway will log nothing.",
			strings.Join(hosts, ", "))
	case !status.CertificateNotAfter.IsZero() && status.CertificateNotAfter.Sub(now) < certificateWarningWindow:
		day := status.CertificateNotAfter.UTC().Format("2006-01-02")
		return "expiring:" + day, fmt.Sprintf("interception certificate: expires %s.", day)
	default:
		return "ok", ""
	}
}

func interceptionCondition(status Status) (key, text string) {
	if status.InterceptionEnabled {
		return "on", ""
	}
	if status.Extensions == 0 {
		// Off with nothing installed is the shipped state, not an event.
		return "off-empty", ""
	}
	return "off", "interception: the master switch is off. Installed extensions are not seeing traffic."
}

// subscriptionCondition announces a subscription that has been failing for
// several consecutive checks, and its recovery.
func subscriptionCondition(status Status, state *alertState) (key, text string) {
	current := make(map[string]struct{}, len(status.Subscriptions))
	for _, sub := range status.Subscriptions {
		if sub.OK {
			delete(state.failing, sub.Name)
			continue
		}
		current[sub.Name] = struct{}{}
		state.failing[sub.Name]++
	}
	// A subscription that disappeared from the document stops being counted.
	for name := range state.failing {
		if _, still := current[name]; !still {
			delete(state.failing, name)
		}
	}

	sustained := make([]string, 0, len(state.failing))
	for name, windows := range state.failing {
		if windows >= subscriptionFailureWindows {
			sustained = append(sustained, name)
		}
	}
	sort.Strings(sustained)
	if len(sustained) == 0 {
		return "ok", ""
	}
	return "failing:" + strings.Join(sustained, ","), fmt.Sprintf(
		"policy subscriptions failing: %s. The gateway is serving the last good copy.",
		strings.Join(sustained, ", "))
}
