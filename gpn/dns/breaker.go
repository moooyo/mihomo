package dns

import (
	"sync"
	"time"
)

const (
	// breakerThreshold is the consecutive-failure count that opens a group's
	// breaker; breakerCooldown is how long it stays open before a half-open
	// probe is admitted.
	breakerThreshold = 5
	breakerCooldown  = 10 * time.Second
)

// breaker is a per-group circuit breaker. After breakerThreshold consecutive
// exchange failures it opens for breakerCooldown, during which the group fails
// fast without dialing -- so a blackholed upstream (RST, or worse, silently
// dropped) stops adding a read timeout to every uncached query.
//
// It trips on a consecutive-failure COUNT, never on latency, and that
// distinction is what keeps it out of the arbitration decision. Whenever the
// china group is answering at all, its answer is honoured by chnroute
// membership; the breaker only short-circuits a group that has already failed
// repeatedly, where there is no answer to honour.
type breaker struct {
	mu            sync.Mutex
	failures      int
	openUntil     time.Time
	probeInFlight bool
	now           func() time.Time // injectable clock for tests
}

func newBreaker() *breaker { return &breaker{now: time.Now} }

// allow reports whether a call may proceed. Open and still within cooldown is
// false; otherwise true, including the single half-open probe once the cooldown
// has elapsed. A nil breaker always allows.
func (b *breaker) allow() bool {
	if b == nil {
		return true
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.openUntil.IsZero() {
		return true
	}
	if b.clock().Before(b.openUntil) || b.probeInFlight {
		return false
	}
	b.probeInFlight = true
	return true
}

// record folds one outcome in: a success closes the breaker, a failure counts
// toward the threshold. A failed half-open probe re-opens it, since the count
// is already at or over the threshold.
func (b *breaker) record(ok bool) {
	if b == nil {
		return
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	b.probeInFlight = false
	if ok {
		b.failures = 0
		b.openUntil = time.Time{}
		return
	}
	b.failures++
	if b.failures >= breakerThreshold {
		b.openUntil = b.clock().Add(breakerCooldown)
	}
}

// recordCanceled releases a half-open probe slot without scoring the attempt.
//
// Caller cancellation is not an upstream health signal, and on this gateway it
// is the common case rather than the exception: arbitration abandons the trust
// group on every china-CN win. Counting those as failures lets ordinary
// CN-heavy traffic trip the trust breaker after five domestic answers in a row,
// and the half-open probe is cancellable the same way, which latches it open.
func (b *breaker) recordCanceled() {
	if b == nil {
		return
	}
	b.mu.Lock()
	b.probeInFlight = false
	b.mu.Unlock()
}

func (b *breaker) clock() time.Time {
	if b.now != nil {
		return b.now()
	}
	return time.Now()
}
