package dns

import (
	"sync"
	"time"
)

const (
	// breakerThreshold is the consecutive-failure count that opens a member's
	// breaker; breakerCooldown is how long it stays open before a half-open
	// probe is admitted.
	breakerThreshold = 5
	breakerCooldown  = 10 * time.Second
)

// breaker is a per-member circuit breaker. After breakerThreshold consecutive
// exchange failures it opens for breakerCooldown, during which that member is
// skipped -- so a blackholed first upstream stops adding a read timeout while
// later configured members remain available.
//
// It trips on a consecutive-failure COUNT, never on latency, and that
// distinction is what keeps it out of the arbitration decision. It skips only
// a member that has repeatedly failed; later members retain their configured
// order and can continue serving the group.
type breaker struct {
	mu            sync.Mutex
	failures      int
	openUntil     time.Time
	probeInFlight bool
	now           func() time.Time // injectable clock for tests
}

func newBreaker() *breaker { return &breaker{now: time.Now} }

// admit reports both whether work may proceed and whether this caller owns the
// single half-open probe reservation. The latter lets a group release a probe
// it selected for fair budgeting but never reached because an earlier member
// succeeded.
func (b *breaker) admit() (allowed, probe bool) {
	if b == nil {
		return true, false
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.openUntil.IsZero() {
		return true, false
	}
	if b.clock().Before(b.openUntil) || b.probeInFlight {
		return false, false
	}
	b.probeInFlight = true
	return true, true
}

// allow reports whether a call may proceed. Open and still within cooldown is
// false; otherwise true, including the single half-open probe once the cooldown
// has elapsed. A nil breaker always allows.
func (b *breaker) allow() bool {
	allowed, _ := b.admit()
	return allowed
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
