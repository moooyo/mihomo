package dns

import (
	"sort"
	"sync"
	"time"
)

// latencyWindowSize bounds how many recent samples a group retains. Large
// enough that p95 means something -- a p95 over 20 samples is really "the
// second worst" -- and small enough that the window is a few KB and sorting it
// on a status poll is free.
const latencyWindowSize = 512

// latencyWindowAge bounds how OLD a sample may be. Without it a quiet gateway
// reports last night's numbers indefinitely, which is exactly the failure the
// cumulative mean had: it never forgot.
const latencyWindowAge = 15 * time.Minute

type latencySample struct {
	at time.Time
	d  time.Duration
}

// latencyWindow is a per-group rolling window of recent exchange durations,
// reported as percentiles.
//
// It replaces a cumulative sum/count mean that was the wrong statistic three
// ways over: it never decayed, so one pathological exchange stayed visible
// forever; it was persisted across restarts, so the number could predate the
// current upstreams entirely; and being a mean over a small sample, a single
// multi-second outlier dominated it -- a 5ms resolver read as 140ms over 28
// samples.
//
// Percentiles answer the question an operator actually has. p50 is what a
// typical query costs, p95 is what the slow tail costs, and neither moves the
// way a mean does when one exchange goes wrong.
type latencyWindow struct {
	mu      sync.Mutex
	samples []latencySample
	next    int
	filled  bool
	now     func() time.Time
}

func newLatencyWindow() *latencyWindow {
	return &latencyWindow{samples: make([]latencySample, latencyWindowSize)}
}

func (w *latencyWindow) clock() time.Time {
	if w.now != nil {
		return w.now()
	}
	return time.Now()
}

// record adds one completed exchange. Nil-safe, like the counters beside it.
func (w *latencyWindow) record(d time.Duration) {
	if w == nil {
		return
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	w.samples[w.next] = latencySample{at: w.clock(), d: d}
	w.next++
	if w.next == len(w.samples) {
		w.next = 0
		w.filled = true
	}
}

// stats reports the window's percentiles in milliseconds and the sample count
// behind them. A window with no live samples reports a zero count, which the
// API renders as "no samples" rather than as 0ms -- a resolver nobody has asked
// anything is not a resolver answering instantly.
func (w *latencyWindow) stats() (p50Ms, p95Ms float64, count int) {
	if w == nil {
		return 0, 0, 0
	}
	w.mu.Lock()
	live := make([]time.Duration, 0, len(w.samples))
	cutoff := w.clock().Add(-latencyWindowAge)
	limit := w.next
	if w.filled {
		limit = len(w.samples)
	}
	for i := 0; i < limit; i++ {
		s := w.samples[i]
		if s.at.IsZero() || s.at.Before(cutoff) {
			continue
		}
		live = append(live, s.d)
	}
	w.mu.Unlock()

	if len(live) == 0 {
		return 0, 0, 0
	}
	sort.Slice(live, func(i, j int) bool { return live[i] < live[j] })
	return durationMs(percentile(live, 50)), durationMs(percentile(live, 95)), len(live)
}

// percentile returns the p-th percentile of a sorted slice by nearest rank: the
// smallest value at or above p% of the samples. It is the definition that stays
// honest at small n -- with three samples, p95 is the largest of them, not an
// interpolation between two values no exchange ever actually took.
func percentile(sorted []time.Duration, p int) time.Duration {
	if len(sorted) == 0 {
		return 0
	}
	rank := (p*len(sorted) + 99) / 100 // ceil(p/100 * n)
	if rank < 1 {
		rank = 1
	}
	if rank > len(sorted) {
		rank = len(sorted)
	}
	return sorted[rank-1]
}

func durationMs(d time.Duration) float64 { return float64(d.Nanoseconds()) / 1e6 }
