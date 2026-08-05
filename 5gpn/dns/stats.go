package dns

import (
	"sync/atomic"
	"time"
)

// counters are the resolver's observability. Every field here is reported and
// none of it decides anything.
//
// That separation is load-bearing rather than stylistic. The china/trust health
// and latency numbers are exactly the shape of data that invites "prefer the
// healthy group", and doing so would replace deterministic CN-membership
// arbitration with a race whose winner changes with the weather. They are
// per-group and asymmetric on top of that -- trust is counted only when it was
// consulted -- so they could not drive a fair selection even if that were
// wanted.
type counters struct {
	total atomic.Uint64

	// Per-reason verdict counts. The pairs distinguish an explicit operator
	// decision from automatic arbitration, which the final message cannot.
	block           atomic.Uint64
	forceDirect     atomic.Uint64
	forceProxy      atomic.Uint64
	chnrouteCN      atomic.Uint64
	chnrouteForeign atomic.Uint64

	chinaOK  atomic.Uint64
	chinaErr atomic.Uint64
	trustOK  atomic.Uint64
	trustErr atomic.Uint64

	cacheHits   atomic.Uint64
	cacheMisses atomic.Uint64
	refused     atomic.Uint64

	chinaLatency *latencyWindow
	trustLatency *latencyWindow
}

// newCounters returns counters with their latency windows ready. The zero value
// stays usable -- recording into a nil window is a no-op -- so a resolver built
// in a test without stats never panics.
func newCounters() *counters {
	return &counters{chinaLatency: newLatencyWindow(), trustLatency: newLatencyWindow()}
}

func (s *counters) bumpChina(ok bool) {
	if s == nil {
		return
	}
	if ok {
		s.chinaOK.Add(1)
	} else {
		s.chinaErr.Add(1)
	}
}

func (s *counters) bumpTrust(ok bool) {
	if s == nil {
		return
	}
	if ok {
		s.trustOK.Add(1)
	} else {
		s.trustErr.Add(1)
	}
}

func (s *counters) recordChinaLatency(d time.Duration) {
	if s == nil {
		return
	}
	s.chinaLatency.record(d)
}

func (s *counters) recordTrustLatency(d time.Duration) {
	if s == nil {
		return
	}
	s.trustLatency.record(d)
}

func (s *counters) bump(c *atomic.Uint64) {
	if s == nil {
		return
	}
	c.Add(1)
}

// bumpReason folds one verdict into the per-reason counters.
func (s *counters) bumpReason(reason string) {
	if s == nil {
		return
	}
	switch reason {
	case "block":
		s.block.Add(1)
	case "force-direct", "fallback-direct":
		s.forceDirect.Add(1)
	case "force-proxy", "fallback-gateway":
		s.forceProxy.Add(1)
	case "chnroute-cn":
		s.chnrouteCN.Add(1)
	case "chnroute-foreign":
		s.chnrouteForeign.Add(1)
	}
}

// GroupStats is one upstream group's reported health.
type GroupStats struct {
	OK           uint64  `json:"ok"`
	Err          uint64  `json:"err"`
	P50Ms        float64 `json:"p50Ms"`
	P95Ms        float64 `json:"p95Ms"`
	LatencyCount int     `json:"latencyCount"`
}

// Stats is the resolver's reported state.
type Stats struct {
	Total           uint64     `json:"total"`
	Block           uint64     `json:"block"`
	ForceDirect     uint64     `json:"forceDirect"`
	ForceProxy      uint64     `json:"forceProxy"`
	ChnrouteCN      uint64     `json:"chnrouteCn"`
	ChnrouteForeign uint64     `json:"chnrouteForeign"`
	CacheHits       uint64     `json:"cacheHits"`
	CacheMisses     uint64     `json:"cacheMisses"`
	CacheEntries    int        `json:"cacheEntries"`
	Refused         uint64     `json:"refused"`
	China           GroupStats `json:"china"`
	Trust           GroupStats `json:"trust"`
	CNRanges        int        `json:"cnRanges"`
}

func (s *counters) snapshot() Stats {
	if s == nil {
		return Stats{}
	}
	chinaP50, chinaP95, chinaN := s.chinaLatency.stats()
	trustP50, trustP95, trustN := s.trustLatency.stats()
	return Stats{
		Total:           s.total.Load(),
		Block:           s.block.Load(),
		ForceDirect:     s.forceDirect.Load(),
		ForceProxy:      s.forceProxy.Load(),
		ChnrouteCN:      s.chnrouteCN.Load(),
		ChnrouteForeign: s.chnrouteForeign.Load(),
		CacheHits:       s.cacheHits.Load(),
		CacheMisses:     s.cacheMisses.Load(),
		Refused:         s.refused.Load(),
		China:           GroupStats{OK: s.chinaOK.Load(), Err: s.chinaErr.Load(), P50Ms: chinaP50, P95Ms: chinaP95, LatencyCount: chinaN},
		Trust:           GroupStats{OK: s.trustOK.Load(), Err: s.trustErr.Load(), P50Ms: trustP50, P95Ms: trustP95, LatencyCount: trustN},
	}
}
