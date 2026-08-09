package dns

import (
	"strings"
	"sync"
	"time"

	D "github.com/miekg/dns"
)

// cacheKey identifies a cached response.
//
// The DNSSEC bits are part of the identity because they change what the
// upstream returns. Client ECS deliberately is not: it is stripped before every
// upstream exchange, so it can never vary a response and must never let one
// client's subnet select an answer served to another.
type cacheKey struct {
	name             string
	qtype            uint16
	dnssecOK         bool
	checkingDisabled bool
	// action separates direct/auto/gateway decisions even inside one runtime
	// generation. The capture provider publishes before its cache-invalidation
	// callback, so this also closes that narrow projection handoff window.
	action action
	// origin separates mihomo's own post-sniff lookups from client queries.
	// Both ask about the same names, and the answers differ by exactly the
	// thing that matters: a client's answer may have been rewritten to the
	// gateway address, and serving that to mihomo would point the box at
	// itself.
	origin bool
	// originResolver keeps a newly published capture-DNS binding from reusing a
	// trust/china result cached under the other binding before the projection's
	// generation callback completes.
	originResolver string
}

// cacheKeyOf builds the key for a question asked by r.
func cacheKeyOf(name string, qtype uint16, r *D.Msg) cacheKey {
	k := cacheKey{name: strings.ToLower(D.Fqdn(name)), qtype: qtype}
	if r == nil {
		return k
	}
	k.checkingDisabled = r.CheckingDisabled
	if opt := r.IsEdns0(); opt != nil {
		k.dnssecOK = opt.Do()
	}
	return k
}

// cacheMeta preserves the decision that produced a cached response.
//
// The message alone cannot recover it: a fallback-direct foreign answer and an
// ordinary chnroute-CN answer are the same bytes, and the query log has to tell
// them apart.
type cacheMeta struct {
	Verdict  string
	Reason   string
	Upstream string
}

type cacheEntry struct {
	msg        *D.Msg
	expiry     time.Time
	meta       cacheMeta
	generation uint64
}

// cache is a capacity-bounded TTL cache of final, already-rewritten answers.
//
// That "already-rewritten" is why Flush exists and why it is called from every
// swap: the cached value is the answer after steering, so a rule change that
// did not flush would keep serving the pre-change decision for up to the
// entry's TTL, turning a reload into a silent no-op for every name already in
// the map.
type cache struct {
	mu  sync.Mutex
	m   map[cacheKey]cacheEntry
	max int
	now func() time.Time

	// generation is the only runtime generation whose writes may enter the
	// cache. Entries carry it as well, so a query that captured an older runtime
	// can finish for its caller but can neither refill nor read stale data into a
	// newer configuration.
	generation uint64
}

// Large DNSSEC/TXT answers remain valid responses but are poor cache tenants:
// a count-only capacity multiplied by 64 KiB messages can otherwise consume
// gigabytes. Forward them without retaining them.
const maxCacheableResponseBytes = 16 * 1024

func newCache(max int) *cache {
	if max <= 0 {
		max = 1
	}
	return &cache{m: make(map[cacheKey]cacheEntry), max: max, now: time.Now, generation: 1}
}

// Epoch reports the current runtime generation. Kept as a small cache-level
// diagnostic and for focused tests; live resolution gets its generation from
// the immutable runtime snapshot instead. Nil-safe.
func (c *cache) Epoch() uint64 {
	if c == nil {
		return 0
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.generation
}

// get returns a live entry with every TTL rewritten to the remaining lifetime.
//
// An expired entry is a miss but is deliberately NOT deleted: getStale can
// still serve it when every upstream is down. Pruning past the grace window
// happens there, and capacity eviction bounds what accumulates in between.
func (c *cache) get(k cacheKey) (*D.Msg, cacheMeta, bool) {
	return c.getGeneration(k, c.Epoch())
}

func (c *cache) getGeneration(k cacheKey, generation uint64) (*D.Msg, cacheMeta, bool) {
	if c == nil {
		return nil, cacheMeta{}, false
	}
	c.mu.Lock()
	defer c.mu.Unlock()

	e, ok := c.m[k]
	if !ok || e.generation != generation {
		return nil, cacheMeta{}, false
	}
	now := c.now()
	if !now.Before(e.expiry) {
		return nil, cacheMeta{}, false
	}
	cp := e.msg.Copy()
	remaining := uint32(e.expiry.Sub(now).Seconds())
	for _, rr := range cp.Answer {
		rr.Header().Ttl = remaining
	}
	capSectionTTLs(cp.Ns, remaining)
	capSectionTTLs(cp.Extra, remaining)
	return cp, e.meta, true
}

// staleGrace bounds how far past expiry an entry may still be served. Older
// than this and it is too stale to trust even as a last resort.
const staleGrace = time.Hour

// staleReplyTTL is stamped on a served-stale answer -- short, so the client
// re-queries soon once upstreams may have recovered.
const staleReplyTTL = 30

// getStale returns an expired entry within the grace window, with TTLs clamped
// so clients come back quickly. It is the last resort when every upstream
// failed: a slightly stale answer beats handing every client SERVFAIL while
// correct data sat in memory seconds ago.
func (c *cache) getStale(k cacheKey) (*D.Msg, cacheMeta, bool) {
	return c.getStaleGeneration(k, c.Epoch())
}

func (c *cache) getStaleGeneration(k cacheKey, generation uint64) (*D.Msg, cacheMeta, bool) {
	if c == nil {
		return nil, cacheMeta{}, false
	}
	c.mu.Lock()
	defer c.mu.Unlock()

	e, ok := c.m[k]
	if !ok || e.generation != generation {
		return nil, cacheMeta{}, false
	}
	now := c.now()
	// Only a naturally expired entry from this exact configuration generation
	// is stale. A live entry can reach this function only across a race or a
	// caller bug and must not be relabelled as a failure fallback.
	if now.Before(e.expiry) {
		return nil, cacheMeta{}, false
	}
	if now.Sub(e.expiry) > staleGrace {
		delete(c.m, k)
		return nil, cacheMeta{}, false
	}
	cp := e.msg.Copy()
	// Stale data may still be useful, but this resolver can no longer assert
	// that it is currently authenticated on the upstream's behalf.
	cp.AuthenticatedData = false
	capSectionTTLs(cp.Answer, staleReplyTTL)
	capSectionTTLs(cp.Ns, staleReplyTTL)
	capSectionTTLs(cp.Extra, staleReplyTTL)
	return cp, e.meta, true
}

func capSectionTTLs(rrs []D.RR, max uint32) {
	for _, rr := range rrs {
		if _, ok := rr.(*D.OPT); ok {
			continue
		}
		if rr.Header().Ttl > max {
			rr.Header().Ttl = max
		}
	}
}

// put stores a copy of msg, unless a flush has happened since epoch was taken.
func (c *cache) put(k cacheKey, msg *D.Msg, ttl time.Duration, epoch uint64, meta cacheMeta) {
	if c == nil || msg == nil || msg.Len() > maxCacheableResponseBytes {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if epoch != c.generation {
		return
	}
	if len(c.m) >= c.max {
		if _, exists := c.m[k]; !exists {
			c.evictOneLocked()
		}
	}
	c.m[k] = cacheEntry{msg: msg.Copy(), expiry: c.now().Add(ttl), meta: meta, generation: epoch}
}

// evictOneLocked removes one entry, preferring an already-expired zombie over a
// hot live one.
//
// It samples a bounded number of keys rather than scanning: map iteration order
// is random, so a small sample reliably surfaces an expired entry when many
// naturally expire together, and a full scan under a flood would make eviction
// the bottleneck.
func (c *cache) evictOneLocked() {
	const sample = 8
	now := c.now()
	var first cacheKey
	i := 0
	for k, e := range c.m {
		if i == 0 {
			first = k
		}
		if !now.Before(e.expiry) {
			delete(c.m, k)
			return
		}
		if i++; i >= sample {
			break
		}
	}
	delete(c.m, first)
}

// Len is the entry count, including entries expired but not yet reclaimed.
func (c *cache) Len() int {
	if c == nil {
		return 0
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.m)
}

// hardInvalidate installs a new configuration generation and drops every old
// answer. Configuration changes are authorization and steering boundaries: a
// failure under the new configuration must not resurrect an address, policy,
// capture binding, or upstream result from the previous one.
func (c *cache) hardInvalidate(generation uint64, max int) {
	if c == nil {
		return
	}
	if max <= 0 {
		max = 1
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.m = make(map[cacheKey]cacheEntry)
	c.max = max
	c.generation = generation
}

// softExpire marks this generation's live entries expired without changing
// their identity. It is deliberately distinct from hardInvalidate: only a
// soft expiry may later be served stale when the same configuration's
// upstreams fail.
func (c *cache) softExpire(generation uint64) {
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	now := c.now()
	for k, e := range c.m {
		if e.generation == generation && now.Before(e.expiry) {
			e.expiry = now
			c.m[k] = e
		}
	}
}

// Flush is a cache-level hard invalidation. Resolver.FlushCache publishes a
// new immutable runtime generation as well; this method remains for focused
// cache tests.
func (c *cache) Flush() {
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.m = make(map[cacheKey]cacheEntry)
	c.generation++
}
