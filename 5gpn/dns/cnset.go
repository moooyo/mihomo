package dns

import (
	"net/netip"
	"sort"
	"strings"

	"github.com/metacubex/mihomo/5gpn/dns/data"
)

// CNSet answers whether an address is inside China, which is the single
// load-bearing decision in the resolver: it is what makes an answer "connect
// direct" rather than "connect to the gateway".
//
// Sorted merged ranges over uint32 with a binary search, which is what the
// daemon did. Two things changed in the move.
//
// The set is built from an embedded dataset rather than a file the installer
// copied, so there is no path, no missing-file case, and no window during which
// the list is empty. That window used to need its own error value and its own
// tolerance at startup -- an empty set classifies every address as foreign,
// which silently routes the entire domestic internet through the gateway.
// Nothing can observe that from the outside except a bandwidth bill.
//
// And it takes netip.Addr rather than net.IP, because that is what mihomo's
// metadata carries. Converting at every lookup allocated on the hottest path in
// the resolver.
type CNSet struct {
	ranges []cnRange
}

type cnRange struct{ start, end uint32 }

// NewCNSet builds the set from the embedded prefix list.
func NewCNSet() *CNSet { return parseCNSet(data.ChinaIPList) }

// parseCNSet accepts CIDR-per-line text. Comments and blank lines are skipped;
// so is anything that does not parse as an IPv4 prefix, because the upstream
// list has historically carried the occasional IPv6 line and one bad row should
// not cost the other twelve thousand.
func parseCNSet(text string) *CNSet {
	raw := make([]cnRange, 0, 16384)
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		p, err := netip.ParsePrefix(line)
		if err != nil || !p.Addr().Is4() {
			continue
		}
		p = p.Masked()
		start := addrToU32(p.Addr())
		// host bits below the prefix length, all set
		size := uint32(1)<<(32-uint(p.Bits())) - 1
		raw = append(raw, cnRange{start: start, end: start + size})
	}
	return &CNSet{ranges: mergeRanges(raw)}
}

// mergeRanges sorts and coalesces so the lookup can binary search.
//
// Adjacent ranges are merged as well as overlapping ones: the published list is
// full of consecutive /24s, and leaving them separate roughly doubles the set
// for no benefit.
func mergeRanges(raw []cnRange) []cnRange {
	if len(raw) == 0 {
		return nil
	}
	sort.Slice(raw, func(i, j int) bool {
		if raw[i].start != raw[j].start {
			return raw[i].start < raw[j].start
		}
		return raw[i].end < raw[j].end
	})
	out := raw[:1]
	for _, r := range raw[1:] {
		last := &out[len(out)-1]
		// r.start <= last.end+1 covers both overlap and adjacency; the guard on
		// last.end avoids wrapping at 255.255.255.255.
		if last.end != ^uint32(0) && r.start > last.end+1 {
			out = append(out, r)
			continue
		}
		if r.end > last.end {
			last.end = r.end
		}
	}
	return out
}

func addrToU32(a netip.Addr) uint32 {
	b := a.As4()
	return uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
}

// Contains reports whether addr is in the set. A non-IPv4 address is never in
// it: egress is IPv4-only by design, and an IPv6 answer never reaches this
// decision.
func (c *CNSet) Contains(addr netip.Addr) bool {
	if c == nil || len(c.ranges) == 0 {
		return false
	}
	addr = addr.Unmap()
	if !addr.Is4() {
		return false
	}
	n := addrToU32(addr)
	// The last range whose start is <= n is the only one that can contain it.
	i := sort.Search(len(c.ranges), func(i int) bool {
		return c.ranges[i].start > n
	}) - 1
	if i < 0 {
		return false
	}
	return n <= c.ranges[i].end
}

// Len is the number of merged ranges, which is what a health check should
// report: a set that parsed to nothing is a resolver that will call the whole
// internet foreign.
func (c *CNSet) Len() int {
	if c == nil {
		return 0
	}
	return len(c.ranges)
}
