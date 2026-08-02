package dns

import (
	"net/netip"
	"testing"
)

func mustAddr(t *testing.T, s string) netip.Addr {
	t.Helper()
	a, err := netip.ParseAddr(s)
	if err != nil {
		t.Fatalf("parse %q: %v", s, err)
	}
	return a
}

func TestParseSkipsWhatItCannotUse(t *testing.T) {
	set := parseCNSet(`
# a comment
1.0.1.0/24

2001:db8::/32
not-a-prefix
1.0.2.0/23
`)
	if set.Len() == 0 {
		t.Fatal("nothing parsed")
	}
	// 1.0.1.0/24 and 1.0.2.0/23 are adjacent and must have merged into one.
	if set.Len() != 1 {
		t.Errorf("Len() = %d, want 1 merged range", set.Len())
	}
	for _, in := range []string{"1.0.1.0", "1.0.1.255", "1.0.2.0", "1.0.3.255"} {
		if !set.Contains(mustAddr(t, in)) {
			t.Errorf("Contains(%s) = false", in)
		}
	}
	for _, out := range []string{"1.0.0.255", "1.0.4.0"} {
		if set.Contains(mustAddr(t, out)) {
			t.Errorf("Contains(%s) = true", out)
		}
	}
}

func TestMergeCoalescesOverlapAndAdjacency(t *testing.T) {
	// Deliberately unsorted, overlapping, adjacent and disjoint.
	set := parseCNSet("10.0.2.0/24\n10.0.0.0/24\n10.0.1.0/24\n10.0.0.128/25\n192.0.2.0/24\n")
	if set.Len() != 2 {
		t.Fatalf("Len() = %d, want 2 (10.0.0.0-10.0.2.255 and 192.0.2.0/24)", set.Len())
	}
	if !set.Contains(mustAddr(t, "10.0.1.7")) {
		t.Error("a merged interior address is not contained")
	}
	if set.Contains(mustAddr(t, "10.0.3.0")) {
		t.Error("the address just past the merged range is contained")
	}
}

// The upper bound is where an off-by-one in the merge would wrap.
func TestBoundariesAtTheTopOfTheSpace(t *testing.T) {
	set := parseCNSet("255.255.255.255/32\n")
	if !set.Contains(mustAddr(t, "255.255.255.255")) {
		t.Error("the last address is not contained")
	}
	if set.Contains(mustAddr(t, "255.255.255.254")) {
		t.Error("the address below it is contained")
	}
}

func TestNonIPv4IsNeverContained(t *testing.T) {
	set := NewCNSet()
	if set.Contains(mustAddr(t, "2400:3200::1")) {
		t.Error("an IPv6 address was classified as CN")
	}
	// An IPv4-mapped IPv6 address is still IPv4 and must be judged as one.
	mapped := netip.AddrFrom16(mustAddr(t, "114.114.114.114").As16())
	if set.Contains(mapped) != set.Contains(mustAddr(t, "114.114.114.114")) {
		t.Error("a v4-mapped address disagreed with its v4 form")
	}
}

// An empty set does not fail loudly -- it quietly calls the entire internet
// foreign, which routes every domestic flow through the gateway and shows up as
// a bandwidth bill rather than an error. This is why the dataset is embedded,
// and why anything reporting health should read Len().
func TestNilAndEmptyContainNothing(t *testing.T) {
	var nilSet *CNSet
	if nilSet.Contains(mustAddr(t, "114.114.114.114")) {
		t.Error("a nil set contained something")
	}
	if nilSet.Len() != 0 {
		t.Error("a nil set reported a length")
	}
	if parseCNSet("# only comments\n").Len() != 0 {
		t.Error("a comment-only list produced ranges")
	}
}

func TestEmbeddedListClassifiesKnownAddresses(t *testing.T) {
	set := NewCNSet()
	if set.Len() < 4000 {
		t.Fatalf("embedded set has %d ranges, which is too few to be the real list", set.Len())
	}
	cn := []string{
		"114.114.114.114", // Nanjing public resolver
		"223.5.5.5",       // AliDNS
		"1.2.4.8",         // CNNIC
	}
	for _, s := range cn {
		if !set.Contains(mustAddr(t, s)) {
			t.Errorf("Contains(%s) = false, want true", s)
		}
	}
	foreign := []string{
		"8.8.8.8",        // Google
		"1.1.1.1",        // Cloudflare
		"208.67.222.222", // OpenDNS
		"192.0.2.1",      // TEST-NET-1, reserved
	}
	for _, s := range foreign {
		if set.Contains(mustAddr(t, s)) {
			t.Errorf("Contains(%s) = true, want false", s)
		}
	}
}

func BenchmarkContains(b *testing.B) {
	set := NewCNSet()
	addr := netip.MustParseAddr("114.114.114.114")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = set.Contains(addr)
	}
}
