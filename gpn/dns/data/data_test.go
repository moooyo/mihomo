package data

import (
	"strings"
	"testing"
)

// The point of embedding is that the data cannot go missing or go stale
// independently of the binary. That only holds if something asserts the
// embedded content is actually there and actually shaped like what the
// arbitrator expects -- an empty embed compiles fine and fails closed at
// runtime by classifying every address as non-CN.
func TestDatasetsAreEmbeddedAndPlausible(t *testing.T) {
	for _, tc := range []struct {
		name    string
		content string
		min     int
		wantSub string
	}{
		{"china_ip_list", ChinaIPList, 4000, "/"},
		{"block_dns_bypass", BlockDNSBypass, 10, "."},
		{"block_dns_bypass_keyword", BlockDNSBypassKeyword, 1, ""},
		// proxy-domains ships empty on purpose -- it is the operator's list, and a
		// seeded entry would be the project routing something on their behalf. So
		// the assertion is that the file is present and carries its header, not
		// that it has content.
		{"proxy_domains", ProxyDomains, 0, "Forced-proxy domains"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			lines := 0
			for _, l := range strings.Split(tc.content, "\n") {
				if l = strings.TrimSpace(l); l != "" && !strings.HasPrefix(l, "#") {
					lines++
				}
			}
			if lines < tc.min {
				t.Errorf("%d usable lines, want at least %d", lines, tc.min)
			}
			if tc.wantSub != "" && !strings.Contains(tc.content, tc.wantSub) {
				t.Errorf("content does not contain %q; wrong file embedded?", tc.wantSub)
			}
		})
	}
}
