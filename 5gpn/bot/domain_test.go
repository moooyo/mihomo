package bot

import "testing"

// The canonical FQDN table.
//
// This is the coverage that went missing when the daemon moved into the fork.
// It used to live in tests/test_domain_validation.sh as a grep asserting that
// install.sh's is_valid_domain and the bot's regexp contained the same
// characters -- which stopped being possible across two repositories, and was
// the wrong assertion anyway: what matters is that the two reach the same
// verdict, not that they are spelled alike.
//
// So the table is duplicated rather than the pattern. Both suites run it, and
// the day they disagree, one of them fails. Keep the two tables identical: the
// installer's lives in tests/test_domain_validation.sh.
func TestValidDomainMatchesTheInstallerRule(t *testing.T) {
	for name, want := range map[string]bool{
		"example.com":            true,
		"sub.domain.example.com": true,
		"a-b.example.com":        true,
		"EXAMPLE.COM":            true,
		"1foo.example.co":        true,
		"xn--fsq.com":            true,
		"":                       false,
		"example":                false,
		"foo.c":                  false,
		"foo.123":                false,
		"_dmarc.example.com":     false,
		"foo_bar.com":            false,
		"-foo.example.com":       false,
		"foo-.example.com":       false,
		"foo..com":               false,
		"ex ample.com":           false,
		"http://example.com":     false,
		"example.com/x":          false,
	} {
		if got := ValidDomain(name); got != want {
			t.Errorf("ValidDomain(%q) = %v, want %v", name, got, want)
		}
	}
}

// The length bound is in code because neither RE2 nor bash ERE has the
// lookahead the original pattern used, so it is the half most likely to be
// dropped in a rewrite.
func TestValidDomainBoundsTotalLength(t *testing.T) {
	label := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa." // 63 + dot
	long := label + label + label + label + "example.com"
	if len(long) <= 253 {
		t.Fatalf("the fixture is %d characters, which does not exceed the bound", len(long))
	}
	if ValidDomain(long) {
		t.Errorf("a %d-character name was accepted", len(long))
	}
}
