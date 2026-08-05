package bot

import (
	"regexp"
	"strings"
)

// The canonical FQDN rule.
//
// This exists in two places by necessity: here, and as install.sh's
// is_valid_domain. Two implementations of one rule drift silently, so the test
// beside this file holds the same table the installer suite holds, and both
// must agree.
//
// It used to be checked by grepping one repository from the other's test
// suite, which stopped working the moment the daemon moved into the fork. A
// cross-repository grep was never the right shape anyway: it asserted that two
// files contain the same characters, not that two implementations reach the
// same verdict.
//
// The pattern is adapted for RE2, which has no lookahead. The original bounded
// total length with `(?=.{1,253}$)`; that check lives in ValidDomain instead —
// exactly as install.sh does it, because bash ERE has no lookahead either.
var domainRE = regexp.MustCompile(`^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$`)

// ValidDomain reports whether name is a syntactically valid FQDN.
//
// The input is lowercased first, matching install.sh's `tr A-Z a-z`, then
// bounded to 1..253 characters, then matched.
func ValidDomain(name string) bool {
	name = strings.ToLower(name)
	if len(name) < 1 || len(name) > 253 {
		return false
	}
	return domainRE.MatchString(name)
}
