package overlay_test

import (
	"net/netip"
	"strings"
	"testing"

	"github.com/metacubex/mihomo/component/overlay"
	C "github.com/metacubex/mihomo/constant"
	R "github.com/metacubex/mihomo/rules"
	RC "github.com/metacubex/mihomo/rules/common"
)

// Differential equivalence between a rendered mihomo rule and its typed overlay
// form.
//
// Reasoning about "these two express the same policy" is exactly the kind of
// claim that survives review and then turns out to be wrong, so this does not
// reason: it evaluates both against the same corpus of hosts and asserts the
// decisions are identical. mihomo's own parser and matchers are the oracle.
//
// The pairs below are the shapes real operator state actually produces. The
// suffix+keyword and suffix+OR-of-keywords cases are the ones a shadow
// comparison against a live deployment found the typed model silently dropping.

// hostCorpus is chosen to sit on the boundaries these rules care about: exact
// vs suffix, keyword present in the label vs in the domain vs absent, and hosts
// that match one constraint but not the other.
var hostCorpus = []string{
	"capcutapi.com",
	"tnc.capcutapi.com",
	"tnc16-normal-alisg.capcutapi.com",
	"api.capcutapi.com",
	"notcapcutapi.com",
	"tnc.example.test",
	"chat.bilibili.com",
	"p2p.chat.bilibili.com",
	"stun.chat.bilibili.com",
	"tracker.chat.bilibili.com",
	"live.chat.bilibili.com",
	"chat.bilibili.com.evil.test",
	"gs-loc.apple.com",
	"gs-loc-cn.apple.com",
	"gs-loc.apple.com.attacker.test",
	"ads.example.test",
	"",
}

var portCorpus = []uint16{80, 443, 8443}

type rulePair struct {
	name   string
	legacy string
	typed  overlay.ClientRule
}

// pairs mirrors renderInterceptPolicyRule's output for each reviewed rule shape.
var pairs = []rulePair{
	{
		name:   "exact domain",
		legacy: "DOMAIN,gs-loc.apple.com,REJECT",
		typed:  overlay.ClientRule{Kind: overlay.SelectorDomain, Value: "gs-loc.apple.com", Action: overlay.ActionReject},
	},
	{
		name:   "domain suffix",
		legacy: "DOMAIN-SUFFIX,capcutapi.com,REJECT",
		typed:  overlay.ClientRule{Kind: overlay.SelectorDomainSuffix, Value: "capcutapi.com", Action: overlay.ActionReject},
	},
	{
		name:   "single keyword",
		legacy: "DOMAIN-KEYWORD,tnc,REJECT",
		typed:  overlay.ClientRule{Kind: overlay.SelectorDomainKeyword, Value: "tnc", Action: overlay.ActionReject},
	},
	{
		// The shape the shadow comparison found being dropped.
		name:   "suffix AND keyword",
		legacy: "AND,((DOMAIN-SUFFIX,capcutapi.com),(DOMAIN-KEYWORD,tnc)),DIRECT",
		typed: overlay.ClientRule{
			Kind: overlay.SelectorDomainSuffix, Value: "capcutapi.com",
			KeywordsAll: []string{"tnc"}, Action: overlay.ActionDirect,
		},
	},
	{
		// The other dropped shape: suffix narrowed by an any-of keyword set.
		name:   "suffix AND (keyword OR keyword OR keyword)",
		legacy: "AND,((DOMAIN-SUFFIX,chat.bilibili.com),(OR,((DOMAIN-KEYWORD,p2p),(DOMAIN-KEYWORD,stun),(DOMAIN-KEYWORD,tracker)))),REJECT",
		typed: overlay.ClientRule{
			Kind: overlay.SelectorDomainSuffix, Value: "chat.bilibili.com",
			KeywordsAny: []string{"p2p", "stun", "tracker"}, Action: overlay.ActionReject,
		},
	},
	{
		name:   "two all-of keywords",
		legacy: "AND,((DOMAIN-KEYWORD,tnc),(DOMAIN-KEYWORD,alisg)),REJECT",
		typed: overlay.ClientRule{
			Kind: overlay.SelectorAny, KeywordsAll: []string{"tnc", "alisg"}, Action: overlay.ActionReject,
		},
	},
	{
		name:   "any-of keywords with no primary selector",
		legacy: "OR,((DOMAIN-KEYWORD,p2p),(DOMAIN-KEYWORD,stun)),REJECT",
		typed: overlay.ClientRule{
			Kind: overlay.SelectorAny, KeywordsAny: []string{"p2p", "stun"}, Action: overlay.ActionReject,
		},
	},
	{
		name:   "suffix AND port",
		legacy: "AND,((DOMAIN-SUFFIX,capcutapi.com),(DST-PORT,443)),REJECT",
		typed: overlay.ClientRule{
			Kind: overlay.SelectorDomainSuffix, Value: "capcutapi.com",
			Ports: []overlay.PortRange{{From: 443, To: 443}}, Action: overlay.ActionReject,
		},
	},
	{
		name:   "wildcard",
		legacy: "DOMAIN-WILDCARD,*.apple.com,REJECT",
		typed:  overlay.ClientRule{Kind: overlay.SelectorDomainWildcard, Value: "*.apple.com", Action: overlay.ActionReject},
	},
}

func mustParseLegacy(t *testing.T, line string) C.Rule {
	t.Helper()
	tp, payload, target, params := RC.ParseRulePayload(line, true)
	rule, err := R.ParseRule(tp, payload, target, params, nil)
	if err != nil {
		t.Fatalf("parse %q: %v", line, err)
	}
	return rule
}

func compileTyped(t *testing.T, rule overlay.ClientRule) *overlay.Compiled {
	t.Helper()
	doc := &overlay.Document{
		SchemaVersion: overlay.SchemaVersion, Owner: "5gpn", GenerationID: "g1",
		DocumentRevision: 1, TransitionMode: overlay.TransitionRevoke,
		Client: overlay.ClientOverlay{Rules: []overlay.ClientRule{rule}},
	}
	c, err := overlay.Compile(doc, overlay.DefaultQuotas(), nil)
	if err != nil {
		t.Fatalf("compile %+v: %v", rule, err)
	}
	return c
}

// TestTypedRulesMatchTheirRenderedEquivalents is the differential oracle: for
// every rule shape real state produces, the typed overlay must decide exactly
// what mihomo's own parser and matchers decide for the rendered form.
func TestTypedRulesMatchTheirRenderedEquivalents(t *testing.T) {
	for _, pair := range pairs {
		t.Run(pair.name, func(t *testing.T) {
			legacy := mustParseLegacy(t, pair.legacy)
			typed := compileTyped(t, pair.typed)

			for _, host := range hostCorpus {
				for _, port := range portCorpus {
					metadata := &C.Metadata{
						NetWork: C.TCP,
						Host:    host,
						DstPort: port,
					}
					legacyMatched, _ := legacy.Match(metadata, C.RuleMatchHelper{})

					typedDecision := typed.Client.Match(&overlay.MatchInput{
						Host:    strings.ToLower(host),
						DstPort: port,
						Network: overlay.NetworkTCP,
					})

					if legacyMatched != typedDecision.Matched {
						t.Errorf("host %q port %d: legacy=%v typed=%v\n  legacy rule: %s\n  typed rule:  %+v",
							host, port, legacyMatched, typedDecision.Matched, pair.legacy, pair.typed)
					}
				}
			}
		})
	}
}

// The overlay's IP rules must never trigger a resolution — that would leak the
// destination to the resolver before the policy decision is made — so an
// unresolved destination simply does not match.
func TestIPCIDRRuleNeverResolves(t *testing.T) {
	typed := compileTyped(t, overlay.ClientRule{
		Kind: overlay.SelectorIPCIDR, Value: "203.0.113.0/24", Action: overlay.ActionReject,
	})

	unresolved := typed.Client.Match(&overlay.MatchInput{Host: "example.test", Network: overlay.NetworkTCP})
	if unresolved.Matched {
		t.Fatal("an address rule matched a destination that has not been resolved")
	}

	resolved := typed.Client.Match(&overlay.MatchInput{
		DstIP: netip.MustParseAddr("203.0.113.7"), Network: overlay.NetworkTCP,
	})
	if !resolved.Matched {
		t.Fatal("an address rule did not match a resolved destination inside its prefix")
	}
}

// A keyword constraint narrows; it must never widen. A rule with a primary
// selector and a keyword must match strictly fewer hosts than the selector
// alone.
func TestKeywordConstraintsOnlyNarrow(t *testing.T) {
	bare := compileTyped(t, overlay.ClientRule{
		Kind: overlay.SelectorDomainSuffix, Value: "capcutapi.com", Action: overlay.ActionReject,
	})
	narrowed := compileTyped(t, overlay.ClientRule{
		Kind: overlay.SelectorDomainSuffix, Value: "capcutapi.com",
		KeywordsAll: []string{"tnc"}, Action: overlay.ActionReject,
	})

	widened := 0
	for _, host := range hostCorpus {
		in := &overlay.MatchInput{Host: host, Network: overlay.NetworkTCP}
		if narrowed.Client.Match(in).Matched && !bare.Client.Match(in).Matched {
			t.Errorf("host %q matches the narrowed rule but not the bare one", host)
			widened++
		}
	}
	if widened == 0 {
		// Also assert the constraint does something at all, or the test would
		// pass for a keyword implementation that ignores keywords entirely.
		hit := bare.Client.Match(&overlay.MatchInput{Host: "api.capcutapi.com", Network: overlay.NetworkTCP})
		miss := narrowed.Client.Match(&overlay.MatchInput{Host: "api.capcutapi.com", Network: overlay.NetworkTCP})
		if !hit.Matched || miss.Matched {
			t.Fatal("the keyword constraint had no effect; it must actually narrow")
		}
	}
}

// SelectorAny with no keyword would match every connection, which is never what
// a reviewed extension rule means.
func TestUnconstrainedAnySelectorIsRejected(t *testing.T) {
	doc := &overlay.Document{
		SchemaVersion: overlay.SchemaVersion, Owner: "5gpn", GenerationID: "g1",
		DocumentRevision: 1, TransitionMode: overlay.TransitionRevoke,
		Client: overlay.ClientOverlay{Rules: []overlay.ClientRule{
			{Kind: overlay.SelectorAny, Action: overlay.ActionReject},
		}},
	}
	if _, err := overlay.Compile(doc, overlay.DefaultQuotas(), nil); err == nil {
		t.Fatal("an unconstrained 'any' rule was accepted; it would match every connection")
	}
}

// Keyword matching must be case-insensitive in the same way mihomo's own
// DOMAIN-KEYWORD rule is, or a reviewed deny stops applying to a host that
// differs only in case.
func TestKeywordMatchingIsCaseInsensitive(t *testing.T) {
	typed := compileTyped(t, overlay.ClientRule{
		Kind: overlay.SelectorAny, KeywordsAll: []string{"TNC"}, Action: overlay.ActionReject,
	})
	// The rule layer lowercases the host before building MatchInput, and the
	// compiler lowercases the keywords, so both sides meet in lower case.
	if !typed.Client.Match(&overlay.MatchInput{Host: "tnc.capcutapi.com", Network: overlay.NetworkTCP}).Matched {
		t.Fatal("an upper-case keyword did not match a lower-case host")
	}
}

// A deliberate, tested divergence from mihomo's native rules.
//
// mihomo's DOMAIN-KEYWORD lowercases the keyword at construction but matches it
// against metadata.RuleHost() unchanged (rules/common/domain_keyword.go), so a
// mixed-case host misses. The overlay lowercases the host as well
// (rules/common/runtime_overlay.go), so it matches.
//
// The overlay's behaviour is the intended one. DNS names are case-insensitive:
// a device reaching GS-LOC.APPLE.COM is reaching the host the operator
// authorised for capture, and letting case variation slip past the capture set
// would be a bypass, not a nicety. This test exists so the difference is a
// recorded decision rather than something rediscovered as a surprise.
func TestKeywordAndDomainMatchingIsCaseInsensitiveByDesign(t *testing.T) {
	mixed := "TNC16-normal-ALISG.CapCutAPI.com"

	legacy := mustParseLegacy(t, "AND,((DOMAIN-SUFFIX,capcutapi.com),(DOMAIN-KEYWORD,tnc)),DIRECT")
	legacyMatched, _ := legacy.Match(&C.Metadata{NetWork: C.TCP, Host: mixed, DstPort: 443}, C.RuleMatchHelper{})

	typed := compileTyped(t, overlay.ClientRule{
		Kind: overlay.SelectorDomainSuffix, Value: "capcutapi.com",
		KeywordsAll: []string{"tnc"}, Action: overlay.ActionDirect,
	})
	// The rule layer lowercases before building MatchInput; mirror that here.
	typedMatched := typed.Client.Match(&overlay.MatchInput{
		Host: strings.ToLower(mixed), DstPort: 443, Network: overlay.NetworkTCP,
	}).Matched

	if !typedMatched {
		t.Fatal("the overlay failed to match a mixed-case host; capture would be bypassable by case variation")
	}
	if legacyMatched {
		t.Log("note: mihomo's native rule now matches mixed case too; the divergence this test records has closed")
	} else {
		t.Logf("recorded divergence: native mihomo misses %q, the overlay matches it", mixed)
	}

	// Whatever the native rule does, the overlay must be consistent: the same
	// host in any case must produce the same decision.
	for _, variant := range []string{mixed, strings.ToLower(mixed), strings.ToUpper(mixed)} {
		got := typed.Client.Match(&overlay.MatchInput{
			Host: strings.ToLower(variant), DstPort: 443, Network: overlay.NetworkTCP,
		}).Matched
		if !got {
			t.Errorf("case variant %q did not match", variant)
		}
	}
}

// TestMixedCaseSNIBypassesLegacyCaptureRules records why the overlay's
// lowercasing is not merely a nicety.
//
// mihomo's TLS sniffer returns the SNI verbatim (component/sniffer/tls_sniffer.go
// only strips a trailing dot; the HTTP sniffer does lowercase, the TLS one does
// not), replaceDomain puts it in SniffHost, and RuleHost() prefers SniffHost.
// Every native domain matcher then compares that string against a lowercased
// payload without normalising it.
//
// The consequence for a capture rule is that a client which sends mixed-case
// SNI is not captured at all: the rule misses, and resolution falls through to
// the operator's terminal MATCH. The overlay's client stage lowercases the host
// before matching and therefore still captures it.
func TestMixedCaseSNIBypassesLegacyCaptureRules(t *testing.T) {
	const wantHost = "gs-loc.apple.com"
	// What a client controls, and what the TLS sniffer hands on verbatim.
	sniffed := "GS-LOC.Apple.COM"

	for _, line := range []string{
		"DOMAIN," + wantHost + ",REJECT",
		"DOMAIN-SUFFIX,apple.com,REJECT",
		"DOMAIN-KEYWORD,gs-loc,REJECT",
	} {
		t.Run(line, func(t *testing.T) {
			rule := mustParseLegacy(t, line)
			lower, _ := rule.Match(&C.Metadata{NetWork: C.TCP, SniffHost: strings.ToLower(sniffed), DstPort: 443}, C.RuleMatchHelper{})
			mixed, _ := rule.Match(&C.Metadata{NetWork: C.TCP, SniffHost: sniffed, DstPort: 443}, C.RuleMatchHelper{})

			if !lower {
				t.Fatalf("fixture is wrong: %q does not match the lower-case host", line)
			}
			if mixed {
				t.Logf("native rule %q matches mixed case; the gap this test records has closed", line)
				return
			}
			t.Logf("native rule %q misses mixed-case SNI %q — capture would fall through", line, sniffed)
		})
	}

	// The overlay does not have that gap. The action is irrelevant to the
	// matching path, so this uses reject to avoid needing a declared processor.
	typed := compileTyped(t, overlay.ClientRule{
		Kind: overlay.SelectorDomain, Value: wantHost, Action: overlay.ActionReject,
	})
	if !typed.Client.Match(&overlay.MatchInput{
		Host: strings.ToLower(sniffed), DstPort: 443, Network: overlay.NetworkTCP,
	}).Matched {
		t.Fatal("the overlay missed a mixed-case host; case variation would bypass capture")
	}
}
