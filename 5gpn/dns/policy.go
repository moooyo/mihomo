package dns

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	D "github.com/miekg/dns"
)

// The operator policy is one ordered list evaluated once, first match wins,
// across every intent. There are no per-intent passes and no separate block
// list: an operator who writes a `direct` rule above a `block` rule gets
// exactly that, which is the only reading of "ordered" they can hold in their
// head while editing.
//
// A rule decides DNS steering and nothing else. IntentProxy means "answer with
// the gateway address"; what mihomo does with the connection once it arrives is
// the operator's rule tree, so a rule here never names a proxy, group, or
// selector, and there is no field in which it could.

// MatcherKind is how a rule's Value is interpreted.
type MatcherKind string

const (
	// KindDomain matches that exact name only.
	KindDomain MatcherKind = "domain"
	// KindDomainSuffix matches the name itself or any subdomain, on label
	// boundaries.
	KindDomainSuffix MatcherKind = "domain-suffix"
	// KindDomainKeyword matches any name containing Value as a substring.
	KindDomainKeyword MatcherKind = "domain-keyword"
	// KindSubscription expands to many suffix matches fetched from a remote
	// list; Format and IntervalSeconds govern the fetch.
	KindSubscription MatcherKind = "subscription"
)

// Intent is what a matching query resolves as.
type Intent string

const (
	// IntentBlock answers NXDOMAIN without consulting an upstream.
	IntentBlock Intent = "block"
	// IntentDirect resolves through the same arbitration as an unmatched name
	// and returns the real addresses, never the gateway.
	IntentDirect Intent = "direct"
	// IntentProxy answers with the gateway address, so the client connects here
	// and the sniffer recovers where it meant to go.
	IntentProxy Intent = "proxy"
)

// Fallback governs a name no rule matched.
type Fallback string

const (
	// FallbackAuto arbitrates china against trust and rewrites foreign
	// addresses to the gateway. The default, and the only one that steers
	// without the operator listing anything.
	FallbackAuto Fallback = "auto"
	// FallbackDirect uses the same arbitration but returns the real addresses.
	FallbackDirect Fallback = "direct"
	// FallbackGateway answers with the gateway address without asking anyone.
	FallbackGateway Fallback = "gateway"
)

// Rule is one entry in evaluation order. Its position in the slice IS its
// order: the previous model carried an explicit Order field that validation
// then required to equal the index, which made it a second name for the same
// fact and one more thing a caller could set inconsistently.
//
// The slice is kept grouped -- every hand-written rule, then every
// subscription -- by Policy.ordered on the way in. See it for why.
type Rule struct {
	ID      string      `json:"id"`
	Kind    MatcherKind `json:"kind"`
	Value   string      `json:"value"`
	Intent  Intent      `json:"intent"`
	Enabled bool        `json:"enabled"`

	// Format and IntervalSeconds apply to subscription rules and must be unset
	// for every other kind.
	Format          string `json:"format,omitempty"`
	IntervalSeconds int    `json:"intervalSeconds,omitempty"`
}

// Policy is the operator's ordered list plus the unmatched-name strategy.
type Policy struct {
	Rules    []Rule   `json:"rules"`
	Fallback Fallback `json:"fallback"`
}

// ErrInvalidPolicy wraps every caller-caused validation failure so the API can
// answer 400 rather than 500.
var ErrInvalidPolicy = errors.New("5gpn/dns: invalid policy")

// ordered returns the policy with its rules grouped into evaluation order:
// every hand-written rule, in the operator's order, then every subscription, in
// theirs. Relative order inside each group is untouched.
//
// classify takes the first match, so "does my exception beat the imported
// list?" used to be answered by whichever of the two happened to sit earlier in
// one array. That was a fair question to ask of a single list an operator could
// see and reorder. It stopped being fair once the console split the two kinds
// into separate dialogs, where the shared index is not visible at all -- an
// exception could be silently outranked by a subscription with nothing on
// screen to say so.
//
// Pinning it here rather than in the console means every writer gets the same
// precedence: the panel, the bot, and a direct PUT. And it stays true that a
// rule's position in the slice is the whole statement of when it runs -- the
// grouping is applied to the stored document, not layered on top of it at
// match time.
func (p Policy) ordered() Policy {
	if p.rulesAreGrouped() {
		return p
	}
	out := make([]Rule, 0, len(p.Rules))
	for _, r := range p.Rules {
		if r.Kind != KindSubscription {
			out = append(out, r)
		}
	}
	for _, r := range p.Rules {
		if r.Kind == KindSubscription {
			out = append(out, r)
		}
	}
	p.Rules = out
	return p
}

// rulesAreGrouped reports whether no subscription precedes a hand-written rule.
func (p Policy) rulesAreGrouped() bool {
	subscriptionSeen := false
	for _, r := range p.Rules {
		if r.Kind == KindSubscription {
			subscriptionSeen = true
			continue
		}
		if subscriptionSeen {
			return false
		}
	}
	return true
}

var (
	validKinds = map[MatcherKind]bool{
		KindDomain: true, KindDomainSuffix: true, KindDomainKeyword: true, KindSubscription: true,
	}
	validIntents    = map[Intent]bool{IntentBlock: true, IntentDirect: true, IntentProxy: true}
	validFallbacks  = map[Fallback]bool{FallbackAuto: true, FallbackDirect: true, FallbackGateway: true}
	validFormats    = map[string]bool{"plain": true, "gfwlist": true, "dnsmasq": true, "hosts": true, "clash": true}
	policyIDPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$`)
)

// Validate checks the whole policy. Rule IDs must be path-safe because they
// name a subscription's cache file on disk.
func (p Policy) Validate() error {
	if !validFallbacks[p.Fallback] {
		return fmt.Errorf("%w: fallback %q must be auto, direct, or gateway", ErrInvalidPolicy, p.Fallback)
	}
	seen := make(map[string]bool, len(p.Rules))
	for _, r := range p.Rules {
		if !policyIDPattern.MatchString(r.ID) {
			return fmt.Errorf("%w: rule id %q must be a path-safe identifier", ErrInvalidPolicy, r.ID)
		}
		if seen[r.ID] {
			return fmt.Errorf("%w: duplicate rule id %q", ErrInvalidPolicy, r.ID)
		}
		seen[r.ID] = true
		if err := r.Validate(); err != nil {
			return fmt.Errorf("rule %q: %w", r.ID, err)
		}
	}
	return nil
}

// Validate checks one rule's kind, intent, and value shape.
func (r Rule) Validate() error {
	if !validIntents[r.Intent] {
		return fmt.Errorf("%w: intent %q must be block, direct, or proxy", ErrInvalidPolicy, r.Intent)
	}
	if !validKinds[r.Kind] {
		return fmt.Errorf("%w: kind %q is unknown", ErrInvalidPolicy, r.Kind)
	}
	if r.Value == "" {
		return fmt.Errorf("%w: value must not be empty", ErrInvalidPolicy)
	}
	if err := rejectControlBytes("value", r.Value); err != nil {
		return err
	}

	if r.Kind != KindSubscription && (r.Format != "" || r.IntervalSeconds != 0) {
		return fmt.Errorf("%w: kind %q must not set format or interval", ErrInvalidPolicy, r.Kind)
	}

	switch r.Kind {
	case KindSubscription:
		if !strings.HasPrefix(r.Value, "https://") {
			return fmt.Errorf("%w: subscription url %q must be https", ErrInvalidPolicy, r.Value)
		}
		if !validFormats[r.Format] {
			return fmt.Errorf("%w: format %q must be plain, gfwlist, dnsmasq, hosts, or clash", ErrInvalidPolicy, r.Format)
		}
		if r.IntervalSeconds <= 0 {
			return fmt.Errorf("%w: subscription interval must be positive", ErrInvalidPolicy)
		}
	case KindDomain, KindDomainSuffix:
		if !isPolicyDomain(r.Value) {
			return fmt.Errorf("%w: %q is not a valid domain", ErrInvalidPolicy, r.Value)
		}
	}
	return nil
}

// rejectControlBytes refuses a newline, carriage return, or other C0 byte
// before the value is persisted or rendered anywhere.
func rejectControlBytes(field, s string) error {
	for i := 0; i < len(s); i++ {
		if c := s[i]; c == '\n' || c == '\r' || c < 0x20 {
			return fmt.Errorf("%w: %s must not contain a control character", ErrInvalidPolicy, field)
		}
	}
	return nil
}

// isPolicyDomain accepts a name of at least two labels that is not an address
// literal. A single label would match far more than an operator typing it
// intends, and an address is not a name this resolver can be asked about.
func isPolicyDomain(v string) bool {
	v = normalizeDomain(v)
	if v == "" || len(v) > 253 {
		return false
	}
	if isIPLiteral(v) {
		return false
	}
	labels, ok := D.IsDomainName(D.Fqdn(v))
	return ok && labels >= 2
}

func normalizeDomain(d string) string {
	return strings.TrimRight(strings.ToLower(strings.TrimSpace(d)), ".")
}

// domainSet is one rule's materialized matcher.
//
// One set per rule rather than one merged set per intent: merging is what
// destroys cross-intent first-match, because the merged sets then have to be
// consulted in some fixed intent order that the operator never wrote down.
type domainSet struct {
	exact   map[string]struct{}
	suffix  map[string]struct{}
	keyword []string
}

// match reports whether name is covered. name may carry a trailing dot.
func (d *domainSet) match(name string) bool {
	if d == nil {
		return false
	}
	name = normalizeDomain(name)
	if name == "" {
		return false
	}
	if _, ok := d.exact[name]; ok {
		return true
	}
	if len(d.suffix) > 0 {
		// Walk label boundaries. Every candidate is a slice of name, so a miss
		// costs no allocation -- which matters, because a random-subdomain
		// flood makes the miss path the only path.
		for cur := name; cur != ""; {
			if _, ok := d.suffix[cur]; ok {
				return true
			}
			dot := strings.IndexByte(cur, '.')
			if dot < 0 {
				break
			}
			cur = cur[dot+1:]
		}
	}
	for _, kw := range d.keyword {
		if strings.Contains(name, kw) {
			return true
		}
	}
	return false
}

func (d *domainSet) len() int {
	if d == nil {
		return 0
	}
	return len(d.exact) + len(d.suffix) + len(d.keyword)
}

// compiledRule is one rule with its matcher built.
//
// Kind and Value carry no matching weight; they exist so a diagnostic can name
// the rule that won instead of reporting only the intent it produced. Matching
// a name and being able to explain the match are separate requirements, and the
// matcher has discarded the declaration by the time a verdict exists.
type compiledRule struct {
	ID     string
	Kind   MatcherKind
	Value  string
	Intent Intent
	set    *domainSet
	// entries is the matcher's size, so the console can show an operator that a
	// subscription fetched 62,000 names or that it fetched none yet.
	entries int
}

type compiledPolicy struct {
	Rules    []compiledRule
	Fallback Fallback
}

// compile materializes every enabled rule's matcher.
//
// A subscription whose cache file is missing compiles to an empty matcher
// rather than an error, so a policy can be applied before its first fetch
// succeeds; a cache that exists but cannot be read is a hard failure, because
// that is a matcher silently narrower than the operator's intent.
func compile(p Policy, cacheDir string) (*compiledPolicy, error) {
	if err := p.Validate(); err != nil {
		return nil, err
	}
	out := &compiledPolicy{Rules: make([]compiledRule, 0, len(p.Rules)), Fallback: p.Fallback}
	for _, r := range p.Rules {
		if !r.Enabled {
			continue
		}
		set := &domainSet{exact: map[string]struct{}{}, suffix: map[string]struct{}{}}
		switch r.Kind {
		case KindDomain:
			set.exact[normalizeDomain(r.Value)] = struct{}{}
		case KindDomainSuffix:
			set.suffix[normalizeDomain(r.Value)] = struct{}{}
		case KindDomainKeyword:
			set.keyword = []string{strings.ToLower(strings.TrimSpace(r.Value))}
		case KindSubscription:
			if err := loadSubscriptionCache(set, subscriptionCachePath(cacheDir, r.ID)); err != nil {
				return nil, fmt.Errorf("5gpn/dns: rule %s subscription cache: %w", r.ID, err)
			}
		}
		out.Rules = append(out.Rules, compiledRule{
			ID: r.ID, Kind: r.Kind, Value: r.Value, Intent: r.Intent, set: set, entries: set.len(),
		})
	}
	return out, nil
}

// subscriptionCachePath names a rule's fetched list. Keyed on the rule ID
// alone, so changing a rule's intent does not orphan a list already fetched.
func subscriptionCachePath(dir, ruleID string) string {
	return filepath.Join(dir, ruleID+".txt")
}

// loadSubscriptionCache reads a fetched list as suffix entries.
//
// Every entry becomes a suffix regardless of the source format. That
// deliberately widens a provider's exact-name rule, which is the right default
// for a steering list -- a list naming example.com almost always means its
// subdomains too -- and it is the only shape a single cache file can carry
// without inventing a second grammar inside it.
func loadSubscriptionCache(set *domainSet, path string) error {
	raw, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	for _, line := range strings.Split(string(raw), "\n") {
		line = normalizeDomain(strings.TrimSpace(line))
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		set.suffix[line] = struct{}{}
	}
	return nil
}

// classify walks the ordered rules and returns the first match with the rule
// that produced it, or a zero verdict when nothing matched.
func (c *compiledPolicy) classify(name string) (Verdict, *compiledRule) {
	if c == nil {
		return Verdict{}, nil
	}
	for i := range c.Rules {
		r := &c.Rules[i]
		if !r.set.match(name) {
			continue
		}
		switch r.Intent {
		case IntentBlock:
			return Verdict{Verdict: "block", Reason: "block"}, r
		case IntentDirect:
			return Verdict{Verdict: "direct", Reason: "force-direct"}, r
		case IntentProxy:
			return Verdict{Verdict: "proxy", Reason: "force-proxy"}, r
		}
	}
	return Verdict{}, nil
}

func (c *compiledPolicy) fallback() Fallback {
	if c == nil || c.Fallback == "" {
		return FallbackAuto
	}
	return c.Fallback
}
