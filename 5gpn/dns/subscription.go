package dns

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/metacubex/mihomo/5gpn/netguard"
	"github.com/metacubex/mihomo/5gpn/state"
	"github.com/metacubex/mihomo/log"

	D "github.com/miekg/dns"
	"gopkg.in/yaml.v3"
)

// A subscription rule is a policy rule whose names come from a list somebody
// else maintains. The fetch is deliberately conservative: every failure keeps
// the last complete cache, because a rule that silently narrows to nothing is
// a steering decision quietly reversed, and the operator would see it as
// "traffic stopped going through the gateway" with no error anywhere.

const (
	// maxSubscriptionBody bounds a response. Large enough for the published
	// domestic and blocklists, small enough that a hostile server cannot make
	// the resolver's memory its own.
	maxSubscriptionBody = 32 << 20
	maxSubscriptionURLs = 500_000
	// maxInvalidPercent rejects a parse whose result is mostly garbage. That
	// is the signature of the wrong format selected for a valid document, and
	// publishing the residue would give a rule a matcher nobody wrote.
	maxInvalidPercent = 40
	// minPolicyLabels refuses a single-label entry. A list that resolves to
	// "com" as a suffix would capture the internet.
	minPolicyLabels = 2

	subscriptionTick = time.Minute
)

var errEmptySubscription = errors.New("subscription contains no usable domains")

// subscriptionSource is the part of a rule that defines the bytes a fetch is
// expected to produce. Intent and interval changes do not change the source;
// URL and format changes do, even when the operator keeps the same rule ID.
type subscriptionSource struct {
	url    string
	format string
}

type subscriptionFetchToken struct {
	revision string
	ruleID   string
	source   subscriptionSource
}

func sourceOf(rule Rule) subscriptionSource {
	return subscriptionSource{url: rule.Value, format: rule.Format}
}

// SubscriptionStatus is what the console reports for one rule.
type SubscriptionStatus struct {
	RuleID      string    `json:"ruleId"`
	LastAttempt time.Time `json:"lastAttempt,omitempty"`
	LastSuccess time.Time `json:"lastSuccess,omitempty"`
	Entries     int       `json:"entries"`
	Error       string    `json:"error,omitempty"`

	// source names the last successful fetch. It stays private because it is a
	// scheduling fence, not API state. A failed fetch for a newly edited source
	// retains the old source here, keeping the new source immediately due until
	// it has actually published once.
	source subscriptionSource
}

type subscriptions struct {
	svc  *Service
	stop chan struct{}
	wake chan struct{}
	once sync.Once

	mu     sync.Mutex
	status map[string]SubscriptionStatus

	// downloadFn is a test seam. Production leaves it nil and uses download,
	// whose transport pins resolution through guardedDial.
	downloadFn func(context.Context, Rule) ([]string, error)
}

func newSubscriptions(s *Service) *subscriptions {
	subs := &subscriptions{
		svc:    s,
		stop:   make(chan struct{}),
		wake:   make(chan struct{}, 1),
		status: make(map[string]SubscriptionStatus),
	}
	go subs.run()
	return subs
}

func (s *subscriptions) run() {
	ticker := time.NewTicker(subscriptionTick)
	defer ticker.Stop()
	for {
		s.refreshDue()
		select {
		case <-s.stop:
			return
		case <-s.wake:
		case <-ticker.C:
		}
	}
}

func (s *subscriptions) wakeUp() {
	if s == nil {
		return
	}
	select {
	case s.wake <- struct{}{}:
	default:
	}
}

func (s *subscriptions) stopRun() {
	if s == nil {
		return
	}
	s.once.Do(func() { close(s.stop) })
}

// Status reports every subscription rule's last fetch.
func (s *subscriptions) snapshot() []SubscriptionStatus {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]SubscriptionStatus, 0, len(s.status))
	for _, st := range s.status {
		out = append(out, st)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].RuleID < out[j].RuleID })
	return out
}

// refreshDue fetches every enabled subscription rule whose interval has
// elapsed, then recompiles the policy once if anything landed.
func (s *subscriptions) refreshDue() {
	doc, revision := s.svc.Document()
	changed := false
	for _, rule := range doc.Policy.Rules {
		if !rule.Enabled || rule.Kind != KindSubscription {
			continue
		}
		if !s.due(rule) {
			continue
		}
		token := subscriptionFetchToken{revision: revision, ruleID: rule.ID, source: sourceOf(rule)}
		if s.fetch(rule, token) {
			changed = true
		}
	}
	if !changed {
		return
	}
	// One recompile for the whole round. Recompiling per rule would rebuild
	// every other rule's matcher for each list that landed.
	if err := s.svc.refreshCompiledPolicy(); err != nil {
		log.Errorln("[5GPN/DNS] policy recompile after subscription refresh: %v", err)
	}
}

func (s *subscriptions) due(rule Rule) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	st, ok := s.status[rule.ID]
	if !ok || st.LastSuccess.IsZero() || st.source != sourceOf(rule) {
		return true
	}
	return time.Since(st.LastSuccess) >= time.Duration(rule.IntervalSeconds)*time.Second
}

// fetch retrieves and stores one list, reporting whether the cache changed.
func (s *subscriptions) fetch(rule Rule, token subscriptionFetchToken) bool {
	if rule.ID != token.ruleID || sourceOf(rule) != token.source {
		return false
	}
	// A wake can carry an older document snapshot after an update. Avoid the
	// network call when that staleness is already visible.
	if !s.fetchCurrent(token) {
		return false
	}

	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	st := SubscriptionStatus{RuleID: rule.ID, LastAttempt: time.Now()}
	var names []string
	var err error
	if s.downloadFn != nil {
		names, err = s.downloadFn(ctx, rule)
	} else {
		names, err = s.download(ctx, rule)
	}
	if err == nil && len(names) == 0 {
		err = errEmptySubscription
	}
	if err != nil {
		// Do not let a completed request for an edited source replace the newer
		// source's status. The retained wake will schedule the new source.
		if !s.fetchCurrent(token) {
			return false
		}
		st.Error = err.Error()
		s.record(rule.ID, token.source, st, false)
		log.Warnln("[5GPN/DNS] subscription %s: %v (keeping the previous cache)", rule.ID, err)
		return false
	}

	published, err := s.publish(token, names)
	if err != nil {
		st.Error = err.Error()
		s.record(rule.ID, token.source, st, false)
		return false
	}
	if !published {
		log.Infoln("[5GPN/DNS] subscription %s: discarded fetch for an older document or source", rule.ID)
		return false
	}
	st.Entries = len(names)
	st.LastSuccess = time.Now()
	s.record(rule.ID, token.source, st, true)
	log.Infoln("[5GPN/DNS] subscription %s: %d names", rule.ID, len(names))
	return true
}

// publish performs the source/revision check and cache rename under the same
// update lock used by document writes. An update therefore lands either before
// this check (and rejects the old fetch) or after the complete cache publish;
// it cannot change the source between the check and the rename.
func (s *subscriptions) publish(token subscriptionFetchToken, names []string) (bool, error) {
	s.svc.updateMu.Lock()
	defer s.svc.updateMu.Unlock()
	if !s.fetchCurrent(token) {
		return false, nil
	}
	body := strings.Join(names, "\n") + "\n"
	if err := state.WriteFile(subscriptionCachePath(s.svc.rulesDir, token.ruleID), []byte(body)); err != nil {
		return false, err
	}
	return true, nil
}

func (s *subscriptions) fetchCurrent(token subscriptionFetchToken) bool {
	doc, revision := s.svc.Document()
	if revision != token.revision {
		return false
	}
	for _, rule := range doc.Policy.Rules {
		if rule.ID == token.ruleID && rule.Enabled && rule.Kind == KindSubscription {
			return sourceOf(rule) == token.source
		}
	}
	return false
}

func (s *subscriptions) record(id string, source subscriptionSource, st SubscriptionStatus, success bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if previous, ok := s.status[id]; ok && !success {
		// Keep what the last good fetch reported, so a failing rule still shows
		// the matcher that is actually live rather than zero.
		st.LastSuccess, st.Entries, st.source = previous.LastSuccess, previous.Entries, previous.source
	} else if success {
		st.source = source
	}
	s.status[id] = st
}

// download fetches and parses one list.
func (s *subscriptions) download(ctx context.Context, rule Rule) ([]string, error) {
	u, err := url.Parse(rule.Value)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" {
		return nil, fmt.Errorf("subscription url %q must be an absolute https URL", rule.Value)
	}

	client := &http.Client{
		Transport: &http.Transport{
			DialContext:         s.guardedDial,
			TLSHandshakeTimeout: 10 * time.Second,
			ForceAttemptHTTP2:   true,
		},
		// Every redirect hop is dialed through the same guard, so a redirect
		// cannot be used to reach an address the first request could not.
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 5 {
				return errors.New("too many redirects")
			}
			if req.URL.Scheme != "https" {
				return fmt.Errorf("redirect to non-https %q refused", req.URL.Scheme)
			}
			return nil
		},
		Timeout: 60 * time.Second,
	}
	defer client.CloseIdleConnections()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "*/*")

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("upstream returned HTTP %d", resp.StatusCode)
	}

	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxSubscriptionBody+1))
	if err != nil {
		return nil, err
	}
	if len(raw) > maxSubscriptionBody {
		return nil, fmt.Errorf("body exceeds %d bytes", maxSubscriptionBody)
	}
	names, err := parseDomains(rule.Format, raw)
	if err != nil {
		return nil, err
	}
	if len(names) == 0 {
		return nil, errEmptySubscription
	}
	return names, nil
}

// guardedDial resolves the host through this gateway's own trust group and
// refuses any address that is not a public unicast one.
//
// Resolving here rather than letting the transport do it is what makes the
// check meaningful: a guard applied to a name the dialer resolves again
// afterwards checks one answer and dials another.
func (s *subscriptions) guardedDial(ctx context.Context, network, addr string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}

	var candidates []string
	if _, err := netip.ParseAddr(host); err == nil {
		candidates = []string{host}
	} else {
		candidates, err = s.svc.resolver.OriginResolve(ctx, host)
		if err != nil {
			return nil, fmt.Errorf("resolve %s: %w", host, err)
		}
	}

	var lastErr error
	for _, c := range candidates {
		addr, err := netip.ParseAddr(c)
		if err != nil {
			continue
		}
		if !isPublicUnicast(addr) {
			lastErr = fmt.Errorf("refusing to dial %s for %s", addr, host)
			continue
		}
		conn, err := (&net.Dialer{Timeout: 10 * time.Second}).DialContext(ctx, network, net.JoinHostPort(addr.String(), port))
		if err == nil {
			return conn, nil
		}
		lastErr = err
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("no usable address for %s", host)
	}
	return nil, lastErr
}

// isPublicUnicast preserves the local fetch boundary name while delegating the
// actual IANA scope decision to the product-wide audited guard.
func isPublicUnicast(a netip.Addr) bool {
	return netguard.IsPubliclyRoutable(a)
}

// --- parsers -------------------------------------------------------------

// parseDomains reduces a list in the named format to normalized, deduplicated,
// sorted names.
func parseDomains(format string, raw []byte) ([]string, error) {
	var lines []string
	var err error
	switch format {
	case "plain":
		lines, err = parsePlain(raw)
	case "gfwlist":
		lines, err = parseGFWList(raw)
	case "dnsmasq":
		lines, err = parseDnsmasq(raw)
	case "hosts":
		lines, err = parseHosts(raw)
	case "clash":
		lines, err = parseClash(raw)
	default:
		return nil, fmt.Errorf("unknown subscription format %q", format)
	}
	if err != nil {
		return nil, err
	}
	return normalizeList(lines)
}

func normalizeList(lines []string) ([]string, error) {
	if len(lines) > maxSubscriptionURLs {
		return nil, fmt.Errorf("list has %d candidates, over the %d limit", len(lines), maxSubscriptionURLs)
	}
	set := make(map[string]struct{}, len(lines))
	invalid, valid := 0, 0
	for _, l := range lines {
		d := normalizeDomain(l)
		if d == "" {
			continue
		}
		if !validListDomain(d) {
			invalid++
			continue
		}
		valid++
		set[d] = struct{}{}
	}
	if considered := invalid + valid; considered > 0 && invalid*100 > considered*maxInvalidPercent {
		return nil, fmt.Errorf("rejected: %d of %d entries are invalid", invalid, considered)
	}
	out := make([]string, 0, len(set))
	for d := range set {
		out = append(out, d)
	}
	sort.Strings(out)
	return out, nil
}

func validListDomain(d string) bool {
	if len(d) > 253 || isIPLiteral(d) {
		return false
	}
	labels, ok := D.IsDomainName(D.Fqdn(d))
	return ok && labels >= minPolicyLabels
}

func newScanner(raw []byte) *bufio.Scanner {
	s := bufio.NewScanner(bytes.NewReader(raw))
	// A generated list may legitimately carry a line larger than the scanner's
	// 64 KiB default. Bounding at the body limit means an oversized line is
	// rejected rather than silently parsed as its first 64 KiB.
	s.Buffer(make([]byte, 64*1024), maxSubscriptionBody)
	return s
}

func parsePlain(raw []byte) ([]string, error) {
	var out []string
	s := newScanner(raw)
	for s.Scan() {
		line := strings.TrimSpace(s.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		out = append(out, line)
	}
	return out, s.Err()
}

// parseGFWList decodes the base64 body, then strips the ABP syntax down to a
// host: '||' and '|scheme://' anchors, a trailing '^', and any path.
func parseGFWList(raw []byte) ([]string, error) {
	decoded, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(raw)))
	if err != nil {
		return nil, fmt.Errorf("decode gfwlist base64: %w", err)
	}
	var out []string
	s := newScanner(decoded)
	for s.Scan() {
		line := strings.TrimSpace(s.Text())
		if line == "" || strings.HasPrefix(line, "@@") || strings.HasPrefix(line, "!") {
			continue // blank, whitelist, comment
		}
		switch {
		case strings.HasPrefix(line, "||"):
			line = line[2:]
		case strings.HasPrefix(line, "|https://"):
			line = line[len("|https://"):]
		case strings.HasPrefix(line, "|http://"):
			line = line[len("|http://"):]
		case strings.HasPrefix(line, "|"):
			line = line[1:]
		}
		line = strings.TrimSuffix(line, "^")
		if idx := strings.IndexAny(line, "/^*"); idx >= 0 {
			line = line[:idx]
		}
		if line = strings.TrimSpace(line); line != "" {
			out = append(out, line)
		}
	}
	return out, s.Err()
}

// parseDnsmasq takes the domain out of server=/DOMAIN/IP and address=/DOMAIN/IP.
func parseDnsmasq(raw []byte) ([]string, error) {
	var out []string
	s := newScanner(raw)
	for s.Scan() {
		line := strings.TrimSpace(s.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		var rest string
		switch {
		case strings.HasPrefix(line, "server=/"):
			rest = line[len("server=/"):]
		case strings.HasPrefix(line, "address=/"):
			rest = line[len("address=/"):]
		default:
			continue
		}
		idx := strings.IndexByte(rest, '/')
		if idx <= 0 {
			continue
		}
		out = append(out, rest[:idx])
	}
	return out, s.Err()
}

// parseHosts takes the first hostname after the address on each line.
func parseHosts(raw []byte) ([]string, error) {
	var out []string
	s := newScanner(raw)
	for s.Scan() {
		line := s.Text()
		if idx := strings.IndexByte(line, '#'); idx >= 0 {
			line = line[:idx]
		}
		fields := strings.Fields(strings.TrimSpace(line))
		if len(fields) < 2 || fields[1] == "localhost" {
			continue
		}
		out = append(out, fields[1])
	}
	return out, s.Err()
}

// parseClash reads a Clash rule-provider document: a mapping with a payload
// sequence in that provider's own grammar.
//
// Every cached entry is loaded as a suffix, so DOMAIN and DOMAIN-SUFFIX
// collapse to the same match here and an exact-only rule is deliberately
// widened rather than dropped. Rule kinds carrying no name at all -- keyword,
// every IP-CIDR and GEOIP form, process and port matchers -- are dropped before
// normalization so they never count toward the invalid-entry threshold.
func parseClash(raw []byte) ([]string, error) {
	var doc struct {
		Payload []string `yaml:"payload"`
	}
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		return nil, fmt.Errorf("clash provider: %w", err)
	}
	out := make([]string, 0, len(doc.Payload))
	for _, entry := range doc.Payload {
		if d, ok := clashDomain(entry); ok {
			out = append(out, d)
		}
	}
	return out, nil
}

func clashDomain(entry string) (string, bool) {
	e := strings.TrimSpace(entry)
	if e == "" || strings.HasPrefix(e, "#") {
		return "", false
	}
	if kind, value, tokenized := strings.Cut(e, ","); tokenized {
		switch strings.ToUpper(strings.TrimSpace(kind)) {
		case "DOMAIN", "DOMAIN-SUFFIX":
			e = strings.TrimSpace(value)
		default:
			return "", false
		}
	}
	// Both suffix markers mean "this name and every subdomain", which is what
	// the cache already stores, so they are stripped rather than translated.
	e = strings.TrimPrefix(e, "+")
	e = strings.TrimPrefix(e, ".")
	if e == "" {
		return "", false
	}
	// A residual marker is a shape this parser does not model, and stripping it
	// matters more than it looks: a hostname may legally contain '+', so an
	// unstripped "+.example.com" passes name validation and is cached as a
	// literal entry that label-boundary matching can never match -- a
	// subscription reporting a healthy count while matching nothing.
	if strings.ContainsAny(e, "+*,/ \t") {
		return "", false
	}
	return e, true
}
