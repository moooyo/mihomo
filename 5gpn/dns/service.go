package dns

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/metacubex/mihomo/5gpn/dns/ingress"
	"github.com/metacubex/mihomo/5gpn/state"
	"github.com/metacubex/mihomo/log"
	"github.com/metacubex/tls"
)

// Document is the whole operator-owned DNS state, in one file with one
// revision.
//
// It replaces four: policy.json, upstreams.json, ecs.json, and the DNS-shaped
// half of an environment file that systemd read and the daemon could not write.
// Splitting them made every cross-cutting edit -- change the gateway address
// and the upstreams that serve it -- two writes with no way to name the pair,
// and put the one file the console most needed to fix out of its reach.
type Document struct {
	Listen     Listen    `json:"listen"`
	Gateway    string    `json:"gateway"`
	LocalNames []string  `json:"localNames,omitempty"`
	Upstreams  Upstreams `json:"upstreams"`
	Policy     Policy    `json:"policy"`
	Tuning     Tuning    `json:"tuning"`
}

// Listen is where the resolver binds and what identity it presents.
type Listen struct {
	// DoT is the only client-facing ingress. Empty disables it.
	DoT string `json:"dot"`
	// Debug is a loopback plain-UDP listener for on-box troubleshooting.
	Debug string `json:"debug,omitempty"`
	// Origin is the loopback boundary mihomo's own resolver queries.
	Origin string `json:"origin,omitempty"`
	// Certificate and PrivateKey are the DoT leaf, re-read as it is renewed.
	Certificate string `json:"certificate,omitempty"`
	PrivateKey  string `json:"privateKey,omitempty"`
}

// Upstreams are the two groups and the client subnet attached to the domestic
// one.
type Upstreams struct {
	China []string `json:"china"`
	Trust []string `json:"trust"`
	// ECS is the subnet sent to the china group. Empty disables it.
	ECS string `json:"ecs,omitempty"`
}

// Tuning is the small set of knobs with no correct universal value. Zero uses
// the built-in default; non-zero values are bounded by normalized so a durable
// write cannot turn the next process start into an allocation or duration
// failure.
type Tuning struct {
	TimeoutMs     int `json:"timeoutMs,omitempty"`
	TTLMinSeconds int `json:"ttlMinSeconds,omitempty"`
	TTLMaxSeconds int `json:"ttlMaxSeconds,omitempty"`
	CacheSize     int `json:"cacheSize,omitempty"`
	MaxInflight   int `json:"maxInflight,omitempty"`
}

const (
	minDocumentTimeout  = 100 * time.Millisecond
	maxDocumentTimeout  = 30 * time.Second
	maxDocumentTTLMin   = 24 * time.Hour
	maxDocumentTTLMax   = 7 * 24 * time.Hour
	minDocumentCache    = 128
	maxDocumentCache    = 16384
	maxDocumentInflight = 4096
)

// normalized validates operator-supplied values and expands zero to the
// documented defaults. Negative, nonsensical, and resource-exhausting values
// are rejected instead of being silently treated as defaults at startup.
func (t Tuning) normalized() (runtimeTuning, error) {
	if t.TimeoutMs < 0 || t.TTLMinSeconds < 0 || t.TTLMaxSeconds < 0 || t.CacheSize < 0 || t.MaxInflight < 0 {
		return runtimeTuning{}, fmt.Errorf("%w: tuning values cannot be negative", ErrInvalidPolicy)
	}
	if t.TimeoutMs != 0 && (t.TimeoutMs < int(minDocumentTimeout/time.Millisecond) || t.TimeoutMs > int(maxDocumentTimeout/time.Millisecond)) {
		return runtimeTuning{}, fmt.Errorf("%w: tuning timeoutMs must be 0 or between %d and %d", ErrInvalidPolicy, minDocumentTimeout/time.Millisecond, maxDocumentTimeout/time.Millisecond)
	}
	if t.TTLMinSeconds != 0 && (t.TTLMinSeconds < 1 || t.TTLMinSeconds > int(maxDocumentTTLMin/time.Second)) {
		return runtimeTuning{}, fmt.Errorf("%w: tuning ttlMinSeconds must be 0 or between 1 and %d", ErrInvalidPolicy, int(maxDocumentTTLMin/time.Second))
	}
	if t.TTLMaxSeconds != 0 && (t.TTLMaxSeconds < 1 || t.TTLMaxSeconds > int(maxDocumentTTLMax/time.Second)) {
		return runtimeTuning{}, fmt.Errorf("%w: tuning ttlMaxSeconds must be 0 or between 1 and %d", ErrInvalidPolicy, int(maxDocumentTTLMax/time.Second))
	}
	cacheSize := t.CacheSize
	if cacheSize == 0 {
		cacheSize = defaultCacheSize
	}
	if cacheSize < minDocumentCache || cacheSize > maxDocumentCache {
		return runtimeTuning{}, fmt.Errorf("%w: tuning cacheSize must be 0 or between %d and %d", ErrInvalidPolicy, minDocumentCache, maxDocumentCache)
	}
	maxInflight := t.MaxInflight
	if maxInflight == 0 {
		maxInflight = defaultMaxInflight
	}
	if maxInflight < 1 || maxInflight > maxDocumentInflight {
		return runtimeTuning{}, fmt.Errorf("%w: tuning maxInflight must be 0 or between 1 and %d", ErrInvalidPolicy, maxDocumentInflight)
	}
	timeout := time.Duration(t.TimeoutMs) * time.Millisecond
	if timeout == 0 {
		timeout = defaultTimeout
	}
	ttlMin := time.Duration(t.TTLMinSeconds) * time.Second
	if ttlMin == 0 {
		ttlMin = defaultTTLMin
	}
	ttlMax := time.Duration(t.TTLMaxSeconds) * time.Second
	if ttlMax == 0 {
		ttlMax = defaultTTLMax
	}
	if ttlMax < ttlMin {
		return runtimeTuning{}, fmt.Errorf("%w: effective tuning ttlMaxSeconds must be at least ttlMinSeconds", ErrInvalidPolicy)
	}
	return runtimeTuning{
		timeout: timeout, ttlMin: ttlMin, ttlMax: ttlMax,
		cacheSize: cacheSize, maxInflight: maxInflight,
	}, nil
}

// DefaultDocument is what a gateway with no DNS state starts from.
//
// The trust member is a placeholder for a resolver on a clean path, not a
// public recursive one, and the installer is expected to replace it. It is
// present rather than empty because an empty group refuses every query, and a
// resolver that will not answer is harder to diagnose from a phone than one
// answering from an address the operator recognises as wrong.
// The two lists a fresh gateway starts with, carried over from the seed the
// pre-monolith installer wrote.
//
// One resolves China's domains DIRECT and one steers the GFW list to the
// gateway. Together they are the difference between a resolver that decides
// something and one that sends every name to the fallback -- which is a working
// gateway that appears to do nothing.
//
// Exported because DefaultDocument only ever applies to an ABSENT document.
// Every gateway that already has one would miss these, which is exactly how
// extension discovery once shipped dark on every existing host. The console
// offers them explicitly for that case, from this same definition, so the two
// paths cannot describe different defaults.
const (
	defaultChinaListURL = "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Clash/ChinaMax/ChinaMax_Domain.yaml"
	defaultGFWListURL   = "https://raw.githubusercontent.com/Loyalsoldier/v2ray-rules-dat/release/gfw.txt"
	defaultListInterval = 86400
)

func DefaultSubscriptionRules() []Rule {
	return []Rule{
		{
			ID:              "china-domains",
			Kind:            KindSubscription,
			Value:           defaultChinaListURL,
			Intent:          IntentDirect,
			Enabled:         true,
			Format:          "clash",
			IntervalSeconds: defaultListInterval,
		},
		{
			ID:              "gfwlist",
			Kind:            KindSubscription,
			Value:           defaultGFWListURL,
			Intent:          IntentProxy,
			Enabled:         true,
			Format:          "plain",
			IntervalSeconds: defaultListInterval,
		},
	}
}

func DefaultDocument() Document {
	return Document{
		Listen: Listen{
			DoT:    ":853",
			Debug:  "127.0.0.1:5353",
			Origin: "127.0.0.1:5354",
		},
		Upstreams: Upstreams{
			China: []string{"223.5.5.5:53"},
			Trust: []string{"22.22.22.22:53"},
			ECS:   "112.96.32.0/24",
		},
		// An explicit empty list rather than a nil slice. Go marshals nil as
		// `null`, and every consumer that iterates the policy -- the console,
		// the acceptance suites, an operator's jq -- errors on it rather than
		// seeing zero rules. `[]` says the same thing with nothing to trip on.
		Policy: Policy{Rules: DefaultSubscriptionRules(), Fallback: FallbackAuto},
	}
}

// Validate checks a candidate document without applying it.
func (d Document) Validate() error {
	if d.Policy.Rules == nil {
		return fmt.Errorf("%w: policy rules must be an array", ErrInvalidPolicy)
	}
	if !d.Policy.rulesAreGrouped() {
		return fmt.Errorf("%w: hand-written rules must precede subscriptions", ErrInvalidPolicy)
	}
	if err := d.Policy.Validate(); err != nil {
		return err
	}
	if _, err := ParseMembers("china", d.Upstreams.China); err != nil {
		return err
	}
	if _, err := ParseMembers("trust", d.Upstreams.Trust); err != nil {
		return err
	}
	if _, err := parseECS(d.Upstreams.ECS); err != nil {
		return err
	}
	if g := strings.TrimSpace(d.Gateway); g != "" {
		addr, err := netip.ParseAddr(g)
		if err != nil || !usableGateway(addr) {
			return fmt.Errorf("%w: gateway %q must be a usable unicast IPv4 address", ErrInvalidPolicy, d.Gateway)
		}
	}
	if _, err := d.Tuning.normalized(); err != nil {
		return err
	}
	return nil
}

// Service owns the DNS document, the resolver it configures, and the listeners
// that serve it.
type Service struct {
	doc                      *state.Doc[Document]
	resolver                 *Resolver
	ing                      *ingress.Ingress
	rulesDir                 string
	fatal                    func(error)
	requireCriticalListeners bool

	mu    sync.Mutex
	bound Listen
	// updateMu keeps the durable document and its runtime projection in one
	// order. state.Doc serializes writes, but releases its lock after the rename;
	// without this outer lock a later revision could publish before an earlier
	// writer resumes and installs stale runtime state.
	updateMu sync.Mutex
	closing  atomic.Bool

	subs *subscriptions
}

type preparedDocument struct {
	policy     *compiledPolicy
	ups        *upstreams
	localNames map[string]struct{}
	gateway    netip.Addr
	tuning     runtimeTuning
}

// Option configures process-level integration without putting process control
// inside the DNS packages.
type Option func(*Service)

// WithFatalHandler reports an unexpected listener exit after a successful
// bind. The owner normally terminates the monolith so its supervisor can
// restart the complete failure domain.
func WithFatalHandler(handler func(error)) Option {
	return func(s *Service) {
		s.fatal = handler
	}
}

// WithRequiredListeners applies the product boundary: the monolith must never
// report healthy without both client DoT and the loopback origin resolver.
// Lower-level resolver tests may omit them by leaving this option unset.
func WithRequiredListeners() Option {
	return func(s *Service) {
		s.requireCriticalListeners = true
	}
}

// Open loads the document and builds a configured resolver. It does not bind
// anything; Listen does that, so a bind failure is a separate outcome from an
// unusable document.
func Open(stateDir string, options ...Option) (*Service, error) {
	doc, err := state.New(filepath.Join(stateDir, "dns.json"), DefaultDocument())
	if err != nil {
		return nil, err
	}
	rulesDir := filepath.Join(stateDir, "dns-rules")
	if err := os.MkdirAll(rulesDir, 0o700); err != nil {
		return nil, fmt.Errorf("5gpn/dns: create %s: %w", rulesDir, err)
	}

	current := doc.Get().Value
	if err := current.Validate(); err != nil {
		return nil, err
	}
	tuning, _ := current.Tuning.normalized()
	s := &Service{
		doc: doc,
		resolver: NewResolver(Options{
			Timeout: tuning.timeout, TTLMin: tuning.ttlMin, TTLMax: tuning.ttlMax,
			CacheSize: tuning.cacheSize, MaxInflight: tuning.maxInflight,
		}),
		ing:      &ingress.Ingress{},
		rulesDir: rulesDir,
	}
	for _, option := range options {
		option(s)
	}
	if err := s.validateRequiredListeners(current.Listen); err != nil {
		return nil, err
	}
	prepared, err := prepareDocument(current, rulesDir)
	if err != nil {
		return nil, err
	}
	s.publish(prepared)
	s.subs = newSubscriptions(s)
	return s, nil
}

// Resolver is the configured decision engine.
func (s *Service) Resolver() *Resolver { return s.resolver }

// RulesDir is where subscription caches live.
func (s *Service) RulesDir() string { return s.rulesDir }

// Document returns the current document and its revision.
func (s *Service) Document() (Document, string) {
	snap := s.doc.Get()
	return snap.Value, snap.Revision
}

// Update validates and publishes a mutated document, then applies it.
//
// Validation runs before the write, so a rejected candidate leaves both the
// file and the running resolver exactly as they were. An empty revision means
// the caller owns the document outright; anything else must match or the update
// is refused, which is what stops two console tabs from silently overwriting
// each other.
func (s *Service) Update(revision string, mutate func(Document) (Document, error)) (Document, string, error) {
	s.updateMu.Lock()
	defer s.updateMu.Unlock()
	if s.closing.Load() {
		document, currentRevision := s.Document()
		return document, currentRevision, errors.New("5gpn/dns: service is shutting down")
	}

	var prepared *preparedDocument
	snap, err := s.doc.Update(revision, func(current Document) (Document, error) {
		next, err := mutate(current)
		if err != nil {
			return current, err
		}
		// Group before validating, so what is checked is what will be stored
		// and what will run.
		next.Policy = next.Policy.ordered()
		// Listener and certificate paths are installation-owned. Binding a
		// complete replacement while the unchanged critical sockets are live is
		// impossible without socket activation, and persisting before a bind
		// succeeds can turn one rejected API write into a permanent restart loop.
		// Whole-document clients therefore round-trip this section unchanged.
		if next.Listen != current.Listen {
			return current, fmt.Errorf("%w: listener settings are installation-owned", ErrInvalidPolicy)
		}
		prepared, err = prepareDocument(next, s.rulesDir)
		if err != nil {
			return current, err
		}
		return next, nil
	})
	if err != nil {
		if prepared != nil && prepared.ups != nil {
			prepared.ups.china.Close()
			prepared.ups.trust.Close()
		}
		return snap.Value, snap.Revision, err
	}
	s.publish(prepared)
	s.subs.wakeUp()
	return snap.Value, snap.Revision, nil
}

func (s *Service) refreshCompiledPolicy() error {
	s.updateMu.Lock()
	defer s.updateMu.Unlock()
	if s.closing.Load() {
		return errors.New("5gpn/dns: service is shutting down")
	}
	document, _ := s.Document()
	compiled, err := compile(document.Policy, s.rulesDir)
	if err != nil {
		return err
	}
	s.resolver.setCompiledPolicy(compiled)
	return nil
}

func prepareDocument(d Document, rulesDir string) (*preparedDocument, error) {
	if err := d.Validate(); err != nil {
		return nil, err
	}
	china, err := ParseMembers("china", d.Upstreams.China)
	if err != nil {
		return nil, err
	}
	trust, err := ParseMembers("trust", d.Upstreams.Trust)
	if err != nil {
		return nil, err
	}
	ecs, err := parseECS(d.Upstreams.ECS)
	if err != nil {
		return nil, err
	}
	policy, err := compile(d.Policy, rulesDir)
	if err != nil {
		return nil, err
	}

	gateway := netip.Addr{}
	if g := strings.TrimSpace(d.Gateway); g != "" {
		gateway, _ = netip.ParseAddr(g)
	}
	chinaGroup := newGroup("china", china)
	chinaGroup.SetECS(ecs)
	localNames := make(map[string]struct{}, len(d.LocalNames))
	for _, name := range d.LocalNames {
		if name = normalizeDomain(name); name != "" {
			localNames[name] = struct{}{}
		}
	}
	tuning, _ := d.Tuning.normalized()
	return &preparedDocument{
		policy:     policy,
		ups:        &upstreams{china: chinaGroup, trust: newGroup("trust", trust)},
		localNames: localNames,
		gateway:    gateway,
		tuning:     tuning,
	}, nil
}

// publish applies only objects that were completely prepared before the state
// document became durable. It cannot fail, so a successful revision can never
// describe runtime state the resolver refused to install.
func (s *Service) publish(prepared *preparedDocument) {
	s.resolver.applyDocumentRuntime(prepared.policy, prepared.ups, prepared.localNames, prepared.gateway, prepared.tuning)
}

// Listen binds the configured listeners.
func (s *Service) Listen() error {
	d, _ := s.Document()
	return s.relisten(d.Listen)
}

// relisten rebinds only when the listener configuration actually changed.
//
// Unconditional rebinding would drop :853 on every unrelated edit -- a policy
// rule, an upstream, a gateway address -- and each of those would be a moment
// where every client on the network has no resolver.
func (s *Service) relisten(want Listen) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.bound == want {
		return nil
	}

	next, err := s.startIngress(want)
	if err != nil {
		return err
	}
	s.publishIngressLocked(next, want)
	return nil
}

func (s *Service) startIngress(want Listen) (*ingress.Ingress, error) {
	if err := s.validateRequiredListeners(want); err != nil {
		return nil, err
	}
	next := &ingress.Ingress{}
	cfg := ingress.Config{DoT: want.DoT, Debug: want.Debug, Origin: want.Origin, Fatal: s.fatal}
	if want.DoT != "" {
		if want.Certificate == "" || want.PrivateKey == "" {
			return nil, errors.New("5gpn/dns: the DoT listener needs a certificate and private key")
		}
		certs := &certSource{}
		certs.set(want.Certificate, want.PrivateKey)
		if _, err := certs.load(); err != nil {
			return nil, err
		}
		cfg.Certificate = certs.get
	}
	if err := next.Start(cfg, s.resolver, s.resolver.Origin()); err != nil {
		return nil, err
	}
	return next, nil
}

func (s *Service) validateRequiredListeners(want Listen) error {
	if !s.requireCriticalListeners {
		return nil
	}
	if strings.TrimSpace(want.DoT) == "" || strings.TrimSpace(want.Origin) == "" {
		return errors.New("5gpn/dns: both DoT and origin listeners are required")
	}
	return nil
}

func (s *Service) publishIngressLocked(next *ingress.Ingress, want Listen) {
	previous := s.ing
	if previous != nil {
		previous.PrepareShutdown()
	}
	s.ing = next
	s.bound = want
	if previous != nil {
		// Drain the old listeners after the new ones are accepting, so the
		// window in which neither is bound is as close to zero as a rebind
		// allows.
		go func() {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			previous.Shutdown(ctx)
		}()
	}
	log.Infoln("[5GPN/DNS] listening: DoT %q debug %q origin %q", want.DoT, want.Debug, want.Origin)
}

// Subscriptions reports every subscription rule's last fetch.
func (s *Service) Subscriptions() []SubscriptionStatus { return s.subs.snapshot() }

// Shutdown stops the listeners and the subscription refresher.
func (s *Service) Shutdown(ctx context.Context) {
	if ctx == nil {
		ctx = context.Background()
	}
	s.closing.Store(true)
	s.subs.stopRun()
	// Wait for a document transaction that entered before closing became
	// visible. Update rechecks closing under this same lock, so nothing can
	// publish a fresh upstream generation after the final pools are closed.
	s.updateMu.Lock()
	s.updateMu.Unlock()
	s.mu.Lock()
	ing := s.ing
	s.mu.Unlock()
	if ing != nil {
		ing.Shutdown(ctx)
	}
	s.resolver.Close()
}

// certSource serves the DoT leaf, re-reading it as it is renewed.
//
// A function rather than a certificate captured at bind time, because the
// lineage is replaced underneath a running process by a root oneshot. Capturing
// once means serving an expired certificate until someone restarts the gateway,
// and nothing observes that until clients start failing.
type certSource struct {
	mu       sync.Mutex
	certFile string
	keyFile  string
	cert     *tls.Certificate
	modCert  time.Time
	modKey   time.Time
	checked  time.Time
}

func (c *certSource) set(certFile, keyFile string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if certFile != c.certFile || keyFile != c.keyFile {
		c.certFile, c.keyFile = certFile, keyFile
		c.cert, c.checked = nil, time.Time{}
	}
}

// get is the handshake callback. It re-stats at most once a minute: a handshake
// is not the place to pay two syscalls, and a renewal that takes a minute to be
// picked up is invisible next to a certificate lifetime measured in months.
func (c *certSource) get(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	c.mu.Lock()
	fresh := c.cert != nil && time.Since(c.checked) < time.Minute
	cert := c.cert
	c.mu.Unlock()
	if fresh {
		return cert, nil
	}
	return c.load()
}

func (c *certSource) load() (*tls.Certificate, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.certFile == "" || c.keyFile == "" {
		return nil, errors.New("5gpn/dns: no DoT certificate configured")
	}

	certInfo, err := os.Stat(c.certFile)
	if err != nil {
		return nil, fmt.Errorf("5gpn/dns: certificate %s: %w", c.certFile, err)
	}
	keyInfo, err := os.Stat(c.keyFile)
	if err != nil {
		return nil, fmt.Errorf("5gpn/dns: private key %s: %w", c.keyFile, err)
	}
	c.checked = time.Now()
	if c.cert != nil && certInfo.ModTime().Equal(c.modCert) && keyInfo.ModTime().Equal(c.modKey) {
		return c.cert, nil
	}

	pair, err := tls.LoadX509KeyPair(c.certFile, c.keyFile)
	if err != nil {
		// Keep serving the previous leaf. A renewal caught mid-write leaves a
		// certificate that does not match its key for a few milliseconds, and
		// failing the handshake there would drop DNS for every client that
		// happened to connect in that window.
		if c.cert != nil {
			log.Warnln("[5GPN/DNS] certificate reload failed, keeping the previous leaf: %v", err)
			return c.cert, nil
		}
		return nil, fmt.Errorf("5gpn/dns: load certificate: %w", err)
	}
	c.cert = &pair
	c.modCert, c.modKey = certInfo.ModTime(), keyInfo.ModTime()
	return c.cert, nil
}
