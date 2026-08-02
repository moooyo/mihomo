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
	"time"

	"github.com/metacubex/mihomo/gpn/dns/ingress"
	"github.com/metacubex/mihomo/gpn/state"
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

// Tuning is the small set of knobs with no correct universal value.
type Tuning struct {
	TimeoutMs     int `json:"timeoutMs,omitempty"`
	TTLMinSeconds int `json:"ttlMinSeconds,omitempty"`
	TTLMaxSeconds int `json:"ttlMaxSeconds,omitempty"`
	CacheSize     int `json:"cacheSize,omitempty"`
	MaxInflight   int `json:"maxInflight,omitempty"`
}

// DefaultDocument is what a gateway with no DNS state starts from.
//
// The trust member is a placeholder for a resolver on a clean path, not a
// public recursive one, and the installer is expected to replace it. It is
// present rather than empty because an empty group refuses every query, and a
// resolver that will not answer is harder to diagnose from a phone than one
// answering from an address the operator recognises as wrong.
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
		Policy: Policy{Fallback: FallbackAuto},
	}
}

// Validate checks a candidate document without applying it.
func (d Document) Validate() error {
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
		if err != nil || !addr.Unmap().Is4() {
			return fmt.Errorf("%w: gateway %q must be an IPv4 address", ErrInvalidPolicy, d.Gateway)
		}
	}
	return nil
}

// Service owns the DNS document, the resolver it configures, and the listeners
// that serve it.
type Service struct {
	doc      *state.Doc[Document]
	resolver *Resolver
	ing      *ingress.Ingress
	certs    *certSource
	rulesDir string

	mu    sync.Mutex
	bound Listen

	subs *subscriptions
}

// Open loads the document and builds a configured resolver. It does not bind
// anything; Listen does that, so a bind failure is a separate outcome from an
// unusable document.
func Open(stateDir string) (*Service, error) {
	doc, err := state.New(filepath.Join(stateDir, "dns.json"), DefaultDocument())
	if err != nil {
		return nil, err
	}
	rulesDir := filepath.Join(stateDir, "dns-rules")
	if err := os.MkdirAll(rulesDir, 0o700); err != nil {
		return nil, fmt.Errorf("gpn/dns: create %s: %w", rulesDir, err)
	}

	current := doc.Get().Value
	if err := current.Validate(); err != nil {
		return nil, err
	}

	tuning := current.Tuning
	s := &Service{
		doc: doc,
		resolver: NewResolver(Options{
			Timeout:     time.Duration(tuning.TimeoutMs) * time.Millisecond,
			TTLMin:      time.Duration(tuning.TTLMinSeconds) * time.Second,
			TTLMax:      time.Duration(tuning.TTLMaxSeconds) * time.Second,
			CacheSize:   tuning.CacheSize,
			MaxInflight: tuning.MaxInflight,
		}),
		ing:      &ingress.Ingress{},
		certs:    &certSource{},
		rulesDir: rulesDir,
	}
	if err := s.apply(current); err != nil {
		return nil, err
	}
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
	snap, err := s.doc.Update(revision, func(current Document) (Document, error) {
		next, err := mutate(current)
		if err != nil {
			return current, err
		}
		if err := next.Validate(); err != nil {
			return current, err
		}
		return next, nil
	})
	if err != nil {
		return snap.Value, snap.Revision, err
	}
	if err := s.apply(snap.Value); err != nil {
		return snap.Value, snap.Revision, err
	}
	// A listener change needs a rebind; everything else is already live.
	if err := s.relisten(snap.Value.Listen); err != nil {
		return snap.Value, snap.Revision, err
	}
	s.subs.wakeUp()
	return snap.Value, snap.Revision, nil
}

// apply pushes a validated document into the running resolver.
func (s *Service) apply(d Document) error {
	china, err := ParseMembers("china", d.Upstreams.China)
	if err != nil {
		return err
	}
	trust, err := ParseMembers("trust", d.Upstreams.Trust)
	if err != nil {
		return err
	}
	ecs, err := parseECS(d.Upstreams.ECS)
	if err != nil {
		return err
	}
	if err := s.resolver.SetPolicy(d.Policy, s.rulesDir); err != nil {
		return err
	}
	s.resolver.SetUpstreams(china, trust, ecs)
	s.resolver.SetLocalNames(d.LocalNames)

	gateway := netip.Addr{}
	if g := strings.TrimSpace(d.Gateway); g != "" {
		if addr, err := netip.ParseAddr(g); err == nil {
			gateway = addr
		}
	}
	s.resolver.SetGateway(gateway)

	s.certs.set(d.Listen.Certificate, d.Listen.PrivateKey)
	return nil
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

	next := &ingress.Ingress{}
	cfg := ingress.Config{DoT: want.DoT, Debug: want.Debug, Origin: want.Origin}
	if want.DoT != "" {
		if want.Certificate == "" || want.PrivateKey == "" {
			return errors.New("gpn/dns: the DoT listener needs a certificate and private key")
		}
		if _, err := s.certs.load(); err != nil {
			return err
		}
		cfg.Certificate = s.certs.get
	}
	if err := next.Start(cfg, s.resolver, s.resolver.Origin()); err != nil {
		return err
	}

	previous := s.ing
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
	log.Infoln("[GPN/DNS] listening: DoT %q debug %q origin %q", want.DoT, want.Debug, want.Origin)
	return nil
}

// Subscriptions reports every subscription rule's last fetch.
func (s *Service) Subscriptions() []SubscriptionStatus { return s.subs.snapshot() }

// Shutdown stops the listeners and the subscription refresher.
func (s *Service) Shutdown(ctx context.Context) {
	s.subs.stopRun()
	s.mu.Lock()
	ing := s.ing
	s.mu.Unlock()
	if ing != nil {
		ing.Shutdown(ctx)
	}
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
		return nil, errors.New("gpn/dns: no DoT certificate configured")
	}

	certInfo, err := os.Stat(c.certFile)
	if err != nil {
		return nil, fmt.Errorf("gpn/dns: certificate %s: %w", c.certFile, err)
	}
	keyInfo, err := os.Stat(c.keyFile)
	if err != nil {
		return nil, fmt.Errorf("gpn/dns: private key %s: %w", c.keyFile, err)
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
			log.Warnln("[GPN/DNS] certificate reload failed, keeping the previous leaf: %v", err)
			return c.cert, nil
		}
		return nil, fmt.Errorf("gpn/dns: load certificate: %w", err)
	}
	c.cert = &pair
	c.modCert, c.modKey = certInfo.ModTime(), keyInfo.ModTime()
	return c.cert, nil
}
