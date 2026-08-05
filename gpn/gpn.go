// Package gpn is the only 5gpn package the core is allowed to import.
//
// Everything else lives under gpn/ and is reachable only through here. That is
// not tidiness: the fork's cost is measured in edits to upstream-owned files,
// and a façade is what keeps that number from growing one import at a time.
// gpn/importrule_test.go enforces it.
package gpn

import (
	"context"
	"errors"
	"net"
	"path/filepath"
	"sync/atomic"
	"time"

	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/gpn/api"
	"github.com/metacubex/mihomo/gpn/bot"
	"github.com/metacubex/mihomo/gpn/dial"
	"github.com/metacubex/mihomo/gpn/dns"
	"github.com/metacubex/mihomo/gpn/engine"
	"github.com/metacubex/mihomo/gpn/state"
	"github.com/metacubex/mihomo/log"
	"github.com/metacubex/mihomo/tunnel"
)

var (
	stateDir  atomic.Pointer[string]
	engineRef atomic.Pointer[engine.Engine]
	dnsRef    atomic.Pointer[dns.Service]
	botRef    atomic.Pointer[bot.Service]
	installed atomic.Bool
)

// Start prepares the 5gpn subsystems and installs them into the core.
//
// It runs once, after the core has a home directory and before any listener
// accepts. Everything it installs is idempotent, because a config reload must
// not tear down the interception engine: mihomo's ApplyConfig rebuilds
// listeners, resolvers and the rule tree on every reload, and an engine that
// came and went with it would drop every captured session whenever an operator
// changed an unrelated proxy.
func Start(home string) error {
	dir, err := state.Dir(home)
	if err != nil {
		return err
	}
	stateDir.Store(&dir)

	// The engine cannot open a socket of its own. Both seams are pointed at
	// mihomo's own inner dialer so an intercepted upstream obeys exactly the
	// rules an ordinary connection would, and shows up in the same connection
	// table.
	engine.SetUpstreamAuthorizer(func(network C.NetWork, host string, port int, owner string, ownerOnly bool) (string, error) {
		return dial.Authorize(network, host, port, owner, ownerOnly)
	})
	engine.SetUpstreamDialer(func(ctx context.Context, host string, port int, owner string, ownerOnly bool) (net.Conn, error) {
		return dial.TCP(ctx, host, port, owner, ownerOnly)
	})
	engine.SetUpstreamPacketDialer(func(ctx context.Context, host string, port int, owner string, ownerOnly bool) (net.PacketConn, error) {
		return dial.UDP(ctx, host, port, owner, ownerOnly)
	})

	api.Advertise("gpn-core", api.Feature{Version: 1})
	installed.Store(true)
	log.Infoln("[GPN] state directory %s", dir)

	// The resolver comes up here rather than in StartInterception because it is
	// not optional: it is the reason a client points at this box at all. A
	// document it cannot parse is fatal, since starting with an empty policy
	// would resolve names the operator meant to block and steer nothing they
	// meant to steer.
	svc, err := dns.Open(dir)
	if err != nil {
		return err
	}
	dnsRef.Store(svc)
	tunnel.SetEgressProxyUpdateCallback(func() {
		svc.Resolver().FlushCache()
		if e := engineRef.Load(); e != nil {
			e.InvalidateEgressTransports()
		}
	})
	tunnel.SetClientBoundaryUpdateCallback(svc.Resolver().FlushCache)
	api.SetDNSService(svc)
	api.Advertise("gpn-dns", api.Feature{Version: 1})

	// Extension fetches resolve through the gateway's own trust group. Using
	// the host resolver instead would let the box's /etc/resolv.conf decide
	// where an operator's plugin code comes from, and on a gateway that is
	// frequently pointed back at this very process.
	engine.SetImporter(engine.NewImporter(func(ctx context.Context, host string) ([]string, error) {
		return svc.Resolver().OriginResolve(ctx, host)
	}))

	// Binding is a separate outcome. A gateway whose certificate has not been
	// issued yet must still come up, serve its API and let an operator finish
	// the bootstrap -- refusing to start would leave them with no surface on
	// which to fix the thing that stopped it.
	if err := svc.Listen(); err != nil {
		log.Warnln("[GPN/DNS] listeners not bound: %v", err)
	}

	// The interception engine comes up from a document beside the resolver's.
	// Both failures below are warnings for the same reason: interception is
	// optional relative to resolving and forwarding, and a gateway that cannot
	// read its extension document should still carry traffic rather than refuse
	// to boot.
	interceptPath := filepath.Join(dir, "intercept.json")
	if err := engine.EnsureDocument(interceptPath); err != nil {
		log.Warnln("[GPN] interception document unavailable: %v", err)
		return nil
	}
	if err := StartInterception(interceptPath); err != nil {
		log.Warnln("[GPN] interception engine not installed: %v", err)
	}

	// The bot comes up last because it reports on everything above it. Its
	// failures are warnings for the same reason interception's are: a gateway
	// that cannot read its bot document should still resolve and forward.
	if err := startBot(filepath.Join(dir, "bot.json")); err != nil {
		log.Warnln("[GPN] Telegram bot not installed: %v", err)
	}
	return nil
}

// startBot opens the bot document and starts the poll loop if it is enabled.
//
// The Facts it is given are the whole of what a chat command can reach. They
// are assembled here rather than in gpn/bot because the bot package must not
// import the resolver or the engine: what it cannot reach, no command added
// later can reach either.
func startBot(configPath string) error {
	api.Advertise("gpn-bot", api.Feature{})
	api.SetBotService(nil)
	botRef.Store(nil)

	svc, err := bot.Open(configPath, bot.Facts{
		Status:  gatewayStatus,
		Resolve: explainName,
	}, func(ctx context.Context, host string, port int) (net.Conn, error) {
		// Through the core's own rules, exactly as an engine upstream goes.
		// api.telegram.org is unreachable from a good number of the networks
		// this gateway runs on, and the operator has already configured how to
		// reach such places.
		return dial.SystemTCP(ctx, host, port)
	})
	if err != nil {
		return err
	}
	botRef.Store(svc)
	api.SetBotService(svc)
	api.Advertise("gpn-bot", api.Feature{Version: 1})
	svc.Apply()
	return nil
}

// Bot returns the Telegram control plane, or nil.
func Bot() *bot.Service { return botRef.Load() }

// gatewayStatus collects what the bot may report. Every field is something a
// console page already shows.
func gatewayStatus() bot.Status {
	status := bot.Status{}
	if svc := dnsRef.Load(); svc != nil {
		resolver := svc.Resolver()
		stats := resolver.Stats()
		china, trust := resolver.Upstreams()
		status.ResolverUp = true
		status.Queries = stats.Total
		status.Blocked = stats.Block
		status.CacheHits = stats.CacheHits
		status.CacheMisses = stats.CacheMisses
		status.ChinaUpstreams = china
		status.TrustUpstreams = trust
		if gateway := resolver.Gateway(); gateway.IsValid() {
			status.Gateway = gateway.String()
		}
		for _, sub := range svc.Subscriptions() {
			status.Subscriptions = append(status.Subscriptions, bot.Subscription{
				Name:  sub.RuleID,
				OK:    sub.Error == "",
				Error: sub.Error,
			})
		}
	}
	if e := engineRef.Load(); e != nil {
		if snapshot, err := e.Snapshot(); err == nil {
			status.InterceptionInstalled = true
			status.InterceptionEnabled = snapshot.Enabled
			status.Extensions = len(snapshot.Modules)
			for _, m := range snapshot.Modules {
				if m.Enabled {
					status.EnabledExtensions++
				}
			}
			status.CertificateLoaded = snapshot.Certificate.Loaded
			status.CertificateCovers = snapshot.Certificate.CoveredAll
			status.MissingHosts = snapshot.Certificate.Missing
			if snapshot.Certificate.NotAfter > 0 {
				status.CertificateNotAfter = time.Unix(snapshot.Certificate.NotAfter, 0)
			}
		}
	}
	return status
}

// explainName runs the same name-only decision live resolution runs.
func explainName(name string) (bot.Explanation, error) {
	svc := dnsRef.Load()
	if svc == nil {
		return bot.Explanation{}, errors.New("the resolver is not running")
	}
	decision := svc.Resolver().Decide(name)
	explanation := bot.Explanation{
		Name:    name,
		Verdict: decision.Verdict.Verdict,
		Reason:  decision.Verdict.Reason,
	}
	if decision.Capture != nil {
		explanation.Extension = decision.Capture.ExtensionName
		if !decision.Capture.Ready {
			explanation.Reason = "the extension declares this host, but its interception runtime is not ready"
		}
	}
	return explanation, nil
}

// DNS returns the resolver service, or nil before Start.
func DNS() *dns.Service { return dnsRef.Load() }

// StateDir reports where 5gpn documents live, or "" before Start.
func StateDir() string {
	if p := stateDir.Load(); p != nil {
		return *p
	}
	return ""
}

// StartInterception assembles the plugin engine and installs it as the core's
// capture stage. Calling it with an empty path, or not calling it at all,
// leaves the core routing every connection normally.
//
// Separate from Start because interception is optional and failible in a way
// the rest is not: a malformed interception document, or a certificate whose
// SAN set no longer covers the enabled capture hosts, must leave a working
// gateway rather than refusing to boot. The error is returned for the caller to
// log; it is not fatal.
func StartInterception(configPath string) error {
	// Withdrawing first means every early return below leaves the feature
	// unadvertised. Advertising a subsystem that failed to come up would have
	// the client render a panel over an engine that is not there, which is a
	// worse failure than an absent panel: the operator would read its emptiness
	// as "no extensions enabled".
	api.Advertise("gpn-interception", api.Feature{})
	api.SetInterceptionEngine(nil)
	engineRef.Store(nil)
	tunnel.SetTrafficPolicy(nil)
	tunnel.SetInterceptor(nil)
	dial.SetTrafficPolicy(nil, nil)
	// The resolver must forget the capture table in the same breath. A stale
	// lookup would keep steering hosts the current document no longer names,
	// at a gateway with nothing left to terminate them.
	if svc := dnsRef.Load(); svc != nil {
		svc.Resolver().SetCaptureLookup(nil)
	}

	if configPath == "" {
		return nil
	}
	e, err := engine.New(configPath, StateDir())
	if err != nil {
		// Explicitly clear rather than leave whatever was installed before. A
		// failed reload that silently kept the previous capture set would have
		// the gateway intercepting hosts the current document no longer names.
		return err
	}
	e.SetEgressGroupSource(tunnel.IsEgressProxy, tunnel.EgressProxies)
	e.SetClientBoundarySource(tunnel.ClientPolicyBoundaryReady)
	if svc := dnsRef.Load(); svc != nil {
		e.SetTrafficPolicyChangeCallback(svc.Resolver().FlushCache)
	}
	policy := e.TrafficPolicy()
	dial.SetTrafficPolicy(policy, tunnel.IsEgressProxy)
	tunnel.SetTrafficPolicy(policy)
	tunnel.SetInterceptor(e.Interceptor())
	engineRef.Store(e)
	api.SetInterceptionEngine(e)
	api.Advertise("gpn-interception", api.Feature{Version: 1})
	if svc := dnsRef.Load(); svc != nil {
		svc.Resolver().SetCaptureLookup(func(name string) (dns.Capture, bool) {
			binding, ok := e.CaptureFor(name)
			if !ok {
				return dns.Capture{}, false
			}
			return dns.Capture{
				ExtensionID:   binding.ModuleID,
				ExtensionName: binding.ModuleName,
				Pattern:       binding.Pattern,
				Resolver:      binding.CaptureDNS,
				Ready:         binding.Ready,
			}, true
		})
		svc.Resolver().FlushCache()
	}
	log.Infoln("[GPN] interception engine installed from %s", configPath)
	return nil
}

// Engine returns the installed plugin engine, or nil.
func Engine() *engine.Engine { return engineRef.Load() }

// SetInterceptor installs the capture stage into the core, or removes it with
// nil. Exported here rather than letting callers reach tunnel directly so the
// façade stays the single seam.
func SetInterceptor(i C.Interceptor) { tunnel.SetInterceptor(i) }
