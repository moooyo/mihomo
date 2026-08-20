// Package fivegpn is the only 5gpn package the core is allowed to import.
//
// Everything else lives under 5gpn/ and is reachable only through here. That is
// not tidiness: the fork's cost is measured in edits to upstream-owned files,
// and a façade is what keeps that number from growing one import at a time.
// 5gpn/importrule_test.go enforces it.
package fivegpn

import (
	"context"
	"errors"
	"fmt"
	"net"
	"path/filepath"
	"sync/atomic"
	"time"

	"github.com/metacubex/mihomo/5gpn/api"
	"github.com/metacubex/mihomo/5gpn/bot"
	"github.com/metacubex/mihomo/5gpn/dial"
	"github.com/metacubex/mihomo/5gpn/dns"
	"github.com/metacubex/mihomo/5gpn/engine"
	"github.com/metacubex/mihomo/5gpn/location"
	"github.com/metacubex/mihomo/5gpn/netguard"
	"github.com/metacubex/mihomo/5gpn/state"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/log"
	"github.com/metacubex/mihomo/tunnel"
)

var (
	stateDir       atomic.Pointer[string]
	engineRef      atomic.Pointer[engine.Engine]
	dnsRef         atomic.Pointer[dns.Service]
	botRef         atomic.Pointer[bot.Service]
	certManagerRef atomic.Pointer[certificateManager]
	installed      atomic.Bool
)

const (
	capabilityCoreKey         = "5gpn-core"
	capabilityDNSKey          = "5gpn-dns"
	capabilityInterceptionKey = "5gpn-interception"
	capabilityBotKey          = "5gpn-bot"
	capabilityDNSVersion      = 2

	// The interception capability version is the review contract. Keeping one
	// exported engine constant prevents the advertised API and confirmation
	// writes from advancing independently.
	capabilityInterceptionVersion = engine.ReviewContractVersion
)

// Start prepares the 5gpn subsystems and installs them into the core.
//
// It runs once, after the core has a home directory and before any listener
// accepts. Everything it installs is idempotent, because a config reload must
// not tear down the interception engine: mihomo's ApplyConfig rebuilds
// listeners, resolvers and the rule tree on every reload, and an engine that
// came and went with it would drop every captured session whenever an operator
// changed an unrelated proxy.
func Start(home string, onFatal func(error)) error {
	if onFatal == nil {
		return errors.New("5gpn: a fatal error handler is required")
	}
	if err := configureDeploymentRuntime(); err != nil {
		return err
	}
	// A successful rename followed by a failed directory fsync leaves disk and
	// the immutable in-memory revision unable to agree on what crash recovery
	// will retain. That is an unrecoverable monolith invariant, so state reports
	// it at the same process-owner boundary as a critical listener ending.
	state.SetCommitAmbiguousHandler(onFatal)
	dir, err := state.Dir(home)
	if err != nil {
		return err
	}
	stateDir.Store(&dir)
	// The upstream tunnel cannot import product subpackages. Publish the one
	// audited address-scope predicate before any engine egress seam is wired.
	tunnel.SetExtensionEgressAddressPolicy(netguard.IsPubliclyRoutable)

	// The engine cannot open a socket of its own. Its egress seam is pointed at
	// mihomo's own inner dialer so an intercepted upstream obeys exactly the
	// rules an ordinary connection would, and shows up in the same connection
	// table.
	engine.SetUpstreamAuthorizer(func(network C.NetWork, host string, port int, owner string, ownerOnly bool) (string, error) {
		return dial.Authorize(network, host, port, owner, ownerOnly)
	})
	engine.SetUpstreamDialer(func(ctx context.Context, host string, port int, owner string, ownerOnly bool) (net.Conn, error) {
		return dial.TCP(ctx, host, port, owner, ownerOnly)
	})
	api.Advertise(capabilityCoreKey, api.Feature{Version: 1})
	api.SetLocationSearcher(location.New(func(ctx context.Context, host string, port int) (net.Conn, error) {
		return dial.SystemTCP(ctx, host, port)
	}))
	log.Infoln("[5GPN] state directory %s", dir)

	// The resolver comes up here rather than in StartInterception because it is
	// not optional: it is the reason a client points at this box at all. A
	// document it cannot parse is fatal, since starting with an empty policy
	// would resolve names the operator meant to block and steer nothing they
	// meant to steer.
	svc, err := dns.Open(dir, dns.WithFatalHandler(onFatal), dns.WithRequiredListeners())
	if err != nil {
		return err
	}
	dnsRef.Store(svc)
	// The gateway is installation-owned DNS state. Publish its current startup
	// projection to the narrow managed-egress guard before any listener opens;
	// a checked host reconfigure takes effect on the next process start without
	// rewriting the operator-owned mihomo rule list.
	tunnel.SetManagedGatewaySource(svc.Resolver().Gateway)
	tunnel.SetEgressProxyUpdateCallback(func() {
		svc.Resolver().FlushCache()
		if e := engineRef.Load(); e != nil {
			e.InvalidateEgressTransports()
		}
	})
	tunnel.SetClientBoundaryUpdateCallback(svc.Resolver().FlushCache)
	api.SetDNSService(svc)
	api.Advertise(capabilityDNSKey, api.Feature{Version: capabilityDNSVersion})

	// Extension fetches resolve through the gateway's own trust group. Using
	// the host resolver instead would let the box's /etc/resolv.conf decide
	// where an operator's plugin code comes from, and on a gateway that is
	// frequently pointed back at this very process.
	engine.SetImporter(engine.NewImporter(func(ctx context.Context, host string) ([]string, error) {
		return svc.Resolver().OriginResolve(ctx, host)
	}))

	// Build and publish the interception plan before the public resolver accepts
	// a query. A valid document with no ready certificate still installs a
	// pending lookup, so DNS keeps a claimed host on the gateway while the client
	// boundary rejects it. A missing plan is different: opening DoT with a nil
	// lookup creates a startup window in which a capture host can be answered as
	// ordinary direct traffic.
	interceptPath := filepath.Join(dir, "intercept.json")
	if err := startInterceptionBeforeDNS(
		func() error { return engine.EnsureDocument(interceptPath) },
		func() error {
			if err := StartInterception(interceptPath, onFatal); err != nil {
				return err
			}
			if !ContainerMode() {
				return nil
			}
			manager, err := newContainerCertificateManager(onFatal)
			if err != nil {
				return err
			}
			current := engineRef.Load()
			if current == nil {
				_ = manager.Close()
				return errors.New("5gpn: interception engine disappeared before container certificate manager startup")
			}
			certManagerRef.Store(manager)
			current.SetCertificateRequestReconcileCallback(manager.NotifyIntercept)
			if err := manager.Start(); err != nil {
				current.SetCertificateRequestReconcileCallback(nil)
				certManagerRef.CompareAndSwap(manager, nil)
				_ = manager.Close()
				return err
			}
			log.Infoln("[5GPN] container certificate manager started")
			return nil
		},
		svc.Listen,
	); err != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		_ = Shutdown(ctx)
		cancel()
		return err
	}

	// The bot comes up last because it reports on everything above it. Its
	// failures are warnings for the same reason interception's are: a gateway
	// that cannot read its bot document should still resolve and forward.
	if err := startBot(filepath.Join(dir, "bot.json")); err != nil {
		log.Warnln("[5GPN] Telegram bot not installed: %v", err)
	}
	installed.Store(true)
	return nil
}

// Shutdown waits for each owned goroutine or child process. It is idempotent:
// process signals, a fatal event, and a restart request all converge here.
//
// The traffic hooks deliberately remain installed until process exit. Shutdown
// releases owned goroutines and workers without publishing an empty interceptor
// or policy that could create a fail-open window.
func Shutdown(ctx context.Context) error {
	installed.Store(false)

	var shutdownErr error
	if manager := certManagerRef.Swap(nil); manager != nil {
		shutdownErr = errors.Join(shutdownErr, manager.Close())
	}
	if service := botRef.Swap(nil); service != nil {
		service.Shutdown()
	}
	if service := dnsRef.Swap(nil); service != nil {
		service.Shutdown(ctx)
	}
	if current := engineRef.Swap(nil); current != nil {
		shutdownErr = errors.Join(shutdownErr, current.Close())
	}
	return shutdownErr
}

// startInterceptionBeforeDNS makes the startup ordering executable rather than
// a comment. ensure and install must both complete before listen can expose
// DoT; any failure prevents the public resolver from opening.
func startInterceptionBeforeDNS(ensure, install, listen func() error) error {
	if err := ensure(); err != nil {
		return fmt.Errorf("5gpn: prepare interception document: %w", err)
	}
	if err := install(); err != nil {
		return fmt.Errorf("5gpn: install interception plan: %w", err)
	}
	// Binding is part of the required DNS boundary. Continuing with any socket
	// absent would leave systemd reporting a healthy gateway with no resolver.
	if err := listen(); err != nil {
		return fmt.Errorf("5gpn: start DNS listeners: %w", err)
	}
	return nil
}

// startBot opens the bot document and starts the poll loop if it is enabled.
//
// The Facts it is given are the whole of what a chat command can reach. They
// are assembled here rather than in 5gpn/bot because the bot package must not
// import the resolver or the engine: what it cannot reach, no command added
// later can reach either.
func startBot(configPath string) error {
	api.Advertise(capabilityBotKey, api.Feature{})
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
	api.Advertise(capabilityBotKey, api.Feature{Version: 1})
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

func advertiseInterceptionCapability(available bool) {
	if !available {
		api.Advertise(capabilityInterceptionKey, api.Feature{})
		return
	}
	api.Advertise(capabilityInterceptionKey, api.Feature{Version: capabilityInterceptionVersion})
}

// StartInterception assembles the plugin engine and installs it as the core's
// capture stage. Calling it with an empty path, or not calling it at all,
// leaves the core routing every connection normally.
//
// Separate from Start so a management transaction can rebuild the plan without
// rebuilding the resolver. Initial startup treats a document that cannot build
// either an active or pending plan as fatal and never opens DoT; ordinary
// certificate and egress unavailability are represented inside a valid pending
// plan and do not prevent startup.
func StartInterception(configPath string, onFatal func(error)) error {
	// Withdrawing first means every early return below leaves the feature
	// unadvertised. Advertising a subsystem that failed to come up would have
	// the client render a panel over an engine that is not there, which is a
	// worse failure than an absent panel: the operator would read its emptiness
	// as "no extensions enabled".
	advertiseInterceptionCapability(false)
	api.SetInterceptionEngine(nil)
	previousEngine := engineRef.Swap(nil)
	if previousEngine != nil {
		_ = previousEngine.Close()
	}
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
	e.SetFatalHandler(onFatal)
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
	advertiseInterceptionCapability(true)
	if svc := dnsRef.Load(); svc != nil {
		svc.Resolver().SetCaptureLookup(func(name string) (dns.Capture, bool) {
			binding, ok := e.CaptureFor(name)
			if !ok {
				return dns.Capture{}, false
			}
			return captureBindingForDNS(binding), true
		})
		svc.Resolver().FlushCache()
	}
	log.Infoln("[5GPN] interception engine installed from %s", configPath)
	return nil
}

func captureBindingForDNS(binding engine.CaptureBinding) dns.Capture {
	return dns.Capture{
		ExtensionID:   binding.ModuleID,
		ExtensionName: binding.ModuleName,
		Pattern:       binding.Pattern,
		Resolver:      binding.CaptureDNS,
		Ready:         binding.Ready,
		Claimed:       binding.Claimed,
	}
}

// Engine returns the installed plugin engine, or nil.
func Engine() *engine.Engine { return engineRef.Load() }

// SetInterceptor installs the capture stage into the core, or removes it with
// nil. Exported here rather than letting callers reach tunnel directly so the
// façade stays the single seam.
func SetInterceptor(i C.Interceptor) { tunnel.SetInterceptor(i) }

// ExtensionWorkerMain enters the hidden one-shot extension worker. The root
// facade is the only product package main.go imports, preserving the fork's
// import boundary.
func ExtensionWorkerMain(args []string) int { return engine.ExtensionWorkerMain(args) }

// ExtensionWorkerCommand returns the exact hidden argv[1] marker. It is a
// function rather than a duplicated literal so parent and child cannot drift.
func ExtensionWorkerCommand() string { return engine.ExtensionWorkerCommand }
