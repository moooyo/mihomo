// Package gpn is the only 5gpn package the core is allowed to import.
//
// Everything else lives under gpn/ and is reachable only through here. That is
// not tidiness: the fork's cost is measured in edits to upstream-owned files,
// and a façade is what keeps that number from growing one import at a time.
// gpn/importrule_test.go enforces it.
package gpn

import (
	"context"
	"net"
	"sync/atomic"

	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/gpn/api"
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
	engine.SetUpstreamDialer(func(ctx context.Context, host string, port int) (net.Conn, error) {
		return dial.TCP(ctx, host, port)
	})
	engine.SetUpstreamPacketDialer(func(ctx context.Context, host string, port int) (net.PacketConn, error) {
		return dial.UDP(ctx, host, port)
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
	return nil
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
	// The resolver must forget the capture table in the same breath. A stale
	// lookup would keep steering hosts the current document no longer names,
	// at a gateway with nothing left to terminate them.
	if svc := dnsRef.Load(); svc != nil {
		svc.Resolver().SetCaptureLookup(nil)
	}

	if configPath == "" {
		tunnel.SetInterceptor(nil)
		return nil
	}
	e, err := engine.New(configPath, StateDir())
	if err != nil {
		// Explicitly clear rather than leave whatever was installed before. A
		// failed reload that silently kept the previous capture set would have
		// the gateway intercepting hosts the current document no longer names.
		tunnel.SetInterceptor(nil)
		return err
	}
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
