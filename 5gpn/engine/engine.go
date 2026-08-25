package engine

import (
	"fmt"

	C "github.com/metacubex/mihomo/constant"
)

// Engine is the interception subsystem, assembled and ready to be installed
// into the core.
//
// This replaces main.go. What that file did was open a config, build a
// certificate store, a log ring and a proxy, hand them to each other, bind a
// SOCKS listener and then sit in a signal loop until something told it to stop.
// Only the middle third was ever the engine; the rest was being a process. The
// core owns the lifecycle now, so what is left is a constructor and an accessor.
type Engine struct {
	config              *configStore
	certs               *certificateStore
	logs                *engineLogHub
	proxy               *interceptProxy
	interceptor         *Interceptor
	egressGroups        *egressGroupRegistry
	trafficChanged      func()
	clientBoundaryReady func() bool
	workers             *workerController
	// catalogs holds the fetched Marketplace index for a few minutes. Nothing in
	// it is state: it exists so opening the extensions page does not put a
	// request on the publishing host per render.
	catalogs catalogCache
}

// New assembles the engine from the interception document at configPath, using
// stateDir for plugin persistent storage.
//
// It does not start anything. Nothing in here accepts a connection: the engine
// is reached only through the interceptor, which the core consults once it is
// installed. That ordering is deliberate -- an engine that bound a listener in
// its constructor would be serving before the caller had decided it should be.
func New(configPath, stateDir string) (*Engine, error) {
	workers, err := newWorkerController()
	if err != nil {
		return nil, fmt.Errorf("5gpn/engine: extension hard isolation: %w", err)
	}
	config, err := newConfigStore(configPath, workers)
	if err != nil {
		_ = workers.Close()
		return nil, fmt.Errorf("5gpn/engine: load %s: %w", configPath, err)
	}
	certs := newCertificateStore(config)

	// The ring is wired before the proxy exists so that configuration events
	// raised during assembly are not published into nothing. The sidecar had
	// this ordering too, and the reason is unchanged: the first thing an
	// operator looks at after a failed apply is the log that would have
	// explained it.
	logs := newEngineLogHub(engineLogRingCapacity)
	config.setEngineLogPublisher(logs)

	proxy := newInterceptProxy(config, certs, workers, stateDir)
	proxy.setEngineLogPublisher(logs)

	e := &Engine{
		config: config, certs: certs, logs: logs, proxy: proxy, workers: workers,
	}
	proxy.runtimeReady = e.runtimeReadyForHostConfig
	e.interceptor = NewInterceptor(proxy)
	e.interceptor.engine = e
	return e, nil
}

// Close releases pooled transports and logs, then the process-local isolation
// manager. It is idempotent and kills any worker still scoped to this engine
// generation.
func (e *Engine) Close() error {
	if e == nil {
		return nil
	}
	if e.config != nil {
		e.config.setCertificateRequestReconcileCallback(nil)
	}
	if e.proxy != nil {
		e.proxy.closeUpstreamTransports()
	}
	if e.logs != nil {
		e.logs.Close()
	}
	if e.workers != nil {
		return e.workers.Close()
	}
	return nil
}

// SetCertificateRequestReconcileCallback installs the process-owner wakeup for
// the durable interception-certificate request. The callback receives no
// request body: it is only a hint to re-read the latest atomically published
// file, so coalescing several writes cannot make a signer consume stale work.
// Registration immediately wakes once to cover the request published during
// Engine construction.
func (e *Engine) SetCertificateRequestReconcileCallback(callback func()) {
	if e != nil && e.config != nil {
		e.config.setCertificateRequestReconcileCallback(callback)
	}
}

// Interceptor returns the capture stage to install via tunnel.SetInterceptor.
func (e *Engine) Interceptor() C.Interceptor { return e.interceptor }

// SetFatalHandler installs the one process-owner boundary for unexpected Go
// panics that escape the script exception and timeout containment. It is set
// before the interceptor is published and is never changed afterward.
func (e *Engine) SetFatalHandler(handler func(error)) {
	if e != nil && e.proxy != nil {
		e.proxy.fatal = handler
	}
}

// Reload re-reads the interception document.
//
// The document is the operator's, written by the API, and the engine picks up
// changes here rather than through the core's ApplyConfig. Keeping the two
// apart is what stops an unrelated proxy edit from tearing down every captured
// session: mihomo rebuilds listeners and resolvers on reload, and the engine
// must not be rebuilt with them.
func (e *Engine) Reload() error {
	if _, err := e.config.Current(); err != nil {
		return fmt.Errorf("5gpn/engine: reload: %w", err)
	}
	return nil
}

// Logs returns one cursor-addressable page of retained engine and extension log
// events.
//
// The console reads this rather than subscribing: an operator opens the log
// after something went wrong, and a stream that starts at "now" has nothing to
// show them. The hub retains a bounded ring for exactly that case.
func (e *Engine) Logs(query EngineLogQuery) EngineLogPage {
	if e == nil {
		return EngineLogPage{Logs: make([]EngineLog, 0)}
	}
	return e.logs.Snapshot(query)
}
