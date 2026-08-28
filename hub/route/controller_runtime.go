package route

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/metacubex/mihomo/adapter/inbound"
	"github.com/metacubex/mihomo/component/ca"
	"github.com/metacubex/mihomo/component/ech"
	"github.com/metacubex/mihomo/component/updater"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/log"
	"github.com/metacubex/mihomo/ntp"

	"github.com/metacubex/http"
	"github.com/metacubex/tls"
)

// Controller runtime bookkeeping is isolated here because it is fork-owned.
// server.go remains the upstream router surface and delegates only the narrow
// lifecycle and managed-distribution decisions that 5gpn adds.

var (
	uiPath = ""

	controllerReconcileMu sync.Mutex
	controllerMu          sync.Mutex
	controllerGeneration  uint64
	currentController     *controllerRuntime
	currentControllerPlan atomic.Pointer[controllerPlan]
	controllerFatal       func(error)
)

type controllerListenerKind uint8

const (
	controllerHTTP controllerListenerKind = iota
	controllerTLS
	controllerUnix
	controllerPipe
)

type controllerListenerSpec struct {
	kind        controllerListenerKind
	network     string
	address     string
	routingMark int
}

type controllerListener struct {
	spec     controllerListenerSpec
	server   *http.Server
	listener net.Listener
	retired  atomic.Bool
}

type controllerRuntime struct {
	generation    uint64
	config        Config
	uiPath        string
	listeners     map[controllerListenerKind]*controllerListener
	fatalReported bool
}

type controllerPlan struct {
	remoteHandler http.Handler
	localHandler  http.Handler
	tlsConfig     *tls.Config
}

type controllerHandler struct {
	local bool
}

const uiContentSecurityPolicy = "default-src 'self'; " +
	"script-src 'self'; " +
	"style-src 'self' 'unsafe-inline'; " +
	"img-src 'self' data: blob: http: https:; " +
	"font-src 'self' data:; " +
	"connect-src 'self' http: https: ws: wss:; " +
	"worker-src 'self'; manifest-src 'self'; " +
	"object-src 'none'; base-uri 'self'; form-action 'self'; " +
	"frame-src 'none'; frame-ancestors 'none'"

const (
	managedControllerReadHeaderTimeout = 15 * time.Second
	managedControllerIdleTimeout       = 90 * time.Second
	managedControllerMaxHeaderBytes    = 64 << 10
)

func (h controllerHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	plan := currentControllerPlan.Load()
	if plan == nil {
		http.Error(w, "controller is not ready", http.StatusServiceUnavailable)
		return
	}
	handler := plan.remoteHandler
	if h.local {
		handler = plan.localHandler
	}
	handler.ServeHTTP(w, r)
}

// ValidateConfig enforces fork-owned controller invariants only for the
// managed 5gpn distribution. Ordinary mihomo builds retain the upstream
// controller surface, including plaintext, DoH, Unix sockets and named pipes.
func ValidateConfig(cfg *Config) error {
	if cfg == nil {
		return fmt.Errorf("controller config is nil")
	}
	if !updater.ManagedDistribution() {
		return nil
	}
	return ValidateManagedConfig(cfg)
}

// ValidateManagedConfig validates the controller boundary required by the
// managed 5gpn distribution without consulting global process state. Local
// one-shot inspectors use the same check before releasing controller facts.
func ValidateManagedConfig(cfg *Config) error {
	if cfg == nil {
		return fmt.Errorf("controller config is nil")
	}
	if strings.TrimSpace(cfg.Secret) == "" {
		return fmt.Errorf("managed 5gpn requires a non-empty controller secret")
	}
	if strings.IndexFunc(cfg.Secret, func(r rune) bool { return r <= 0x1f || r == 0x7f }) >= 0 {
		return fmt.Errorf("managed 5gpn controller secret contains a forbidden control character")
	}
	if cfg.Addr != "" {
		return fmt.Errorf("managed 5gpn forbids the plaintext external controller")
	}
	if cfg.TLSAddr != "127.0.0.1:443" {
		return fmt.Errorf("managed 5gpn requires external-controller-tls 127.0.0.1:443")
	}
	if cfg.RoutingMark != 0 {
		return fmt.Errorf("managed 5gpn forbids external-controller-routing-mark")
	}
	if strings.TrimSpace(cfg.Certificate) == "" || strings.TrimSpace(cfg.PrivateKey) == "" {
		return fmt.Errorf("managed 5gpn requires the controller TLS certificate and private key")
	}
	if cfg.ClientAuthType != "" {
		return fmt.Errorf("managed 5gpn forbids tls.client-auth-type")
	}
	if cfg.ClientAuthCert != "" {
		return fmt.Errorf("managed 5gpn forbids tls.client-auth-cert")
	}
	if cfg.EchKey != "" {
		return fmt.Errorf("managed 5gpn forbids controller TLS ECH")
	}
	if cfg.DohServer != "" {
		return fmt.Errorf("managed 5gpn forbids an external DoH route")
	}
	if cfg.UnixAddr != "" {
		return fmt.Errorf("managed 5gpn forbids an external controller Unix socket")
	}
	if cfg.PipeAddr != "" {
		return fmt.Errorf("managed 5gpn forbids an external controller named pipe")
	}
	return nil
}

// PreflightManagedController performs every managed controller check that can
// fail before listener staging. It resolves the UI path and loads the TLS key
// pair without binding a socket, so fivegpn.Start can retain its mandatory
// worker-isolation-before-listener ordering without a later controller failure
// leaving DoT briefly live on its own.
func PreflightManagedController(cfg *Config, externalUI string) error {
	if err := ValidateManagedConfig(cfg); err != nil {
		return err
	}
	if _, err := resolveControllerUI(externalUI); err != nil {
		return fmt.Errorf("validate managed external-ui: %w", err)
	}
	if err := ca.ValidateTLSKeyPair(cfg.Certificate, cfg.PrivateKey); err != nil {
		return fmt.Errorf("prepare external controller TLS certificate: %w", err)
	}
	return nil
}

// ErrControllerRestartRequired identifies a valid controller change that
// cannot be committed by PUT /configs. Listener topology cannot change without
// closing the carrying connection, and a managed secret rotation must terminate
// every connection authenticated by the previous credential.
var ErrControllerRestartRequired = errors.New("controller configuration change requires a process restart")

func validateManagedControllerRestartTransition(previous *controllerRuntime, next Config, resolvedUI string) error {
	if previous == nil || !updater.ManagedDistribution() {
		return nil
	}
	if previous.config.Secret != next.Secret {
		return fmt.Errorf("%w: managed controller secret changes require a process restart", ErrControllerRestartRequired)
	}
	if previous.config.Certificate != next.Certificate || previous.config.PrivateKey != next.PrivateKey {
		return fmt.Errorf("%w: managed controller certificate and private-key changes require a process restart", ErrControllerRestartRequired)
	}
	if previous.uiPath != resolvedUI {
		return fmt.Errorf("%w: managed external-ui changes require a process restart", ErrControllerRestartRequired)
	}
	return nil
}

// SetControllerFatalHandler installs the process-owner seam for a critical
// controller listener ending. Production supplies the same fatal callback used
// by the other 5gpn critical listeners; tests can inject a recorder without
// terminating their process.
func SetControllerFatalHandler(handler func(error)) {
	controllerMu.Lock()
	controllerFatal = handler
	controllerMu.Unlock()
}

// ReCreateServer prepares every candidate route, certificate and new listener
// synchronously. Nothing is published and no old listener is closed unless all
// preparation succeeds. Publication is one plan swap, after which retired
// listeners are intentionally closed and can no longer become current again.
func ReCreateServer(cfg *Config, externalUI string) error {
	return reconcileController(cfg, externalUI, true)
}

// ReconcileHotServer applies the controller fields that can change on existing
// listeners. Address, transport, routing-mark, and managed secret changes are
// explicitly rejected so PUT /configs never drops its own connection, claims a
// configuration that is not live, or leaves sessions authenticated by a
// retired managed credential. Other plan changes govern every new HTTP request
// and TLS handshake; already authenticated WebSockets and existing TLS
// connections finish in their original connection generation.
func ReconcileHotServer(cfg *Config, externalUI string) error {
	return reconcileController(cfg, externalUI, false)
}

func reconcileHotDebugRoute(debug bool) error {
	controllerMu.Lock()
	current := currentController
	if current == nil {
		controllerMu.Unlock()
		return fmt.Errorf("%w: no live controller generation is available", ErrControllerRestartRequired)
	}
	cfg := cloneControllerConfig(&current.config)
	externalUI := current.uiPath
	controllerMu.Unlock()
	cfg.IsDebug = debug
	return ReconcileHotServer(&cfg, externalUI)
}

func reconcileController(cfg *Config, externalUI string, allowListenerChanges bool) error {
	controllerReconcileMu.Lock()
	defer controllerReconcileMu.Unlock()

	if err := ValidateConfig(cfg); err != nil {
		return err
	}
	snapshot := cloneControllerConfig(cfg)
	resolvedUI, err := resolveControllerUI(externalUI)
	if err != nil {
		return err
	}
	specs, err := controllerListenerSpecs(&snapshot)
	if err != nil {
		return err
	}

	controllerMu.Lock()
	previous := currentController
	previousFailed := previous != nil && previous.fatalReported
	controllerMu.Unlock()
	if previousFailed {
		return errors.New("current controller has failed")
	}
	if err := validateManagedControllerRestartTransition(previous, snapshot, resolvedUI); err != nil {
		return err
	}
	if previous != nil && previous.uiPath == resolvedUI && sameControllerConfig(previous.config, snapshot) {
		return nil
	}
	if !allowListenerChanges {
		if previous == nil {
			return fmt.Errorf("%w: no live controller generation is available", ErrControllerRestartRequired)
		}
		if !sameControllerListeners(previous.listeners, specs) {
			return fmt.Errorf("%w: external-controller, external-controller-tls, external-controller-unix, external-controller-pipe and external-controller-routing-mark are startup fields", ErrControllerRestartRequired)
		}
	}

	nextListeners := make(map[controllerListenerKind]*controllerListener, len(specs))
	staged := make([]*controllerListener, 0, len(specs))
	for kind, spec := range specs {
		if previous != nil {
			if live := previous.listeners[kind]; live != nil && live.spec == spec {
				nextListeners[kind] = live
				continue
			}
		}
		listener, listenErr := stageControllerListener(spec)
		if listenErr != nil {
			closeStagedControllerListeners(staged)
			return fmt.Errorf("prepare %s listener %q while keeping the current controller live: %w", controllerListenerName(kind), spec.address, listenErr)
		}
		nextListeners[kind] = listener
		staged = append(staged, listener)
	}
	plan, err := prepareControllerPlan(&snapshot, resolvedUI)
	if err != nil {
		closeStagedControllerListeners(staged)
		return err
	}

	controllerMu.Lock()
	if currentController != previous {
		controllerMu.Unlock()
		closeStagedControllerListeners(staged)
		return errors.New("controller changed during reconcile")
	}
	if previous != nil && previous.fatalReported {
		controllerMu.Unlock()
		closeStagedControllerListeners(staged)
		return errors.New("current controller failed during reconcile")
	}
	controllerGeneration++
	next := &controllerRuntime{
		generation: controllerGeneration,
		config:     snapshot,
		uiPath:     resolvedUI,
		listeners:  nextListeners,
	}
	retired := make([]*controllerListener, 0, len(nextListeners))
	if previous != nil {
		for kind, listener := range previous.listeners {
			if nextListeners[kind] != listener {
				listener.retired.Store(true)
				retired = append(retired, listener)
			}
		}
	}
	currentControllerPlan.Store(plan)
	currentController = next
	uiPath = resolvedUI
	controllerMu.Unlock()

	for _, listener := range staged {
		go serveController(listener)
	}
	for _, listener := range retired {
		closeControllerListener(listener)
	}
	return nil
}

func cloneControllerConfig(cfg *Config) Config {
	snapshot := *cfg
	snapshot.Cors.AllowOrigins = append([]string(nil), cfg.Cors.AllowOrigins...)
	return snapshot
}

func sameControllerConfig(a, b Config) bool {
	return a.Addr == b.Addr &&
		a.TLSAddr == b.TLSAddr &&
		a.UnixAddr == b.UnixAddr &&
		a.PipeAddr == b.PipeAddr &&
		a.RoutingMark == b.RoutingMark &&
		a.Secret == b.Secret &&
		a.Certificate == b.Certificate &&
		a.PrivateKey == b.PrivateKey &&
		a.ClientAuthType == b.ClientAuthType &&
		a.ClientAuthCert == b.ClientAuthCert &&
		a.EchKey == b.EchKey &&
		a.DohServer == b.DohServer &&
		a.IsDebug == b.IsDebug &&
		a.Cors.AllowPrivateNetwork == b.Cors.AllowPrivateNetwork &&
		slices.Equal(a.Cors.AllowOrigins, b.Cors.AllowOrigins)
}

func resolveControllerUI(externalUI string) (string, error) {
	if externalUI == "" {
		return "", nil
	}
	if !C.Path.IsSafePath(externalUI) {
		return "", C.Path.ErrNotSafePath(externalUI)
	}
	return C.Path.Resolve(externalUI), nil
}

func controllerListenerSpecs(cfg *Config) (map[controllerListenerKind]controllerListenerSpec, error) {
	specs := make(map[controllerListenerKind]controllerListenerSpec, 4)
	if cfg.Addr != "" {
		specs[controllerHTTP] = controllerListenerSpec{kind: controllerHTTP, network: "tcp", address: cfg.Addr, routingMark: cfg.RoutingMark}
	}
	if cfg.TLSAddr != "" {
		specs[controllerTLS] = controllerListenerSpec{kind: controllerTLS, network: "tcp", address: cfg.TLSAddr, routingMark: cfg.RoutingMark}
	}
	if cfg.UnixAddr != "" {
		specs[controllerUnix] = controllerListenerSpec{kind: controllerUnix, network: "unix", address: C.Path.Resolve(cfg.UnixAddr)}
	}
	if cfg.PipeAddr != "" {
		if !inbound.SupportNamedPipe {
			return nil, fmt.Errorf("external controller named pipes are unsupported on this platform")
		}
		if !strings.HasPrefix(cfg.PipeAddr, `\\.\pipe\`) {
			return nil, fmt.Errorf("windows named pipe must start with %q", `\\.\pipe\`)
		}
		specs[controllerPipe] = controllerListenerSpec{kind: controllerPipe, network: "pipe", address: cfg.PipeAddr}
	}
	return specs, nil
}

func sameControllerListeners(live map[controllerListenerKind]*controllerListener, candidate map[controllerListenerKind]controllerListenerSpec) bool {
	if len(live) != len(candidate) {
		return false
	}
	for kind, spec := range candidate {
		listener := live[kind]
		if listener == nil || listener.spec != spec {
			return false
		}
	}
	return true
}

func prepareControllerPlan(cfg *Config, resolvedUI string) (*controllerPlan, error) {
	plan := &controllerPlan{
		remoteHandler: routerWithUI(cfg.IsDebug, cfg.Secret, cfg.DohServer, cfg.Cors, resolvedUI),
		localHandler:  routerWithUI(cfg.IsDebug, "", cfg.DohServer, cfg.Cors, resolvedUI),
	}
	if cfg.TLSAddr == "" {
		return plan, nil
	}
	tlsConfig, err := prepareControllerTLS(cfg)
	if err != nil {
		return nil, err
	}
	plan.tlsConfig = tlsConfig
	return plan, nil
}

func prepareControllerTLS(cfg *Config) (*tls.Config, error) {
	certLoader, err := ca.NewTLSKeyPairLoader(cfg.Certificate, cfg.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("prepare external controller TLS certificate: %w", err)
	}
	tlsConfig := &tls.Config{
		Time:       ntp.Now,
		NextProtos: []string{"h2", "http/1.1"},
		GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
			return certLoader()
		},
	}
	tlsConfig.ClientAuth = ca.ClientAuthTypeFromString(cfg.ClientAuthType)
	if cfg.ClientAuthCert != "" && tlsConfig.ClientAuth == tls.NoClientCert {
		tlsConfig.ClientAuth = tls.RequireAndVerifyClientCert
	}
	if tlsConfig.ClientAuth == tls.VerifyClientCertIfGiven || tlsConfig.ClientAuth == tls.RequireAndVerifyClientCert {
		pool, loadErr := ca.LoadCertificates(cfg.ClientAuthCert)
		if loadErr != nil {
			return nil, fmt.Errorf("prepare external controller TLS client CA: %w", loadErr)
		}
		tlsConfig.ClientCAs = pool
	}
	if cfg.EchKey != "" {
		if loadErr := ech.LoadECHKey(cfg.EchKey, tlsConfig); loadErr != nil {
			return nil, fmt.Errorf("prepare external controller TLS ECH key: %w", loadErr)
		}
	}
	return tlsConfig, nil
}

func stageControllerListener(spec controllerListenerSpec) (*controllerListener, error) {
	server := newControllerServer(spec.kind == controllerUnix || spec.kind == controllerPipe)
	var listener net.Listener
	var err error
	switch spec.kind {
	case controllerHTTP, controllerTLS:
		lc := inbound.NewListenConfig()
		lc.SetRouteMark(spec.routingMark)
		listener, err = lc.Listen(context.Background(), "tcp", spec.address)
	case controllerUnix:
		if err = os.MkdirAll(filepath.Dir(spec.address), 0o755); err == nil {
			_ = syscall.Unlink(spec.address)
			lc := inbound.NewListenConfig()
			lc.SetRouteMark(0)
			listener, err = lc.Listen(context.Background(), "unix", spec.address)
			if err == nil {
				err = os.Chmod(spec.address, 0o666)
			}
		}
	case controllerPipe:
		listener, err = inbound.ListenNamedPipe(spec.address)
	default:
		err = errors.New("unknown controller listener kind")
	}
	if err != nil {
		if listener != nil {
			_ = listener.Close()
		}
		if spec.kind == controllerUnix {
			_ = syscall.Unlink(spec.address)
		}
		return nil, err
	}
	if spec.kind == controllerTLS {
		dynamicTLS := &tls.Config{
			Time:       ntp.Now,
			NextProtos: []string{"h2", "http/1.1"},
			GetConfigForClient: func(*tls.ClientHelloInfo) (*tls.Config, error) {
				plan := currentControllerPlan.Load()
				if plan == nil || plan.tlsConfig == nil {
					return nil, errors.New("controller TLS configuration is not ready")
				}
				return plan.tlsConfig, nil
			},
		}
		listener = tls.NewListener(listener, dynamicTLS)
	}
	return &controllerListener{spec: spec, server: server, listener: listener}, nil
}

func newControllerServer(local bool) *http.Server {
	server := &http.Server{Handler: controllerHandler{local: local}}
	if updater.ManagedDistribution() {
		// Bound work before authentication without imposing whole-request limits
		// on configuration uploads, streaming endpoints, or hijacked WebSockets.
		server.ReadHeaderTimeout = managedControllerReadHeaderTimeout
		server.IdleTimeout = managedControllerIdleTimeout
		server.MaxHeaderBytes = managedControllerMaxHeaderBytes
	}
	return server
}

func closeStagedControllerListeners(listeners []*controllerListener) {
	for _, listener := range listeners {
		_ = listener.listener.Close()
		if listener.spec.kind == controllerUnix {
			_ = syscall.Unlink(listener.spec.address)
		}
	}
}

func closeControllerListener(listener *controllerListener) {
	_ = listener.server.Close()
	_ = listener.listener.Close()
	if listener.spec.kind == controllerUnix {
		_ = syscall.Unlink(listener.spec.address)
	}
}

func serveController(listener *controllerListener) {
	log.Infoln("%s listening at: %s", controllerListenerName(listener.spec.kind), listener.listener.Addr().String())
	err := listener.server.Serve(listener.listener)
	if err == nil {
		err = errors.New("Serve returned without an error")
	}
	failure := fmt.Errorf("%s stopped unexpectedly: %w", controllerListenerName(listener.spec.kind), err)

	controllerMu.Lock()
	active := currentController != nil && currentController.listeners[listener.spec.kind] == listener && !listener.retired.Load()
	fatal := controllerFatal
	if active && currentController.fatalReported {
		active = false
	}
	if active {
		currentController.fatalReported = true
	}
	controllerMu.Unlock()
	if !active {
		return
	}
	if fatal != nil {
		fatal(failure)
		return
	}
	if updater.ManagedDistribution() {
		panic(failure)
	}
	log.Errorln("%v", failure)
}

func controllerListenerName(kind controllerListenerKind) string {
	switch kind {
	case controllerHTTP:
		return "external controller"
	case controllerTLS:
		return "external controller TLS"
	case controllerUnix:
		return "external controller Unix"
	case controllerPipe:
		return "external controller pipe"
	default:
		return "external controller"
	}
}

func controllerUIPath() string {
	controllerMu.Lock()
	defer controllerMu.Unlock()
	return uiPath
}

type controllerRouterMode struct {
	publicDebug        bool
	authenticate       bool
	authenticatedDebug bool
	mountDoH           bool
}

func controllerModeForRouter(isDebug bool, secret, dohServer string) controllerRouterMode {
	managed := updater.ManagedDistribution()
	return controllerRouterMode{
		publicDebug:        isDebug && !managed,
		authenticate:       managed || secret != "",
		authenticatedDebug: isDebug && managed,
		mountDoH:           !managed && strings.HasPrefix(dohServer, "/"),
	}
}

func uiSecurityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if updater.ManagedDistribution() {
			w.Header().Set("Content-Security-Policy", uiContentSecurityPolicy)
			w.Header().Set("X-Content-Type-Options", "nosniff")
			w.Header().Set("Referrer-Policy", "no-referrer")
			w.Header().Set("Permissions-Policy", "camera=(), microphone=(), geolocation=(self), payment=(), usb=()")
			w.Header().Set("Cache-Control", "no-store")
		}
		next.ServeHTTP(w, r)
	})
}
