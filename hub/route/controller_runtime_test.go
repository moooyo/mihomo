package route

import (
	"bytes"
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/metacubex/mihomo/component/ca"
	"github.com/metacubex/mihomo/component/updater"
	C "github.com/metacubex/mihomo/constant"
	listenerpkg "github.com/metacubex/mihomo/listener"

	"github.com/metacubex/http"
	"github.com/metacubex/http/httptest"
)

func TestManagedDebugRouteSharesControllerAuthentication(t *testing.T) {
	previousManaged := updater.ManagedDistribution()
	t.Cleanup(func() { updater.SetManagedDistribution(previousManaged) })

	updater.SetManagedDistribution(true)
	managed := router(true, "controller-secret", "/dns-query", Cors{})
	if response := requestRoute(managed, http.MethodPut, "/debug/gc", ""); response.Code != http.StatusUnauthorized {
		t.Fatalf("managed debug route without auth status %d, want %d", response.Code, http.StatusUnauthorized)
	}
	if response := requestRoute(managed, http.MethodPut, "/debug/gc", "controller-secret"); response.Code != http.StatusOK {
		t.Fatalf("managed debug route with auth status %d, want %d", response.Code, http.StatusOK)
	}
	if response := requestRoute(managed, http.MethodPost, "/dns-query", "controller-secret"); response.Code != http.StatusNotFound {
		t.Fatalf("managed router exposed DoH with status %d", response.Code)
	}

	// The upstream distribution retains its historical anonymous debug route.
	updater.SetManagedDistribution(false)
	upstream := router(true, "controller-secret", "", Cors{})
	if response := requestRoute(upstream, http.MethodPut, "/debug/gc", ""); response.Code != http.StatusOK {
		t.Fatalf("upstream debug route status %d, want %d", response.Code, http.StatusOK)
	}
}

func TestManagedControllerConfigFailsClosed(t *testing.T) {
	previousManaged := updater.ManagedDistribution()
	t.Cleanup(func() { updater.SetManagedDistribution(previousManaged) })
	updater.SetManagedDistribution(true)

	valid := Config{
		TLSAddr:     "127.0.0.1:443",
		Secret:      "controller-secret",
		Certificate: "/etc/5gpn/cert.pem",
		PrivateKey:  "/etc/5gpn/key.pem",
	}
	if err := ValidateConfig(&valid); err != nil {
		t.Fatalf("valid managed config rejected: %v", err)
	}

	tests := []struct {
		name   string
		mutate func(*Config)
	}{
		{name: "empty secret", mutate: func(cfg *Config) { cfg.Secret = "" }},
		{name: "NUL in secret", mutate: func(cfg *Config) { cfg.Secret = "before\x00after" }},
		{name: "unit separator in secret", mutate: func(cfg *Config) { cfg.Secret = "before\x1fafter" }},
		{name: "DEL in secret", mutate: func(cfg *Config) { cfg.Secret = "before\x7fafter" }},
		{name: "plaintext controller", mutate: func(cfg *Config) { cfg.Addr = "127.0.0.1:9090" }},
		{name: "missing TLS controller", mutate: func(cfg *Config) { cfg.TLSAddr = "" }},
		{name: "wrong TLS controller", mutate: func(cfg *Config) { cfg.TLSAddr = "127.0.0.1:9090" }},
		{name: "routing mark", mutate: func(cfg *Config) { cfg.RoutingMark = 1 }},
		{name: "missing certificate", mutate: func(cfg *Config) { cfg.Certificate = "" }},
		{name: "TLS client auth type", mutate: func(cfg *Config) { cfg.ClientAuthType = "require-and-verify-client-cert" }},
		{name: "whitespace TLS client auth type", mutate: func(cfg *Config) { cfg.ClientAuthType = " " }},
		{name: "TLS client auth certificate", mutate: func(cfg *Config) { cfg.ClientAuthCert = "/etc/5gpn/client-ca.pem" }},
		{name: "whitespace TLS client auth certificate", mutate: func(cfg *Config) { cfg.ClientAuthCert = " " }},
		{name: "TLS ECH", mutate: func(cfg *Config) { cfg.EchKey = "/etc/5gpn/ech.pem" }},
		{name: "whitespace TLS ECH", mutate: func(cfg *Config) { cfg.EchKey = " " }},
		{name: "DoH", mutate: func(cfg *Config) { cfg.DohServer = "/dns-query" }},
		{name: "Unix socket", mutate: func(cfg *Config) { cfg.UnixAddr = "mihomo.sock" }},
		{name: "named pipe", mutate: func(cfg *Config) { cfg.PipeAddr = `\\.\pipe\mihomo` }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			cfg := valid
			test.mutate(&cfg)
			if err := ValidateConfig(&cfg); err == nil {
				t.Fatal("invalid managed controller config was accepted")
			}
		})
	}
	unicodeSecret := valid
	unicodeSecret.Secret = "控制器🔐"
	if err := ValidateConfig(&unicodeSecret); err != nil {
		t.Fatalf("ordinary Unicode managed secret was rejected: %v", err)
	}

	updater.SetManagedDistribution(false)
	upstream := valid
	upstream.Secret = "upstream\x00secret"
	upstream.Addr = "0.0.0.0:9090"
	upstream.TLSAddr = ""
	upstream.Certificate = ""
	upstream.PrivateKey = ""
	upstream.RoutingMark = 99
	upstream.ClientAuthType = "require-and-verify-client-cert"
	upstream.ClientAuthCert = "/etc/mihomo/client-ca.pem"
	upstream.EchKey = "/etc/mihomo/ech.pem"
	upstream.DohServer = "/dns-query"
	upstream.UnixAddr = "mihomo.sock"
	if err := ValidateConfig(&upstream); err != nil {
		t.Fatalf("upstream controller behavior was restricted: %v", err)
	}
}

func TestManagedControllerServerBoundsOnlyHeadersAndIdleConnections(t *testing.T) {
	previousManaged := updater.ManagedDistribution()
	t.Cleanup(func() { updater.SetManagedDistribution(previousManaged) })

	updater.SetManagedDistribution(true)
	managed := newControllerServer(false)
	if managed.ReadHeaderTimeout != managedControllerReadHeaderTimeout {
		t.Fatalf("managed ReadHeaderTimeout = %s, want %s", managed.ReadHeaderTimeout, managedControllerReadHeaderTimeout)
	}
	if managed.IdleTimeout != managedControllerIdleTimeout {
		t.Fatalf("managed IdleTimeout = %s, want %s", managed.IdleTimeout, managedControllerIdleTimeout)
	}
	if managed.MaxHeaderBytes != managedControllerMaxHeaderBytes {
		t.Fatalf("managed MaxHeaderBytes = %d, want %d", managed.MaxHeaderBytes, managedControllerMaxHeaderBytes)
	}
	if managed.ReadTimeout != 0 || managed.WriteTimeout != 0 {
		t.Fatalf("managed whole-request timeouts = (%s, %s), want both disabled", managed.ReadTimeout, managed.WriteTimeout)
	}

	updater.SetManagedDistribution(false)
	upstream := newControllerServer(false)
	if upstream.ReadHeaderTimeout != 0 || upstream.IdleTimeout != 0 || upstream.MaxHeaderBytes != 0 {
		t.Fatalf(
			"upstream server limits = (%s, %s, %d), want zero values",
			upstream.ReadHeaderTimeout,
			upstream.IdleTimeout,
			upstream.MaxHeaderBytes,
		)
	}
	if upstream.ReadTimeout != 0 || upstream.WriteTimeout != 0 {
		t.Fatalf("upstream whole-request timeouts = (%s, %s), want zero values", upstream.ReadTimeout, upstream.WriteTimeout)
	}
}

func TestManagedControllerPreflightLoadsTheKeyPairAndValidatesTheUIPath(t *testing.T) {
	home := t.TempDir()
	previousHome := C.Path.HomeDir()
	C.SetHomeDir(home)
	t.Cleanup(func() { C.SetHomeDir(previousHome) })

	certificate, privateKey, _, err := ca.NewRandomTLSKeyPair(ca.KeyPairTypeP256)
	if err != nil {
		t.Fatal(err)
	}
	_, otherPrivateKey, _, err := ca.NewRandomTLSKeyPair(ca.KeyPairTypeP256)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(home, "cert.pem"), []byte(certificate), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(home, "key.pem"), []byte(privateKey), 0o600); err != nil {
		t.Fatal(err)
	}

	cfg := Config{
		TLSAddr:     "127.0.0.1:443",
		Secret:      "controller-secret",
		Certificate: "cert.pem",
		PrivateKey:  "key.pem",
	}
	if err := PreflightManagedController(&cfg, "ui"); err != nil {
		t.Fatalf("valid managed controller preflight failed: %v", err)
	}
	if err := os.WriteFile(filepath.Join(home, "key.pem"), []byte(otherPrivateKey), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := PreflightManagedController(&cfg, "ui"); err == nil {
		t.Fatal("mismatched controller certificate and private key were accepted")
	}
	unsafeUI := filepath.Join(filepath.Dir(home), "outside-ui")
	if err := PreflightManagedController(&cfg, unsafeUI); err == nil {
		t.Fatal("unsafe managed external-ui path was accepted")
	}
}

func TestManagedControllerBootstrapChangesRequireRestart(t *testing.T) {
	previousManaged := updater.ManagedDistribution()
	t.Cleanup(func() { updater.SetManagedDistribution(previousManaged) })

	previous := &controllerRuntime{
		config: Config{Secret: "old-secret", Certificate: "old-cert.pem", PrivateKey: "old-key.pem"},
		uiPath: "/opt/5gpn/ui",
	}
	updater.SetManagedDistribution(true)
	unchanged := previous.config
	if err := validateManagedControllerRestartTransition(previous, unchanged, previous.uiPath); err != nil {
		t.Fatalf("unchanged managed secret was rejected: %v", err)
	}
	tests := []struct {
		name string
		next Config
		ui   string
	}{
		{name: "secret", next: Config{Secret: "new-secret", Certificate: "old-cert.pem", PrivateKey: "old-key.pem"}, ui: previous.uiPath},
		{name: "certificate", next: Config{Secret: "old-secret", Certificate: "new-cert.pem", PrivateKey: "old-key.pem"}, ui: previous.uiPath},
		{name: "private key", next: Config{Secret: "old-secret", Certificate: "old-cert.pem", PrivateKey: "new-key.pem"}, ui: previous.uiPath},
		{name: "external UI", next: unchanged, ui: ""},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if err := validateManagedControllerRestartTransition(previous, test.next, test.ui); !errors.Is(err, ErrControllerRestartRequired) {
				t.Fatalf("managed bootstrap transition error = %v, want ErrControllerRestartRequired", err)
			}
		})
	}

	updater.SetManagedDistribution(false)
	for _, test := range tests {
		if err := validateManagedControllerRestartTransition(previous, test.next, test.ui); err != nil {
			t.Fatalf("non-managed %s transition was restricted: %v", test.name, err)
		}
	}
}

func TestManagedConfigPutRejectsBootstrapChangesAndKeepsTheLiveGeneration(t *testing.T) {
	tests := []struct {
		name        string
		secret      string
		certificate string
		privateKey  string
		externalUI  string
	}{
		{name: "secret", secret: "new-secret", certificate: "old-cert.pem", privateKey: "old-key.pem", externalUI: "ui"},
		{name: "certificate", secret: "old-secret", certificate: "new-cert.pem", privateKey: "old-key.pem", externalUI: "ui"},
		{name: "private key", secret: "old-secret", certificate: "old-cert.pem", privateKey: "new-key.pem", externalUI: "ui"},
		{name: "external UI", secret: "old-secret", certificate: "old-cert.pem", privateKey: "old-key.pem", externalUI: "other-ui"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			resetControllerTestState(t)
			previousManaged := updater.ManagedDistribution()
			updater.SetManagedDistribution(true)
			t.Cleanup(func() { updater.SetManagedDistribution(previousManaged) })

			emptyProjection := listenerpkg.ProjectInboundListeners(nil)
			configApplyMu.Lock()
			previousProjection := managedNamedListenerProjection
			managedNamedListenerProjection = &emptyProjection
			configApplyMu.Unlock()
			t.Cleanup(func() {
				configApplyMu.Lock()
				managedNamedListenerProjection = previousProjection
				configApplyMu.Unlock()
			})

			listener := &controllerListener{spec: controllerListenerSpec{
				kind: controllerTLS, network: "tcp", address: "127.0.0.1:443",
			}}
			live := &controllerRuntime{
				generation: 7,
				config: Config{
					TLSAddr: "127.0.0.1:443", Secret: "old-secret",
					Certificate: "old-cert.pem", PrivateKey: "old-key.pem",
				},
				uiPath:    C.Path.Resolve("ui"),
				listeners: map[controllerListenerKind]*controllerListener{controllerTLS: listener},
			}
			plan := &controllerPlan{}
			controllerMu.Lock()
			currentController = live
			currentControllerPlan.Store(plan)
			controllerMu.Unlock()
			t.Cleanup(func() {
				controllerMu.Lock()
				currentController = nil
				currentControllerPlan.Store(nil)
				controllerMu.Unlock()
			})

			payload := "secret: " + test.secret + "\n" +
				"external-controller-tls: 127.0.0.1:443\n" +
				"external-ui: " + test.externalUI + "\n" +
				"tls:\n" +
				"  certificate: " + test.certificate + "\n" +
				"  private-key: " + test.privateKey + "\n"
			body, err := json.Marshal(map[string]string{"payload": payload})
			if err != nil {
				t.Fatal(err)
			}
			request := httptest.NewRequest(http.MethodPut, "/configs", bytes.NewReader(body))
			response := httptest.NewRecorder()
			updateConfigs(response, request)
			if response.Code != http.StatusConflict {
				t.Fatalf("PUT /configs status %d, want %d: %s", response.Code, http.StatusConflict, response.Body.String())
			}
			if !strings.Contains(response.Body.String(), ErrControllerRestartRequired.Error()) {
				t.Fatalf("PUT /configs response does not identify the controller restart boundary: %s", response.Body.String())
			}
			controllerMu.Lock()
			unchanged := currentController == live && currentController.generation == 7 && currentController.listeners[controllerTLS] == listener
			controllerMu.Unlock()
			if !unchanged || currentControllerPlan.Load() != plan {
				t.Fatal("rejected PUT /configs changed the live controller generation")
			}
		})
	}
}

func TestControllerReconcileStagesListenersAndRejectsHotAddressChanges(t *testing.T) {
	resetControllerTestState(t)
	previousManaged := updater.ManagedDistribution()
	updater.SetManagedDistribution(false)
	t.Cleanup(func() { updater.SetManagedDistribution(previousManaged) })

	initial := &Config{Addr: "127.0.0.1:0"}
	if err := ReCreateServer(initial, ""); err != nil {
		t.Fatal(err)
	}
	controllerMu.Lock()
	previous := currentController
	previousGeneration := previous.generation
	previousListener := previous.listeners[controllerHTTP]
	previousAddress := previousListener.listener.Addr().String()
	controllerMu.Unlock()

	badCertificate := &Config{
		Addr:        initial.Addr,
		TLSAddr:     "127.0.0.1:0",
		Certificate: "missing-controller-cert.pem",
		PrivateKey:  "missing-controller-key.pem",
	}
	if err := ReCreateServer(badCertificate, ""); err == nil {
		t.Fatal("a candidate with an unusable TLS keypair was published")
	}
	controllerMu.Lock()
	if currentController != previous || currentController.generation != previousGeneration {
		controllerMu.Unlock()
		t.Fatal("failed certificate preparation changed the current controller")
	}
	controllerMu.Unlock()

	occupied, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer occupied.Close()
	candidate := &Config{Addr: occupied.Addr().String()}
	if err := ReCreateServer(candidate, ""); err == nil {
		t.Fatal("a candidate whose listener could not bind was published")
	}

	controllerMu.Lock()
	if currentController != previous || currentController.generation != previousGeneration || currentController.listeners[controllerHTTP] != previousListener {
		controllerMu.Unlock()
		t.Fatal("a failed staged reconcile changed the current controller")
	}
	controllerMu.Unlock()
	connection, err := net.DialTimeout("tcp", previousAddress, time.Second)
	if err != nil {
		t.Fatalf("the old listener was not preserved after candidate failure: %v", err)
	}
	_ = connection.Close()

	if err := ReconcileHotServer(candidate, ""); !errors.Is(err, ErrControllerRestartRequired) {
		t.Fatalf("hot listener change error = %v, want ErrControllerRestartRequired", err)
	}
	controllerMu.Lock()
	defer controllerMu.Unlock()
	if currentController != previous || currentController.generation != previousGeneration {
		t.Fatal("a rejected hot listener change advanced the generation")
	}
}

func TestControllerHotReconcileClearsUIWithoutReplacingTheListener(t *testing.T) {
	resetControllerTestState(t)
	previousManaged := updater.ManagedDistribution()
	previousHome := C.Path.HomeDir()
	updater.SetManagedDistribution(false)
	home := t.TempDir()
	C.SetHomeDir(home)
	t.Cleanup(func() {
		updater.SetManagedDistribution(previousManaged)
		C.SetHomeDir(previousHome)
	})

	uiDir := filepath.Join(home, "ui")
	if err := os.MkdirAll(uiDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(uiDir, "asset.txt"), []byte("console"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := &Config{Addr: "127.0.0.1:0"}
	if err := ReCreateServer(cfg, "ui"); err != nil {
		t.Fatal(err)
	}
	controllerMu.Lock()
	listener := currentController.listeners[controllerHTTP]
	controllerMu.Unlock()
	before := currentControllerPlan.Load()
	if response := requestRoute(before.remoteHandler, http.MethodGet, "/ui/asset.txt", ""); response.Code != http.StatusOK {
		t.Fatalf("initial UI status %d, want %d", response.Code, http.StatusOK)
	}

	if err := ReconcileHotServer(cfg, ""); err != nil {
		t.Fatal(err)
	}
	controllerMu.Lock()
	if uiPath != "" {
		controllerMu.Unlock()
		t.Fatalf("cleared UI path remained %q", uiPath)
	}
	if currentController.listeners[controllerHTTP] != listener {
		controllerMu.Unlock()
		t.Fatal("a UI-only hot reconcile replaced the listener")
	}
	controllerMu.Unlock()
	after := currentControllerPlan.Load()
	if response := requestRoute(after.remoteHandler, http.MethodGet, "/ui/asset.txt", ""); response.Code != http.StatusNotFound {
		t.Fatalf("cleared UI status %d, want %d", response.Code, http.StatusNotFound)
	}
	if response := requestRoute(after.remoteHandler, http.MethodGet, "/", ""); response.Code != http.StatusOK {
		t.Fatalf("root status after clearing UI %d, want %d", response.Code, http.StatusOK)
	}
}

func TestControllerHotDebugReconcileUsesTheCurrentGeneration(t *testing.T) {
	resetControllerTestState(t)
	previousManaged := updater.ManagedDistribution()
	updater.SetManagedDistribution(false)
	t.Cleanup(func() { updater.SetManagedDistribution(previousManaged) })

	if err := ReCreateServer(&Config{Addr: "127.0.0.1:0"}, ""); err != nil {
		t.Fatal(err)
	}
	controllerMu.Lock()
	listener := currentController.listeners[controllerHTTP]
	controllerMu.Unlock()
	if response := requestRoute(currentControllerPlan.Load().remoteHandler, http.MethodPut, "/debug/gc", ""); response.Code != http.StatusNotFound {
		t.Fatalf("debug route before hot enable status %d, want %d", response.Code, http.StatusNotFound)
	}

	if err := reconcileHotDebugRoute(true); err != nil {
		t.Fatal(err)
	}
	controllerMu.Lock()
	if currentController.listeners[controllerHTTP] != listener {
		controllerMu.Unlock()
		t.Fatal("a debug-only hot reconcile replaced the listener")
	}
	controllerMu.Unlock()
	if response := requestRoute(currentControllerPlan.Load().remoteHandler, http.MethodPut, "/debug/gc", ""); response.Code != http.StatusOK {
		t.Fatalf("debug route after hot enable status %d, want %d", response.Code, http.StatusOK)
	}
}

func TestControllerServeExitUsesFatalSeamAndReloadCloseDoesNot(t *testing.T) {
	t.Run("unexpected", func(t *testing.T) {
		resetControllerTestState(t)
		previousManaged := updater.ManagedDistribution()
		updater.SetManagedDistribution(false)
		t.Cleanup(func() { updater.SetManagedDistribution(previousManaged) })
		failures := make(chan error, 1)
		SetControllerFatalHandler(func(err error) { failures <- err })

		if err := ReCreateServer(&Config{Addr: "127.0.0.1:0"}, ""); err != nil {
			t.Fatal(err)
		}
		controllerMu.Lock()
		listener := currentController.listeners[controllerHTTP]
		controllerMu.Unlock()
		if err := listener.listener.Close(); err != nil {
			t.Fatal(err)
		}
		select {
		case failure := <-failures:
			if failure == nil {
				t.Fatal("fatal seam received a nil failure")
			}
		case <-time.After(time.Second):
			t.Fatal("an unexpected current controller exit did not reach the fatal seam")
		}
	})

	t.Run("intentional reload", func(t *testing.T) {
		resetControllerTestState(t)
		previousManaged := updater.ManagedDistribution()
		updater.SetManagedDistribution(false)
		t.Cleanup(func() { updater.SetManagedDistribution(previousManaged) })
		failures := make(chan error, 1)
		SetControllerFatalHandler(func(err error) { failures <- err })

		if err := ReCreateServer(&Config{Addr: "127.0.0.1:0"}, ""); err != nil {
			t.Fatal(err)
		}
		if err := ReCreateServer(&Config{}, ""); err != nil {
			t.Fatal(err)
		}
		select {
		case failure := <-failures:
			t.Fatalf("intentional controller close reached the fatal seam: %v", failure)
		case <-time.After(100 * time.Millisecond):
		}
	})
}

func resetControllerTestState(t *testing.T) {
	t.Helper()
	detach := func() {
		controllerReconcileMu.Lock()
		controllerMu.Lock()
		current := currentController
		if current != nil {
			for _, listener := range current.listeners {
				listener.retired.Store(true)
			}
		}
		currentController = nil
		currentControllerPlan.Store(nil)
		controllerFatal = nil
		uiPath = ""
		controllerMu.Unlock()
		if current != nil {
			for _, listener := range current.listeners {
				closeControllerListener(listener)
			}
		}
		controllerReconcileMu.Unlock()
	}
	detach()
	t.Cleanup(detach)
}
