package route

import (
	"errors"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/metacubex/mihomo/component/updater"
	C "github.com/metacubex/mihomo/constant"

	"github.com/metacubex/http"
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
		{name: "plaintext controller", mutate: func(cfg *Config) { cfg.Addr = "127.0.0.1:9090" }},
		{name: "missing TLS controller", mutate: func(cfg *Config) { cfg.TLSAddr = "" }},
		{name: "wrong TLS controller", mutate: func(cfg *Config) { cfg.TLSAddr = "127.0.0.1:9090" }},
		{name: "missing certificate", mutate: func(cfg *Config) { cfg.Certificate = "" }},
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

	updater.SetManagedDistribution(false)
	upstream := valid
	upstream.Secret = ""
	upstream.Addr = "0.0.0.0:9090"
	upstream.TLSAddr = ""
	upstream.Certificate = ""
	upstream.PrivateKey = ""
	upstream.DohServer = "/dns-query"
	upstream.UnixAddr = "mihomo.sock"
	if err := ValidateConfig(&upstream); err != nil {
		t.Fatalf("upstream controller behavior was restricted: %v", err)
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
