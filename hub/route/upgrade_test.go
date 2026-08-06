package route

import (
	"strings"
	"testing"

	"github.com/metacubex/mihomo/component/updater"

	"github.com/metacubex/http"
	"github.com/metacubex/http/httptest"
)

func TestManagedDistributionRejectsCoreAndUIUpgrades(t *testing.T) {
	previous := updater.ManagedDistribution()
	updater.SetManagedDistribution(true)
	t.Cleanup(func() { updater.SetManagedDistribution(previous) })

	for name, handler := range map[string]http.HandlerFunc{
		"core": upgradeCore,
		"ui":   updateUI,
	} {
		t.Run(name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodPost, "https://controller.invalid/upgrade", nil)
			response := httptest.NewRecorder()
			handler(response, request)

			if response.Code != http.StatusForbidden {
				t.Fatalf("status %d, want %d", response.Code, http.StatusForbidden)
			}
			if !strings.Contains(response.Body.String(), "digest-pinned 5gpn release") {
				t.Fatalf("response %q does not explain the managed release boundary", response.Body.String())
			}
		})
	}
}

func TestManagedControllerRoutesRejectOldConsoleUpgradeRequests(t *testing.T) {
	previousManagedDistribution := updater.ManagedDistribution()
	previousEmbedMode := embedMode
	updater.SetManagedDistribution(true)
	embedMode = false
	t.Cleanup(func() {
		updater.SetManagedDistribution(previousManagedDistribution)
		embedMode = previousEmbedMode
	})

	handler := router(false, "controller-secret", "", Cors{})
	for _, target := range []string{
		"/upgrade",
		"/upgrade/",
		"/upgrade?channel=release",
		"/upgrade/ui",
	} {
		response := requestRoute(handler, http.MethodPost, target, "controller-secret")
		if response.Code != http.StatusForbidden {
			t.Fatalf("POST %s status %d, want %d", target, response.Code, http.StatusForbidden)
		}
	}

	response := requestRoute(handler, http.MethodPost, "/upgrade", "")
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated status %d, want %d", response.Code, http.StatusUnauthorized)
	}
	response = requestRoute(handler, http.MethodPost, "/upgrade/ui", "")
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated UI status %d, want %d", response.Code, http.StatusUnauthorized)
	}
	response = requestRoute(handler, http.MethodGet, "/upgrade/geo", "controller-secret")
	if response.Code != http.StatusMethodNotAllowed {
		t.Fatalf("GET GEO status %d, want %d", response.Code, http.StatusMethodNotAllowed)
	}
	response = requestRoute(handler, http.MethodPost, "/upgrade/geo", "")
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated GEO status %d, want %d", response.Code, http.StatusUnauthorized)
	}
}
