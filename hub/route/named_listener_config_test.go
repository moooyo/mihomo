package route

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/metacubex/mihomo/component/updater"
	coreconfig "github.com/metacubex/mihomo/config"
	"github.com/metacubex/mihomo/hub/executor"
	"github.com/metacubex/mihomo/listener"
	"github.com/metacubex/mihomo/log"

	"github.com/metacubex/http"
	"github.com/metacubex/http/httptest"
)

func TestManagedNamedListenerTransitionRequiresRestart(t *testing.T) {
	initial := parseNamedListenerConfig(t, "10000")
	changed := parseNamedListenerConfig(t, "10001")
	projection := listener.ProjectInboundListeners(initial.Listeners)

	previous := managedNamedListenerProjection
	managedNamedListenerProjection = &projection
	t.Cleanup(func() { managedNamedListenerProjection = previous })

	if _, err := validateManagedNamedListenerTransition(initial, true, true); err != nil {
		t.Fatalf("unchanged named listeners were rejected: %v", err)
	}
	if _, err := validateManagedNamedListenerTransition(changed, true, true); !errors.Is(err, ErrNamedListenersRestartRequired) {
		t.Fatalf("changed named listener error = %v, want restart required", err)
	}
	if _, err := validateManagedNamedListenerTransition(changed, false, true); err != nil {
		t.Fatalf("ordinary mihomo listener change was restricted: %v", err)
	}
}

func TestManagedConfigPutRejectsNamedListenerChangeBeforeExecutorMutation(t *testing.T) {
	previousManaged := updater.ManagedDistribution()
	updater.SetManagedDistribution(true)
	t.Cleanup(func() { updater.SetManagedDistribution(previousManaged) })

	initial := parseNamedListenerConfig(t, "10000")
	projection := listener.ProjectInboundListeners(initial.Listeners)
	configApplyMu.Lock()
	previousProjection := managedNamedListenerProjection
	managedNamedListenerProjection = &projection
	configApplyMu.Unlock()
	t.Cleanup(func() {
		configApplyMu.Lock()
		managedNamedListenerProjection = previousProjection
		configApplyMu.Unlock()
	})

	previousLevel := log.Level()
	log.SetLevel(log.INFO)
	t.Cleanup(func() { log.SetLevel(previousLevel) })

	payload := namedListenerYAML("10001") + "log-level: debug\n"
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
	if !strings.Contains(response.Body.String(), ErrNamedListenersRestartRequired.Error()) {
		t.Fatalf("PUT /configs response does not identify the restart boundary: %s", response.Body.String())
	}
	if log.Level() != log.INFO {
		t.Fatalf("rejected PUT /configs changed log level to %s", log.Level())
	}
}

func parseNamedListenerConfig(t *testing.T, port string) *coreconfig.Config {
	t.Helper()
	cfg, err := executor.ParseWithBytes([]byte(namedListenerYAML(port)))
	if err != nil {
		t.Fatal(err)
	}
	return cfg
}

func namedListenerYAML(port string) string {
	return "listeners:\n" +
		"  - name: managed-http\n" +
		"    type: http\n" +
		"    listen: 127.0.0.1\n" +
		"    port: " + port + "\n"
}
