package api

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/metacubex/http"
	"github.com/metacubex/http/httptest"
	"github.com/metacubex/mihomo/5gpn/engine"
)

func newInterceptionAPIEngine(t *testing.T) *engine.Engine {
	t.Helper()
	dir := t.TempDir()
	configPath := filepath.Join(dir, "intercept.json")
	if err := engine.EnsureDocument(configPath); err != nil {
		t.Fatalf("seed interception document: %v", err)
	}
	e, err := engine.New(configPath, dir)
	if err != nil {
		t.Fatalf("open interception engine: %v", err)
	}
	SetInterceptionEngine(e)
	t.Cleanup(func() { SetInterceptionEngine(nil) })
	return e
}

func TestInstalledSourceUpdateRoutesAreNotExposed(t *testing.T) {
	for _, method := range []string{http.MethodGet, http.MethodPost} {
		response := httptest.NewRecorder()
		request := httptest.NewRequest(method, "/extensions/example.plugin/update", nil)
		interceptionRouter().ServeHTTP(response, request)
		if response.Code != http.StatusNotFound {
			t.Fatalf("%s installed-source update route returned %d, want 404", method, response.Code)
		}
	}
}

func TestSettingsRejectHTTP3WithoutPublishing(t *testing.T) {
	e := newInterceptionAPIEngine(t)

	before, revision := e.ReadDocument()
	body, err := json.Marshal(settingsRequest{
		Revision: revision,
		Enabled:  true,
		HTTP2:    true,
		HTTP3:    true,
	})
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPut, "/settings", strings.NewReader(string(body)))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	interceptionRouter().ServeHTTP(response, request)

	if response.Code != http.StatusUnprocessableEntity {
		t.Fatalf("status %d, want %d; body=%s", response.Code, http.StatusUnprocessableEntity, response.Body.String())
	}
	var failure struct {
		Message string `json:"message"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &failure); err != nil {
		t.Fatalf("decode error response: %v", err)
	}
	if !strings.Contains(failure.Message, "HTTP/3") || !strings.Contains(failure.Message, "unsupported") || !strings.Contains(failure.Message, "blocked") {
		t.Fatalf("unclear HTTP/3 rejection %q", failure.Message)
	}

	after, stillRevision := e.ReadDocument()
	if stillRevision != revision {
		t.Errorf("revision moved from %s to %s after the rejected API write", revision, stillRevision)
	}
	if before.MITM != after.MITM || after.MITM.HTTP3 {
		t.Errorf("rejected API write changed settings from %+v to %+v", before.MITM, after.MITM)
	}
}

func TestExtensionSettingsRouteRequiresACompleteValuesDocument(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "intercept.json")
	const document = `{
  "version": 6,
  "execution_order": ["settings-test"],
  "tls_cert": "/etc/5gpn/intercept/tls/fullchain.pem",
  "tls_key": "/etc/5gpn/intercept/tls/privkey.pem",
  "mitm": {"enabled": false, "http2": true, "http3": false},
  "modules": [{
    "id": "settings-test",
    "extension_version": "1.0.0",
    "name": "Settings test",
    "enabled": false,
    "imported_at": "2026-08-06T00:00:00Z",
    "source": {"digest": "44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a", "body": "{}"},
    "capture_hosts": ["settings.example.com"],
    "capture_dns": "trust",
    "upstream_mappings": [{"host": "settings.example.com", "target": "origin.settings.example.net"}],
    "settings": [{"key": "region", "type": "select", "required": true, "options": ["cn", "hk"], "value": "cn"}],
    "persistent_storage": false,
    "egress_group_required": false
  }],
  "catalogs": []
}`
	if err := os.WriteFile(configPath, []byte(document), 0o600); err != nil {
		t.Fatal(err)
	}
	e, err := engine.New(configPath, dir)
	if err != nil {
		t.Fatalf("open interception engine: %v", err)
	}
	SetInterceptionEngine(e)
	t.Cleanup(func() { SetInterceptionEngine(nil) })
	revision := e.Revision()

	requestBody, err := json.Marshal(extensionSettingsRequest{Revision: revision})
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPut, "/extensions/settings-test/settings", strings.NewReader(string(requestBody)))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	interceptionRouter().ServeHTTP(response, request)
	if response.Code != http.StatusUnprocessableEntity {
		t.Fatalf("missing values status %d, want %d; body=%s", response.Code, http.StatusUnprocessableEntity, response.Body.String())
	}
	if e.Revision() != revision {
		t.Fatalf("rejected settings request moved revision %q to %q", revision, e.Revision())
	}

	legacy := httptest.NewRequest(http.MethodPut, "/extensions/settings-test/settings/region", strings.NewReader(string(requestBody)))
	legacy.Header.Set("Content-Type", "application/json")
	legacyResponse := httptest.NewRecorder()
	interceptionRouter().ServeHTTP(legacyResponse, legacy)
	if legacyResponse.Code != http.StatusNotFound {
		t.Fatalf("retired per-key route status %d, want %d", legacyResponse.Code, http.StatusNotFound)
	}

	validBody, err := json.Marshal(extensionSettingsRequest{
		Revision: revision,
		Values: engine.SettingValues{
			"region": json.RawMessage(`"hk"`),
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	validRequest := httptest.NewRequest(http.MethodPut, "/extensions/settings-test/settings", strings.NewReader(string(validBody)))
	validRequest.Header.Set("Content-Type", "application/json")
	validResponse := httptest.NewRecorder()
	interceptionRouter().ServeHTTP(validResponse, validRequest)
	if validResponse.Code != http.StatusOK {
		t.Fatalf("complete values status %d, want %d; body=%s", validResponse.Code, http.StatusOK, validResponse.Body.String())
	}
	detail, err := e.Detail("settings-test")
	if err != nil {
		t.Fatal(err)
	}
	if got := string(detail.Settings[0].Value); got != `"hk"` {
		t.Fatalf("stored API setting = %s, want hk", got)
	}
}

func TestCertificateRetryRouteReturnsTheStandardPendingEnvelope(t *testing.T) {
	e := newInterceptionAPIEngine(t)
	before, err := e.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	revision := e.Revision()
	if before.Certificate.Status != "pending" || before.Certificate.TargetDigest == "" || before.Certificate.Attempt == "" {
		t.Fatalf("initial certificate state = %+v, want a fenced pending request", before.Certificate)
	}

	body, err := json.Marshal(certificateRetryRequest{
		Revision:     revision,
		TargetDigest: before.Certificate.TargetDigest,
		Attempt:      before.Certificate.Attempt,
	})
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, "/certificate/retry", strings.NewReader(string(body)))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	interceptionRouter().ServeHTTP(response, request)
	if response.Code != http.StatusAccepted {
		t.Fatalf("retry status %d, want %d; body=%s", response.Code, http.StatusAccepted, response.Body.String())
	}
	var envelope interceptionResponse
	if err := json.Unmarshal(response.Body.Bytes(), &envelope); err != nil {
		t.Fatalf("decode retry envelope: %v", err)
	}
	if envelope.Revision != revision || envelope.Snapshot.Certificate.Status != "pending" {
		t.Fatalf("retry envelope = %+v, want unchanged revision and pending status", envelope)
	}

	staleBody, err := json.Marshal(certificateRetryRequest{
		Revision:     revision,
		TargetDigest: before.Certificate.TargetDigest,
		Attempt:      strings.Repeat("f", 32),
	})
	if err != nil {
		t.Fatal(err)
	}
	staleRequest := httptest.NewRequest(http.MethodPost, "/certificate/retry", strings.NewReader(string(staleBody)))
	staleRequest.Header.Set("Content-Type", "application/json")
	staleResponse := httptest.NewRecorder()
	interceptionRouter().ServeHTTP(staleResponse, staleRequest)
	if staleResponse.Code != http.StatusConflict {
		t.Fatalf("stale retry status %d, want %d; body=%s", staleResponse.Code, http.StatusConflict, staleResponse.Body.String())
	}
}
