package api

import (
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"

	"github.com/metacubex/http"
	"github.com/metacubex/http/httptest"
	"github.com/metacubex/mihomo/gpn/engine"
)

func TestSettingsRejectHTTP3WithoutPublishing(t *testing.T) {
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
