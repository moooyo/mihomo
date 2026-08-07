package route

import (
	"bytes"
	"os"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/metacubex/chi"
	"github.com/metacubex/mihomo/component/updater"

	"github.com/metacubex/http"
	"github.com/metacubex/http/httptest"
)

func TestExternalControllerRoutesShareAuthenticationBoundary(t *testing.T) {
	previousRouters := externalRouters
	previousUIPath := uiPath
	t.Cleanup(func() {
		externalRouters = previousRouters
		uiPath = previousUIPath
	})
	externalRouters = []externalRouter{func(router chi.Router) {
		router.Post("/5gpn/interception/location/search", func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusNoContent)
		})
	}}
	uiPath = ""
	handler := router(false, "controller-secret", "", Cors{})

	unauthenticated := requestRoute(handler, http.MethodPost, "/5gpn/interception/location/search", "")
	if unauthenticated.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated external route status %d, want %d", unauthenticated.Code, http.StatusUnauthorized)
	}
	authenticated := requestRoute(handler, http.MethodPost, "/5gpn/interception/location/search", "controller-secret")
	if authenticated.Code != http.StatusNoContent {
		t.Fatalf("authenticated external route status %d, want %d", authenticated.Code, http.StatusNoContent)
	}
}

func TestUIProfileContentType(t *testing.T) {
	previousUIPath := uiPath
	previousEmbedMode := embedMode
	t.Cleanup(func() {
		uiPath = previousUIPath
		embedMode = previousEmbedMode
	})

	dir := t.TempDir()
	profile := []byte{0x30, 0x82, 0x00, 0x05, 0x06, 0x03, 0x2a, 0x03, 0x04}
	if err := os.WriteFile(filepath.Join(dir, "ios-dot.MOBILECONFIG"), profile, 0o600); err != nil {
		t.Fatal(err)
	}
	plain := []byte("ordinary static asset")
	if err := os.WriteFile(filepath.Join(dir, "asset.txt"), plain, 0o600); err != nil {
		t.Fatal(err)
	}
	uiPath = dir
	embedMode = true
	handler := router(false, "controller-secret", "", Cors{})

	for _, method := range []string{http.MethodGet, http.MethodHead} {
		t.Run(method+" profile", func(t *testing.T) {
			response := requestRoute(handler, method, "/ui/ios-dot.MOBILECONFIG", "")
			if response.Code != http.StatusOK {
				t.Fatalf("status %d, want %d", response.Code, http.StatusOK)
			}
			if contentType := response.Header().Get("Content-Type"); contentType != "application/x-apple-aspen-config" {
				t.Fatalf("Content-Type %q, want application/x-apple-aspen-config", contentType)
			}
			if contentLength := response.Header().Get("Content-Length"); contentLength != strconv.Itoa(len(profile)) {
				t.Fatalf("Content-Length %q, want %d", contentLength, len(profile))
			}
			if method == http.MethodGet && !bytes.Equal(response.Body.Bytes(), profile) {
				t.Fatalf("GET body %v, want %v", response.Body.Bytes(), profile)
			}
			if method == http.MethodHead && response.Body.Len() != 0 {
				t.Fatalf("HEAD body length %d, want 0", response.Body.Len())
			}
		})
	}

	response := requestRoute(handler, http.MethodGet, "/ui/asset.txt", "")
	if response.Code != http.StatusOK {
		t.Fatalf("ordinary asset status %d, want %d", response.Code, http.StatusOK)
	}
	if contentType := response.Header().Get("Content-Type"); contentType != "text/plain; charset=utf-8" {
		t.Fatalf("ordinary asset Content-Type %q, want text/plain; charset=utf-8", contentType)
	}
	if !bytes.Equal(response.Body.Bytes(), plain) {
		t.Fatalf("ordinary asset body %q, want %q", response.Body.Bytes(), plain)
	}
}

func TestManagedDistributionUIIsNeverCached(t *testing.T) {
	previousUIPath := uiPath
	previousEmbedMode := embedMode
	previousManagedDistribution := updater.ManagedDistribution()
	t.Cleanup(func() {
		uiPath = previousUIPath
		embedMode = previousEmbedMode
		updater.SetManagedDistribution(previousManagedDistribution)
	})

	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "index.html"), []byte("console"), 0o600); err != nil {
		t.Fatal(err)
	}
	uiPath = dir
	embedMode = true
	updater.SetManagedDistribution(true)
	handler := router(false, "controller-secret", "", Cors{})

	for _, method := range []string{http.MethodGet, http.MethodHead} {
		response := requestRoute(handler, method, "/ui/", "")
		if response.Code != http.StatusOK {
			t.Fatalf("%s status %d, want %d", method, response.Code, http.StatusOK)
		}
		if cacheControl := response.Header().Get("Cache-Control"); cacheControl != "no-store" {
			t.Fatalf("%s Cache-Control %q, want no-store", method, cacheControl)
		}
	}
}

func TestUIRootRedirectAndAuthenticationBoundary(t *testing.T) {
	previousUIPath := uiPath
	previousEmbedMode := embedMode
	t.Cleanup(func() {
		uiPath = previousUIPath
		embedMode = previousEmbedMode
	})

	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "index.html"), []byte("console"), 0o600); err != nil {
		t.Fatal(err)
	}
	uiPath = dir
	embedMode = true
	handler := router(false, "controller-secret", "", Cors{})

	for _, method := range []string{http.MethodGet, http.MethodHead} {
		t.Run(method+" root", func(t *testing.T) {
			response := requestRoute(handler, method, "/", "")
			if response.Code != http.StatusTemporaryRedirect {
				t.Fatalf("status %d, want %d", response.Code, http.StatusTemporaryRedirect)
			}
			if location := response.Header().Get("Location"); location != "/ui/" {
				t.Fatalf("Location %q, want /ui/", location)
			}
			if method == http.MethodHead && response.Body.Len() != 0 {
				t.Fatalf("HEAD body length %d, want 0", response.Body.Len())
			}
		})
	}

	response := requestRoute(handler, http.MethodGet, "/", "controller-secret")
	if response.Code != http.StatusTemporaryRedirect {
		t.Fatalf("authenticated root status %d, want %d", response.Code, http.StatusTemporaryRedirect)
	}

	for _, method := range []string{http.MethodGet, http.MethodHead} {
		t.Run(method+" UI slash redirect", func(t *testing.T) {
			response := requestRoute(handler, method, "/ui", "")
			if response.Code != http.StatusTemporaryRedirect {
				t.Fatalf("status %d, want %d", response.Code, http.StatusTemporaryRedirect)
			}
			if location := response.Header().Get("Location"); location != "/ui/" {
				t.Fatalf("Location %q, want /ui/", location)
			}
		})
	}

	for _, method := range []string{http.MethodGet, http.MethodHead} {
		t.Run(method+" UI", func(t *testing.T) {
			response := requestRoute(handler, method, "/ui/", "")
			if response.Code != http.StatusOK {
				t.Fatalf("status %d, want %d", response.Code, http.StatusOK)
			}
			if method == http.MethodHead && response.Body.Len() != 0 {
				t.Fatalf("HEAD body length %d, want 0", response.Body.Len())
			}
		})
	}

	response = requestRoute(handler, http.MethodPost, "/", "")
	if response.Code != http.StatusMethodNotAllowed {
		t.Fatalf("POST root status %d, want %d", response.Code, http.StatusMethodNotAllowed)
	}
	if location := response.Header().Get("Location"); location != "" {
		t.Fatalf("POST root unexpectedly redirected to %q", location)
	}

	response = requestRoute(handler, http.MethodGet, "/configs", "")
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated API status %d, want %d", response.Code, http.StatusUnauthorized)
	}
}

func TestRootHelloRemainsWhenUIIsDisabled(t *testing.T) {
	previousUIPath := uiPath
	t.Cleanup(func() { uiPath = previousUIPath })
	uiPath = ""
	handler := router(false, "controller-secret", "", Cors{})

	response := requestRoute(handler, http.MethodGet, "/", "")
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated root status %d, want %d", response.Code, http.StatusUnauthorized)
	}

	response = requestRoute(handler, http.MethodGet, "/", "controller-secret")
	if response.Code != http.StatusOK {
		t.Fatalf("authenticated root status %d, want %d", response.Code, http.StatusOK)
	}
	if body := response.Body.String(); body != "{\"hello\":\"mihomo\"}\n" {
		t.Fatalf("body %q, want mihomo hello", body)
	}
}

func requestRoute(handler http.Handler, method, target, secret string) *httptest.ResponseRecorder {
	request := httptest.NewRequest(method, target, nil)
	if secret != "" {
		request.Header.Set("Authorization", "Bearer "+secret)
	}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	return response
}
