package route

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/metacubex/http"
	"github.com/metacubex/http/httptest"
)

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
