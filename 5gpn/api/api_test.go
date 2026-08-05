package api

import (
	"testing"

	"github.com/metacubex/chi"
	"github.com/metacubex/http"
	"github.com/metacubex/http/httptest"
)

func TestControllerMountContract(t *testing.T) {
	router := chi.NewRouter()
	registerControllerRoutes(router)

	for _, path := range []string{
		"/5gpn/dns/",
		"/5gpn/interception/",
		"/5gpn/bot/",
	} {
		t.Run("mount "+path, func(t *testing.T) {
			response := httptest.NewRecorder()
			request := httptest.NewRequest(http.MethodGet, path, nil)
			router.ServeHTTP(response, request)
			if response.Code == http.StatusNotFound {
				t.Fatalf("GET %s returned 404", path)
			}
		})
	}

	for _, path := range []string{
		"/gpn/dns/",
		"/gpn/interception/",
		"/gpn/bot/",
	} {
		t.Run("legacy "+path, func(t *testing.T) {
			response := httptest.NewRecorder()
			request := httptest.NewRequest(http.MethodGet, path, nil)
			router.ServeHTTP(response, request)
			if response.Code != http.StatusNotFound {
				t.Fatalf("GET %s returned %d, want 404", path, response.Code)
			}
		})
	}
}
