package api

import (
	"encoding/json"
	"testing"

	"github.com/metacubex/chi"
	"github.com/metacubex/http"
	"github.com/metacubex/http/httptest"
)

func TestCapabilitiesReflectFeaturePublishAndWithdrawal(t *testing.T) {
	const key = "5gpn-interception"
	Advertise(key, Feature{})
	t.Cleanup(func() { Advertise(key, Feature{}) })
	router := chi.NewRouter()
	registerControllerRoutes(router)

	read := func() capabilitiesResponse {
		t.Helper()
		response := httptest.NewRecorder()
		request := httptest.NewRequest(http.MethodGet, "/capabilities", nil)
		router.ServeHTTP(response, request)
		if response.Code != http.StatusOK {
			t.Fatalf("GET /capabilities returned %d", response.Code)
		}
		var payload capabilitiesResponse
		if err := json.Unmarshal(response.Body.Bytes(), &payload); err != nil {
			t.Fatalf("decode capabilities: %v", err)
		}
		return payload
	}

	if _, ok := read().Features[key]; ok {
		t.Fatal("withdrawn interception feature remains in /capabilities")
	}
	Advertise(key, Feature{Version: 5})
	if feature, ok := read().Features[key]; !ok || feature.Version != 5 {
		t.Fatalf("/capabilities interception feature = %+v, present %v; want version 5", feature, ok)
	}
	Advertise(key, Feature{})
	if _, ok := read().Features[key]; ok {
		t.Fatal("withdrawn interception feature remains in /capabilities")
	}
}

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
