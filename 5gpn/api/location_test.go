package api

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/metacubex/chi"
	"github.com/metacubex/http"
	"github.com/metacubex/http/httptest"
	"github.com/metacubex/mihomo/5gpn/location"
)

type stubLocationSearcher struct {
	query    string
	language string
	calls    int
	results  []location.Result
	err      error
}

func (s *stubLocationSearcher) Search(_ context.Context, query, language string) ([]location.Result, error) {
	s.calls++
	s.query = query
	s.language = language
	return append([]location.Result(nil), s.results...), s.err
}

func installLocationSearcher(t *testing.T, searcher location.Searcher) {
	t.Helper()
	SetLocationSearcher(searcher)
	t.Cleanup(func() { SetLocationSearcher(nil) })
}

func newLocationSearchRequest(target, body string) *http.Request {
	request := httptest.NewRequest(http.MethodPost, target, strings.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	return request
}

func TestLocationSearchIsMountedWithStableProjectionAndNoStore(t *testing.T) {
	newInterceptionAPIEngine(t)
	searcher := &stubLocationSearcher{results: []location.Result{{
		Label:     "New York, United States",
		Latitude:  40.7128,
		Longitude: -74.006,
		BoundingBox: location.BoundingBox{
			South: 40.49,
			North: 40.92,
			West:  -74.26,
			East:  -73.7,
		},
	}}}
	for len(searcher.results) < maxLocationSearchResults+1 {
		searcher.results = append(searcher.results, searcher.results[0])
	}
	installLocationSearcher(t, searcher)
	router := chi.NewRouter()
	registerControllerRoutes(router)
	// Authentication belongs to hub/route's protected group. This test mounts
	// the API callback directly and covers only path, projection, and no-store.
	request := newLocationSearchRequest("/5gpn/interception/location/search", `{"query":"  New   York  "}`)
	response := httptest.NewRecorder()

	router.ServeHTTP(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("status %d, want %d; body=%s", response.Code, http.StatusOK, response.Body.String())
	}
	if cacheControl := response.Header().Get("Cache-Control"); cacheControl != "no-store" {
		t.Fatalf("Cache-Control = %q, want no-store", cacheControl)
	}
	if searcher.calls != 1 || searcher.query != "New York" || searcher.language != "en" {
		t.Fatalf("search call = count %d query %q language %q", searcher.calls, searcher.query, searcher.language)
	}
	var payload struct {
		Results []map[string]any `json:"results"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if len(payload.Results) != maxLocationSearchResults {
		t.Fatalf("results = %#v", payload.Results)
	}
	result := payload.Results[0]
	for _, field := range []string{"label", "latitude", "longitude", "bounding_box"} {
		if _, ok := result[field]; !ok {
			t.Errorf("result omitted %q: %#v", field, result)
		}
	}
	if len(result) != 4 {
		t.Fatalf("result exposed unexpected fields: %#v", result)
	}
	box, ok := result["bounding_box"].(map[string]any)
	if !ok || len(box) != 4 {
		t.Fatalf("bounding_box = %#v", result["bounding_box"])
	}
	for _, field := range []string{"south", "north", "west", "east"} {
		if _, ok := box[field]; !ok {
			t.Errorf("bounding_box omitted %q: %#v", field, box)
		}
	}
}

func TestLocationSearchRejectsInvalidInputBeforeCallingUpstream(t *testing.T) {
	searcher := &stubLocationSearcher{}
	installLocationSearcher(t, searcher)
	tests := []struct {
		name        string
		target      string
		body        string
		contentType string
		wantStatus  int
	}{
		{name: "URL query", target: "/location/search?query=private", body: `{"query":"Medan"}`, contentType: "application/json", wantStatus: http.StatusBadRequest},
		{name: "missing content type", target: "/location/search", body: `{"query":"Medan"}`, wantStatus: http.StatusUnsupportedMediaType},
		{name: "empty query", target: "/location/search", body: `{"query":"   "}`, contentType: "application/json", wantStatus: http.StatusBadRequest},
		{name: "control in query", target: "/location/search", body: `{"query":"New\nYork"}`, contentType: "application/json", wantStatus: http.StatusBadRequest},
		{name: "query bytes", target: "/location/search", body: `{"query":"` + strings.Repeat("a", maxLocationSearchQueryBytes+1) + `"}`, contentType: "application/json", wantStatus: http.StatusBadRequest},
		{name: "query runes", target: "/location/search", body: `{"query":"` + strings.Repeat("a", maxLocationSearchQueryRunes+1) + `"}`, contentType: "application/json", wantStatus: http.StatusBadRequest},
		{name: "language list", target: "/location/search", body: `{"query":"Medan","language":"en-US,zh-CN"}`, contentType: "application/json", wantStatus: http.StatusBadRequest},
		{name: "language singleton", target: "/location/search", body: `{"query":"Medan","language":"x"}`, contentType: "application/json", wantStatus: http.StatusBadRequest},
		{name: "invalid language tag", target: "/location/search", body: `{"query":"Medan","language":"en-12"}`, contentType: "application/json", wantStatus: http.StatusBadRequest},
		{name: "language underscore", target: "/location/search", body: `{"query":"Medan","language":"en_US"}`, contentType: "application/json", wantStatus: http.StatusBadRequest},
		{name: "null language", target: "/location/search", body: `{"query":"Medan","language":null}`, contentType: "application/json", wantStatus: http.StatusBadRequest},
		{name: "null query", target: "/location/search", body: `{"query":null}`, contentType: "application/json", wantStatus: http.StatusBadRequest},
		{name: "uppercase field", target: "/location/search", body: `{"QUERY":"Medan"}`, contentType: "application/json", wantStatus: http.StatusBadRequest},
		{name: "duplicate field", target: "/location/search", body: `{"query":"Medan","query":"Jakarta"}`, contentType: "application/json", wantStatus: http.StatusBadRequest},
		{name: "unpaired surrogate", target: "/location/search", body: `{"query":"\ud800"}`, contentType: "application/json", wantStatus: http.StatusBadRequest},
		{name: "invalid UTF-8", target: "/location/search", body: "{\"query\":\"\xff\"}", contentType: "application/json", wantStatus: http.StatusBadRequest},
		{name: "unknown field", target: "/location/search", body: `{"query":"Medan","origin":"https://attacker.example"}`, contentType: "application/json", wantStatus: http.StatusBadRequest},
		{name: "trailing JSON", target: "/location/search", body: `{"query":"Medan"}{}`, contentType: "application/json", wantStatus: http.StatusBadRequest},
		{name: "request bytes", target: "/location/search", body: `{"query":"` + strings.Repeat("a", maxLocationSearchRequestBytes) + `"}`, contentType: "application/json", wantStatus: http.StatusRequestEntityTooLarge},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodPost, test.target, strings.NewReader(test.body))
			if test.contentType != "" {
				request.Header.Set("Content-Type", test.contentType)
			}
			response := httptest.NewRecorder()
			interceptionRouter().ServeHTTP(response, request)
			if response.Code != test.wantStatus {
				t.Fatalf("status %d, want %d; body=%s", response.Code, test.wantStatus, response.Body.String())
			}
			if response.Header().Get("Cache-Control") != "no-store" {
				t.Fatalf("Cache-Control = %q", response.Header().Get("Cache-Control"))
			}
			if strings.Contains(response.Body.String(), "private") {
				t.Fatalf("response echoed private query: %s", response.Body.String())
			}
		})
	}
	if searcher.calls != 0 {
		t.Fatalf("invalid requests called searcher %d times", searcher.calls)
	}
}

func TestLocationSearchAcceptsUnicodeAndCanonicalBCP47(t *testing.T) {
	newInterceptionAPIEngine(t)
	searcher := &stubLocationSearcher{}
	installLocationSearcher(t, searcher)
	response := httptest.NewRecorder()
	request := newLocationSearchRequest("/location/search", `{"query":"\ud83d\udccd Medan","language":"EN-u-CA-gregory"}`)
	interceptionRouter().ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("status %d, want %d; body=%s", response.Code, http.StatusOK, response.Body.String())
	}
	if searcher.query != "📍 Medan" || searcher.language != "en-u-ca-gregory" {
		t.Fatalf("normalized request = query %q language %q", searcher.query, searcher.language)
	}
}

func TestLocationSearchDoesNotAcceptQueryStringGET(t *testing.T) {
	searcher := &stubLocationSearcher{}
	installLocationSearcher(t, searcher)
	response := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/location/search?query=private-place", nil)
	interceptionRouter().ServeHTTP(response, request)
	if response.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status %d, want %d; body=%s", response.Code, http.StatusMethodNotAllowed, response.Body.String())
	}
	if response.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("Cache-Control = %q", response.Header().Get("Cache-Control"))
	}
	if searcher.calls != 0 {
		t.Fatalf("GET called searcher %d times", searcher.calls)
	}
}

func TestLocationSearchMapsBoundedErrorsWithoutLeakingDetails(t *testing.T) {
	newInterceptionAPIEngine(t)
	tests := []struct {
		name       string
		err        error
		wantStatus int
		wantCode   string
		wantRetry  string
	}{
		{name: "local rate limit", err: &location.RateLimitError{RetryAfter: 1500 * time.Millisecond}, wantStatus: http.StatusTooManyRequests, wantCode: "rate_limited", wantRetry: "2"},
		{name: "bounded rate limit", err: &location.RateLimitError{RetryAfter: time.Duration(1<<63 - 1)}, wantStatus: http.StatusTooManyRequests, wantCode: "rate_limited", wantRetry: "86400"},
		{name: "timeout", err: location.ErrUpstreamTimeout, wantStatus: http.StatusGatewayTimeout, wantCode: "upstream_timeout"},
		{name: "upstream", err: location.ErrUpstreamUnavailable, wantStatus: http.StatusBadGateway, wantCode: "upstream_unavailable"},
		{name: "opaque internal", err: errors.New("private-place upstream exploded"), wantStatus: http.StatusBadGateway, wantCode: "upstream_unavailable"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			searcher := &stubLocationSearcher{err: test.err}
			SetLocationSearcher(searcher)
			defer SetLocationSearcher(nil)
			response := httptest.NewRecorder()
			request := newLocationSearchRequest("/location/search", `{"query":"private-place","language":"zh-Hans-CN"}`)
			interceptionRouter().ServeHTTP(response, request)
			if response.Code != test.wantStatus {
				t.Fatalf("status %d, want %d; body=%s", response.Code, test.wantStatus, response.Body.String())
			}
			var failure struct {
				Code string `json:"code"`
			}
			if err := json.Unmarshal(response.Body.Bytes(), &failure); err != nil || failure.Code != test.wantCode {
				t.Fatalf("failure = %+v, decode err %v", failure, err)
			}
			if retry := response.Header().Get("Retry-After"); retry != test.wantRetry {
				t.Fatalf("Retry-After = %q, want %q", retry, test.wantRetry)
			}
			if strings.Contains(response.Body.String(), "private-place") || strings.Contains(response.Body.String(), "exploded") {
				t.Fatalf("failure leaked query or internal detail: %s", response.Body.String())
			}
		})
	}
}

func TestLocationSearchUnavailableIsExplicit(t *testing.T) {
	newInterceptionAPIEngine(t)
	SetLocationSearcher(nil)
	response := httptest.NewRecorder()
	request := newLocationSearchRequest("/location/search", `{"query":"Medan"}`)
	interceptionRouter().ServeHTTP(response, request)
	if response.Code != http.StatusServiceUnavailable {
		t.Fatalf("status %d, want %d; body=%s", response.Code, http.StatusServiceUnavailable, response.Body.String())
	}
}

func TestLocationSearchFollowsInterceptionCapabilityLifecycle(t *testing.T) {
	SetInterceptionEngine(nil)
	searcher := &stubLocationSearcher{}
	installLocationSearcher(t, searcher)
	response := httptest.NewRecorder()
	request := newLocationSearchRequest("/location/search", `{"query":"Medan"}`)
	interceptionRouter().ServeHTTP(response, request)
	if response.Code != http.StatusServiceUnavailable {
		t.Fatalf("status %d, want %d; body=%s", response.Code, http.StatusServiceUnavailable, response.Body.String())
	}
	if searcher.calls != 0 {
		t.Fatalf("withdrawn interception capability called searcher %d times", searcher.calls)
	}
}
