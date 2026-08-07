package location

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/url"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/metacubex/http"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return f(request)
}

type errorReadCloser struct {
	err error
}

func (r errorReadCloser) Read([]byte) (int, error) { return 0, r.err }
func (errorReadCloser) Close() error               { return nil }

func upstreamResponse(status int, contentType, body string) *http.Response {
	return &http.Response{
		StatusCode:    status,
		Header:        http.Header{"Content-Type": []string{contentType}},
		Body:          io.NopCloser(strings.NewReader(body)),
		ContentLength: int64(len(body)),
	}
}

func validUpstreamBody(count int) string {
	results := make([]map[string]any, 0, count)
	for index := 0; index < count; index++ {
		results = append(results, map[string]any{
			"place_id":     1000 + index,
			"display_name": " City " + strconv.Itoa(index) + " ",
			"lat":          "3.5952",
			"lon":          "98.6722",
			"boundingbox":  []string{"3.4", "3.7", "98.5", "98.8"},
			"licence":      "must not leave the projection",
		})
	}
	body, err := json.Marshal(results)
	if err != nil {
		panic(err)
	}
	return string(body)
}

func TestSearchUsesFixedBoundaryAndProjectsFiveResults(t *testing.T) {
	var method string
	var endpoint *url.URL
	var headers http.Header
	transport := roundTripFunc(func(request *http.Request) (*http.Response, error) {
		method = request.Method
		copy := *request.URL
		endpoint = &copy
		headers = request.Header.Clone()
		return upstreamResponse(http.StatusOK, "application/json; charset=utf-8", validUpstreamBody(6)), nil
	})
	service := newService(newHTTPClient(transport), func() time.Time {
		return time.Date(2026, time.August, 7, 12, 0, 0, 0, time.UTC)
	})

	results, err := service.Search(context.Background(), "Medan", "zh-CN")
	if err != nil {
		t.Fatalf("Search returned error: %v", err)
	}
	if len(results) != maxResults {
		t.Fatalf("result count = %d, want %d", len(results), maxResults)
	}
	if got := results[0]; got.Label != "City 0" || got.Latitude != 3.5952 || got.Longitude != 98.6722 ||
		got.BoundingBox != (BoundingBox{South: 3.4, North: 3.7, West: 98.5, East: 98.8}) {
		t.Fatalf("first projected result = %+v", got)
	}
	if method != http.MethodGet || endpoint == nil || endpoint.Scheme != "https" || endpoint.Host != nominatimHost || endpoint.Path != nominatimSearchPath {
		t.Fatalf("upstream request = %s %v, want fixed Nominatim search", method, endpoint)
	}
	query := endpoint.Query()
	if len(query) != 6 || query.Get("q") != "Medan" || query.Get("format") != "jsonv2" || query.Get("limit") != "5" ||
		query.Get("addressdetails") != "0" || query.Get("layer") != "address" || query.Get("accept-language") != "zh-CN" {
		t.Fatalf("upstream query = %v", query)
	}
	for name := range headers {
		switch name {
		case "Accept", "Accept-Encoding", "Accept-Language", "User-Agent":
		default:
			t.Errorf("unexpected outbound header %q", name)
		}
	}
	if headers.Get("User-Agent") != searchUserAgent || headers.Get("Accept") != "application/json" ||
		headers.Get("Accept-Encoding") != "identity" || headers.Get("Accept-Language") != "zh-CN" {
		t.Fatalf("outbound headers = %v", headers)
	}
	for _, sensitive := range []string{"Authorization", "Cookie", "Proxy-Authorization", "Referer"} {
		if value := headers.Get(sensitive); value != "" {
			t.Errorf("outbound %s = %q, want empty", sensitive, value)
		}
	}
}

func TestSearchDoesNotFollowRedirect(t *testing.T) {
	var calls atomic.Int32
	transport := roundTripFunc(func(*http.Request) (*http.Response, error) {
		calls.Add(1)
		response := upstreamResponse(http.StatusFound, "text/plain", "redirect")
		response.Header.Set("Location", "https://attacker.example/collect")
		return response, nil
	})
	service := newService(newHTTPClient(transport), time.Now)

	_, err := service.Search(context.Background(), "Medan", "en")
	if !errors.Is(err, ErrUpstreamUnavailable) {
		t.Fatalf("redirect error = %v, want ErrUpstreamUnavailable", err)
	}
	if got := calls.Load(); got != 1 {
		t.Fatalf("redirect made %d requests, want 1", got)
	}
}

func TestSearchCacheRateLimitAndTTL(t *testing.T) {
	now := time.Date(2026, time.August, 7, 12, 0, 0, 0, time.UTC)
	var calls atomic.Int32
	transport := roundTripFunc(func(*http.Request) (*http.Response, error) {
		calls.Add(1)
		return upstreamResponse(http.StatusOK, "application/json", validUpstreamBody(1)), nil
	})
	service := newService(newHTTPClient(transport), func() time.Time { return now })

	first, err := service.Search(context.Background(), "Medan", "en")
	if err != nil {
		t.Fatal(err)
	}
	first[0].Label = "mutated by caller"
	cached, err := service.Search(context.Background(), "Medan", "en")
	if err != nil || cached[0].Label != "City 0" || calls.Load() != 1 {
		t.Fatalf("cache hit = (%+v, %v), calls=%d", cached, err, calls.Load())
	}
	if _, err := service.Search(context.Background(), "Medan", "fr"); !errors.Is(err, ErrRateLimited) {
		t.Fatalf("language-specific miss error = %v, want rate limit", err)
	}
	now = now.Add(minimumRequestInterval)
	if _, err := service.Search(context.Background(), "Medan", "fr"); err != nil {
		t.Fatalf("request at one-second boundary failed: %v", err)
	}
	if _, err := service.Search(context.Background(), "Medan", "FR"); err != nil || calls.Load() != 2 {
		t.Fatalf("case-insensitive language cache failed: err=%v calls=%d", err, calls.Load())
	}

	now = now.Add(cacheTTL)
	if _, err := service.Search(context.Background(), "Medan", "en"); err != nil {
		t.Fatalf("expired cache refresh failed: %v", err)
	}
	if got := calls.Load(); got != 3 {
		t.Fatalf("upstream calls after expiry = %d, want 3", got)
	}
}

func TestSearchHasOneGlobalFlightAndCoalescesSameKey(t *testing.T) {
	now := time.Date(2026, time.August, 7, 12, 0, 0, 0, time.UTC)
	started := make(chan struct{})
	release := make(chan struct{})
	released := false
	defer func() {
		if !released {
			close(release)
		}
	}()
	body := validUpstreamBody(1)
	var calls atomic.Int32
	transport := roundTripFunc(func(*http.Request) (*http.Response, error) {
		if calls.Add(1) == 1 {
			close(started)
		}
		<-release
		return upstreamResponse(http.StatusOK, "application/json", body), nil
	})
	service := newService(newHTTPClient(transport), func() time.Time { return now })
	type outcome struct {
		results []Result
		err     error
	}
	first := make(chan outcome, 1)
	second := make(chan outcome, 1)
	go func() {
		results, err := service.Search(context.Background(), "Medan", "en")
		first <- outcome{results: results, err: err}
	}()
	<-started
	go func() {
		results, err := service.Search(context.Background(), "Medan", "en")
		second <- outcome{results: results, err: err}
	}()
	if _, err := service.Search(context.Background(), "Jakarta", "en"); !errors.Is(err, ErrRateLimited) {
		t.Fatalf("different key during active request returned %v, want rate limit", err)
	}
	if got := calls.Load(); got != 1 {
		t.Fatalf("active requests = %d, want one", got)
	}
	close(release)
	released = true
	for index, channel := range []<-chan outcome{first, second} {
		result := <-channel
		if result.err != nil || len(result.results) != 1 {
			t.Fatalf("coalesced result %d = (%+v, %v)", index, result.results, result.err)
		}
	}
	if got := calls.Load(); got != 1 {
		t.Fatalf("same-key requests made %d upstream calls, want one", got)
	}
}

func TestLeaderCancellationDoesNotCancelSharedFlight(t *testing.T) {
	now := time.Date(2026, time.August, 7, 12, 0, 0, 0, time.UTC)
	started := make(chan struct{})
	release := make(chan struct{})
	released := false
	defer func() {
		if !released {
			close(release)
		}
	}()
	body := validUpstreamBody(1)
	var calls atomic.Int32
	transport := roundTripFunc(func(request *http.Request) (*http.Response, error) {
		if calls.Add(1) == 1 {
			close(started)
		}
		select {
		case <-release:
			return upstreamResponse(http.StatusOK, "application/json", body), nil
		case <-request.Context().Done():
			return nil, request.Context().Err()
		}
	})
	service := newService(newHTTPClient(transport), func() time.Time { return now })
	leaderContext, cancelLeader := context.WithCancel(context.Background())
	leader := make(chan error, 1)
	go func() {
		_, err := service.Search(leaderContext, "Medan", "en")
		leader <- err
	}()
	<-started
	cancelLeader()
	if err := <-leader; !errors.Is(err, ErrUpstreamTimeout) {
		t.Fatalf("cancelled leader error = %v, want ErrUpstreamTimeout", err)
	}

	follower := make(chan error, 1)
	go func() {
		results, err := service.Search(context.Background(), "Medan", "en")
		if err == nil && len(results) != 1 {
			err = errors.New("follower received the wrong result count")
		}
		follower <- err
	}()
	close(release)
	released = true
	if err := <-follower; err != nil {
		t.Fatalf("follower failed after leader cancellation: %v", err)
	}
	if got := calls.Load(); got != 1 {
		t.Fatalf("leader and follower made %d upstream calls, want one", got)
	}
}

func TestUpstreamRateLimitExtendsCooldown(t *testing.T) {
	now := time.Date(2026, time.August, 7, 12, 0, 0, 0, time.UTC)
	var calls atomic.Int32
	transport := roundTripFunc(func(*http.Request) (*http.Response, error) {
		if calls.Add(1) == 1 {
			return upstreamResponse(http.StatusTooManyRequests, "application/json", `{}`), nil
		}
		return upstreamResponse(http.StatusOK, "application/json", validUpstreamBody(1)), nil
	})
	service := newService(newHTTPClient(transport), func() time.Time { return now })

	_, err := service.Search(context.Background(), "Medan", "en")
	var rateLimit *RateLimitError
	if !errors.As(err, &rateLimit) || rateLimit.RetryAfter != defaultUpstreamBackoff {
		t.Fatalf("upstream 429 error = %#v", err)
	}
	now = now.Add(time.Second)
	if _, err := service.Search(context.Background(), "Jakarta", "en"); !errors.Is(err, ErrRateLimited) {
		t.Fatalf("cooldown error = %v, want rate limit", err)
	}
	if got := calls.Load(); got != 1 {
		t.Fatalf("cooldown made %d upstream calls, want 1", got)
	}
	now = now.Add(defaultUpstreamBackoff - time.Second)
	if _, err := service.Search(context.Background(), "Jakarta", "en"); err != nil {
		t.Fatalf("request at cooldown boundary failed: %v", err)
	}
}

func TestUpstreamRetryAfterIsParsedAndBounded(t *testing.T) {
	now := time.Date(2026, time.August, 7, 12, 0, 0, 0, time.UTC)
	tests := []struct {
		name string
		raw  string
		want time.Duration
	}{
		{name: "default", want: defaultUpstreamBackoff},
		{name: "seconds", raw: "120", want: 2 * time.Minute},
		{name: "minimum", raw: "0", want: defaultUpstreamBackoff},
		{name: "shorter than default", raw: "1", want: defaultUpstreamBackoff},
		{name: "maximum", raw: "999999999999", want: maximumUpstreamBackoff},
		{name: "date", raw: now.Add(3 * time.Minute).Format(http.TimeFormat), want: 3 * time.Minute},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := boundedRetryAfter(test.raw, now); got != test.want {
				t.Fatalf("boundedRetryAfter(%q) = %s, want %s", test.raw, got, test.want)
			}
		})
	}
}

func TestSearchRejectsUnboundedOrInvalidUpstreamResponses(t *testing.T) {
	tests := []struct {
		name         string
		response     *http.Response
		transportErr error
		want         error
	}{
		{name: "status", response: upstreamResponse(http.StatusInternalServerError, "application/json", `{}`), want: ErrUpstreamUnavailable},
		{name: "content type", response: upstreamResponse(http.StatusOK, "text/html", `[]`), want: ErrUpstreamUnavailable},
		{name: "malformed JSON", response: upstreamResponse(http.StatusOK, "application/json", `[`), want: ErrUpstreamUnavailable},
		{name: "null JSON", response: upstreamResponse(http.StatusOK, "application/json", `null`), want: ErrUpstreamUnavailable},
		{name: "invalid UTF-8", response: upstreamResponse(http.StatusOK, "application/json", string([]byte{'[', '"', 0xff, '"', ']'})), want: ErrUpstreamUnavailable},
		{name: "extra JSON", response: upstreamResponse(http.StatusOK, "application/json", `[] {}`), want: ErrUpstreamUnavailable},
		{name: "oversized", response: upstreamResponse(http.StatusOK, "application/json", strings.Repeat("x", maxResponseBytes+1)), want: ErrUpstreamUnavailable},
		{name: "invalid coordinate", response: upstreamResponse(http.StatusOK, "application/json", `[{"display_name":"Bad","lat":"91","lon":"0","boundingbox":["0","1","0","1"]}]`), want: ErrUpstreamUnavailable},
		{name: "timeout", transportErr: context.DeadlineExceeded, want: ErrUpstreamTimeout},
		{name: "body timeout", response: &http.Response{StatusCode: http.StatusOK, Header: http.Header{"Content-Type": []string{"application/json"}}, Body: errorReadCloser{err: context.DeadlineExceeded}}, want: ErrUpstreamTimeout},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			transport := roundTripFunc(func(*http.Request) (*http.Response, error) {
				return test.response, test.transportErr
			})
			service := newService(newHTTPClient(transport), time.Now)
			_, err := service.Search(context.Background(), "Medan", "en")
			if !errors.Is(err, test.want) {
				t.Fatalf("Search error = %v, want %v", err, test.want)
			}
		})
	}
}

func TestCacheCapacityIsBounded(t *testing.T) {
	now := time.Date(2026, time.August, 7, 12, 0, 0, 0, time.UTC)
	transport := roundTripFunc(func(*http.Request) (*http.Response, error) {
		return upstreamResponse(http.StatusOK, "application/json", `[]`), nil
	})
	service := newService(newHTTPClient(transport), func() time.Time { return now })
	for index := 0; index <= maxCacheEntries; index++ {
		if _, err := service.Search(context.Background(), "city-"+strconv.Itoa(index), "en"); err != nil {
			t.Fatalf("search %d failed: %v", index, err)
		}
		now = now.Add(minimumRequestInterval)
	}
	service.mu.Lock()
	entries := len(service.cache)
	service.mu.Unlock()
	if entries != maxCacheEntries {
		t.Fatalf("cache entries = %d, want %d", entries, maxCacheEntries)
	}
}

func TestTransportOnlyDialsTheFixedNominatimOrigin(t *testing.T) {
	sentinel := errors.New("dial sentinel")
	var calls atomic.Int32
	var host string
	var port int
	transport := newTransport(func(_ context.Context, dialHost string, dialPort int) (net.Conn, error) {
		calls.Add(1)
		host, port = dialHost, dialPort
		return nil, sentinel
	})

	_, err := transport.DialContext(context.Background(), "tcp", net.JoinHostPort(nominatimHost, "443"))
	if !errors.Is(err, sentinel) || host != nominatimHost || port != nominatimPort || calls.Load() != 1 {
		t.Fatalf("fixed dial = host %q port %d calls %d err %v", host, port, calls.Load(), err)
	}
	for _, target := range []struct {
		network string
		address string
	}{
		{network: "udp", address: net.JoinHostPort(nominatimHost, "443")},
		{network: "tcp", address: "attacker.example:443"},
		{network: "tcp", address: net.JoinHostPort(nominatimHost, "80")},
	} {
		if _, err := transport.DialContext(context.Background(), target.network, target.address); err == nil {
			t.Errorf("DialContext(%q, %q) succeeded", target.network, target.address)
		}
	}
	if got := calls.Load(); got != 1 {
		t.Fatalf("rejected targets reached injected dialer %d times, want 1", got)
	}
}
