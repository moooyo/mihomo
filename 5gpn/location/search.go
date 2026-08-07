// Package location provides the bounded geocoding projection used by the
// authenticated Console location editor.
package location

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"io"
	"math"
	"mime"
	"net"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/metacubex/http"
)

const (
	nominatimHost       = "nominatim.openstreetmap.org"
	nominatimPort       = 443
	nominatimSearchPath = "/search"
	searchUserAgent     = "5gpn-mihomo-location-search/1 (+https://github.com/moooyo/5gpn)"

	searchTimeout          = 8 * time.Second
	minimumRequestInterval = time.Second
	defaultUpstreamBackoff = time.Minute
	maximumUpstreamBackoff = 24 * time.Hour
	cacheTTL               = 30 * time.Minute
	maxCacheEntries        = 128
	maxResults             = 5
	maxResponseBytes       = 64 << 10
	maxResultLabelBytes    = 512
)

var (
	// ErrRateLimited means an uncached request would exceed the process-wide
	// Nominatim request rate. Cache hits do not consume this budget.
	ErrRateLimited = errors.New("location search rate limited")
	// ErrUpstreamUnavailable means Nominatim could not provide a valid bounded
	// response.
	ErrUpstreamUnavailable = errors.New("location search upstream unavailable")
	// ErrUpstreamTimeout means the fixed upstream did not answer in time.
	ErrUpstreamTimeout = errors.New("location search upstream timed out")
)

// Dialer opens one trusted core connection through mihomo's ordinary rules.
type Dialer func(ctx context.Context, host string, port int) (net.Conn, error)

// Searcher is the narrow dependency installed into the controller API.
type Searcher interface {
	Search(ctx context.Context, query, language string) ([]Result, error)
}

// BoundingBox is a WGS-84 extent returned by the fixed geocoder.
type BoundingBox struct {
	South float64 `json:"south"`
	North float64 `json:"north"`
	West  float64 `json:"west"`
	East  float64 `json:"east"`
}

// Result is the deliberately narrow geocoder projection exposed to Console.
type Result struct {
	Label       string      `json:"label"`
	Latitude    float64     `json:"latitude"`
	Longitude   float64     `json:"longitude"`
	BoundingBox BoundingBox `json:"bounding_box"`
}

// RateLimitError carries only the local retry interval, never the search text.
type RateLimitError struct {
	RetryAfter time.Duration
}

func (e *RateLimitError) Error() string { return ErrRateLimited.Error() }
func (e *RateLimitError) Unwrap() error { return ErrRateLimited }

type cacheEntry struct {
	results   []Result
	expiresAt time.Time
}

type searchFlight struct {
	key     [sha256.Size]byte
	done    chan struct{}
	results []Result
	err     error
}

// Service owns one fixed-origin client, a bounded TTL cache, and the
// process-wide public Nominatim rate limit.
type Service struct {
	client *http.Client
	now    func() time.Time

	mu           sync.Mutex
	cache        map[[sha256.Size]byte]cacheEntry
	nextUpstream time.Time
	flight       *searchFlight
}

// New creates a location search service whose only network path is dialer.
// A nil dialer fails closed instead of falling back to the host network.
func New(dialer Dialer) *Service {
	return newService(newHTTPClient(newTransport(dialer)), time.Now)
}

func newService(client *http.Client, now func() time.Time) *Service {
	return &Service{
		client: client,
		now:    now,
		cache:  make(map[[sha256.Size]byte]cacheEntry),
	}
}

func newTransport(dialer Dialer) *http.Transport {
	return &http.Transport{
		Proxy:                  nil,
		DisableCompression:     true,
		DisableKeepAlives:      true,
		MaxConnsPerHost:        1,
		MaxResponseHeaderBytes: 32 << 10,
		ResponseHeaderTimeout:  searchTimeout,
		TLSHandshakeTimeout:    searchTimeout,
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			if network != "tcp" {
				return nil, errors.New("location search transport attempted a non-TCP connection")
			}
			host, port, err := net.SplitHostPort(address)
			if err != nil || !strings.EqualFold(host, nominatimHost) || port != strconv.Itoa(nominatimPort) {
				return nil, errors.New("location search transport attempted a target outside the fixed origin")
			}
			if dialer == nil {
				return nil, errors.New("location search dialer is unavailable")
			}
			return dialer(ctx, nominatimHost, nominatimPort)
		},
	}
}

func newHTTPClient(transport http.RoundTripper) *http.Client {
	return &http.Client{
		Transport: transport,
		Timeout:   searchTimeout,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

// Search returns at most five cached or freshly projected results. The caller
// supplies already validated, normalized input; the fixed endpoint is the only
// URL this service can construct or dial.
func (s *Service) Search(ctx context.Context, query, language string) ([]Result, error) {
	if ctx.Err() != nil {
		return nil, ErrUpstreamTimeout
	}
	key := sha256.Sum256([]byte(strings.ToLower(language) + "\x00" + query))
	now := s.clock()

	s.mu.Lock()
	s.pruneExpiredLocked(now)
	if cached, ok := s.cache[key]; ok {
		results := cloneResults(cached.results)
		s.mu.Unlock()
		return results, nil
	}
	if active := s.flight; active != nil {
		if active.key != key {
			retryAfter := minimumRequestInterval
			if now.Before(s.nextUpstream) {
				retryAfter = s.nextUpstream.Sub(now)
			}
			s.mu.Unlock()
			return nil, &RateLimitError{RetryAfter: retryAfter}
		}
		s.mu.Unlock()
		return waitForFlight(ctx, active)
	}
	if !s.nextUpstream.IsZero() {
		if now.Before(s.nextUpstream) {
			s.mu.Unlock()
			return nil, &RateLimitError{RetryAfter: s.nextUpstream.Sub(now)}
		}
	}
	// Count an attempt when it starts, including an attempt that times out or
	// fails. Retrying a failure immediately would still exceed the public
	// service's one-request-per-second ceiling.
	s.nextUpstream = now.Add(minimumRequestInterval)
	flight := &searchFlight{key: key, done: make(chan struct{})}
	s.flight = flight
	s.mu.Unlock()

	flightContext, cancel := context.WithTimeout(context.Background(), searchTimeout)
	go s.runFlight(flightContext, cancel, flight, query, language)
	return waitForFlight(ctx, flight)
}

func waitForFlight(ctx context.Context, flight *searchFlight) ([]Result, error) {
	select {
	case <-flight.done:
		return cloneResults(flight.results), flight.err
	case <-ctx.Done():
		return nil, ErrUpstreamTimeout
	}
}

func (s *Service) runFlight(ctx context.Context, cancel context.CancelFunc, flight *searchFlight, query, language string) {
	defer cancel()
	results, err := s.fetch(ctx, query, language)

	s.mu.Lock()
	if err == nil {
		now := s.clock()
		s.pruneExpiredLocked(now)
		if len(s.cache) >= maxCacheEntries {
			s.evictLocked()
		}
		s.cache[flight.key] = cacheEntry{results: cloneResults(results), expiresAt: now.Add(cacheTTL)}
	} else {
		var rateLimit *RateLimitError
		if errors.As(err, &rateLimit) && rateLimit.RetryAfter > 0 {
			if next := s.clock().Add(rateLimit.RetryAfter); next.After(s.nextUpstream) {
				s.nextUpstream = next
			}
		}
	}
	flight.results = cloneResults(results)
	flight.err = err
	s.flight = nil
	close(flight.done)
	s.mu.Unlock()
}

func (s *Service) clock() time.Time {
	if s.now != nil {
		return s.now()
	}
	return time.Now()
}

func (s *Service) pruneExpiredLocked(now time.Time) {
	for key, entry := range s.cache {
		if !now.Before(entry.expiresAt) {
			delete(s.cache, key)
		}
	}
}

func (s *Service) evictLocked() {
	var oldestKey [sha256.Size]byte
	var oldestExpiry time.Time
	first := true
	for key, entry := range s.cache {
		if first || entry.expiresAt.Before(oldestExpiry) {
			oldestKey, oldestExpiry, first = key, entry.expiresAt, false
		}
	}
	if !first {
		delete(s.cache, oldestKey)
	}
}

func cloneResults(results []Result) []Result {
	return append([]Result(nil), results...)
}

type nominatimResult struct {
	DisplayName string   `json:"display_name"`
	Latitude    string   `json:"lat"`
	Longitude   string   `json:"lon"`
	BoundingBox []string `json:"boundingbox"`
}

func (s *Service) fetch(ctx context.Context, query, language string) ([]Result, error) {
	endpoint := url.URL{Scheme: "https", Host: nominatimHost, Path: nominatimSearchPath}
	parameters := endpoint.Query()
	parameters.Set("q", query)
	parameters.Set("format", "jsonv2")
	parameters.Set("limit", strconv.Itoa(maxResults))
	parameters.Set("addressdetails", "0")
	parameters.Set("layer", "address")
	parameters.Set("accept-language", language)
	endpoint.RawQuery = parameters.Encode()

	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint.String(), nil)
	if err != nil {
		return nil, ErrUpstreamUnavailable
	}
	// This header set is built from constants and validated input. No incoming
	// controller header, cookie, bearer token, or referrer is ever copied.
	request.Header.Set("Accept", "application/json")
	request.Header.Set("Accept-Encoding", "identity")
	request.Header.Set("Accept-Language", language)
	request.Header.Set("User-Agent", searchUserAgent)

	response, err := s.client.Do(request)
	if err != nil {
		if isTimeout(err) || ctx.Err() != nil {
			return nil, ErrUpstreamTimeout
		}
		return nil, ErrUpstreamUnavailable
	}
	defer response.Body.Close()

	if response.StatusCode == http.StatusTooManyRequests {
		return nil, &RateLimitError{RetryAfter: boundedRetryAfter(response.Header.Get("Retry-After"), s.clock())}
	}
	if response.StatusCode != http.StatusOK {
		return nil, ErrUpstreamUnavailable
	}
	mediaType, _, err := mime.ParseMediaType(response.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/json" {
		return nil, ErrUpstreamUnavailable
	}
	if response.ContentLength > maxResponseBytes {
		return nil, ErrUpstreamUnavailable
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, maxResponseBytes+1))
	if err != nil {
		if isTimeout(err) || ctx.Err() != nil {
			return nil, ErrUpstreamTimeout
		}
		return nil, ErrUpstreamUnavailable
	}
	if len(body) > maxResponseBytes {
		return nil, ErrUpstreamUnavailable
	}

	if !utf8.Valid(body) {
		return nil, ErrUpstreamUnavailable
	}
	trimmedBody := bytes.TrimSpace(body)
	if len(trimmedBody) == 0 || trimmedBody[0] != '[' {
		return nil, ErrUpstreamUnavailable
	}
	var upstream []nominatimResult
	decoder := json.NewDecoder(bytes.NewReader(trimmedBody))
	if err := decoder.Decode(&upstream); err != nil {
		return nil, ErrUpstreamUnavailable
	}
	if err := requireJSONEOF(decoder); err != nil {
		return nil, ErrUpstreamUnavailable
	}

	results := make([]Result, 0, min(len(upstream), maxResults))
	for _, raw := range upstream {
		projected, ok := projectResult(raw)
		if !ok {
			continue
		}
		results = append(results, projected)
		if len(results) == maxResults {
			break
		}
	}
	if len(upstream) != 0 && len(results) == 0 {
		return nil, ErrUpstreamUnavailable
	}
	return results, nil
}

func boundedRetryAfter(raw string, now time.Time) time.Duration {
	requested := time.Duration(0)
	if seconds, err := strconv.ParseInt(strings.TrimSpace(raw), 10, 64); err == nil && seconds > 0 {
		if seconds >= int64(maximumUpstreamBackoff/time.Second) {
			return maximumUpstreamBackoff
		}
		requested = time.Duration(seconds) * time.Second
	} else if when, err := http.ParseTime(strings.TrimSpace(raw)); err == nil && when.After(now) {
		requested = when.Sub(now)
	}
	if requested < defaultUpstreamBackoff {
		return defaultUpstreamBackoff
	}
	if requested > maximumUpstreamBackoff {
		return maximumUpstreamBackoff
	}
	return requested
}

func requireJSONEOF(decoder *json.Decoder) error {
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("multiple JSON values")
		}
		return err
	}
	return nil
}

func projectResult(raw nominatimResult) (Result, bool) {
	label := strings.TrimSpace(raw.DisplayName)
	if label == "" || len(label) > maxResultLabelBytes || !utf8.ValidString(label) || containsControl(label) || len(raw.BoundingBox) != 4 {
		return Result{}, false
	}
	latitude, ok := coordinate(raw.Latitude, -90, 90)
	if !ok {
		return Result{}, false
	}
	longitude, ok := coordinate(raw.Longitude, -180, 180)
	if !ok {
		return Result{}, false
	}
	south, ok := coordinate(raw.BoundingBox[0], -90, 90)
	if !ok {
		return Result{}, false
	}
	north, ok := coordinate(raw.BoundingBox[1], -90, 90)
	if !ok {
		return Result{}, false
	}
	west, ok := coordinate(raw.BoundingBox[2], -180, 180)
	if !ok {
		return Result{}, false
	}
	east, ok := coordinate(raw.BoundingBox[3], -180, 180)
	if !ok || south > north || west > east {
		return Result{}, false
	}
	return Result{
		Label:     label,
		Latitude:  latitude,
		Longitude: longitude,
		BoundingBox: BoundingBox{
			South: south,
			North: north,
			West:  west,
			East:  east,
		},
	}, true
}

func containsControl(value string) bool {
	for _, character := range value {
		if unicode.IsControl(character) {
			return true
		}
	}
	return false
}

func coordinate(raw string, minimum, maximum float64) (float64, bool) {
	value, err := strconv.ParseFloat(strings.TrimSpace(raw), 64)
	return value, err == nil && !math.IsNaN(value) && !math.IsInf(value, 0) && value >= minimum && value <= maximum
}

func isTimeout(err error) bool {
	if errors.Is(err, context.DeadlineExceeded) {
		return true
	}
	var timeout interface{ Timeout() bool }
	return errors.As(err, &timeout) && timeout.Timeout()
}
