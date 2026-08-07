package api

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/metacubex/chi/render"
	"github.com/metacubex/http"
	"github.com/metacubex/mihomo/5gpn/location"
	"golang.org/x/text/language"
)

const (
	maxLocationSearchRequestBytes = 1 << 10
	maxLocationSearchQueryBytes   = 256
	maxLocationSearchQueryRunes   = 128
	maxLocationLanguageBytes      = 32
	maxLocationSearchResults      = 5
	locationSearchRequestTimeout  = 10 * time.Second
	maxLocationRetryAfter         = 24 * time.Hour
)

var locationSearch struct {
	searcher location.Searcher
}

// SetLocationSearcher installs the fixed-origin geocoder used by the
// authenticated interception API. Passing nil withdraws it.
func SetLocationSearcher(searcher location.Searcher) {
	mu.Lock()
	defer mu.Unlock()
	locationSearch.searcher = searcher
}

func currentLocationSearcher() location.Searcher {
	mu.RLock()
	defer mu.RUnlock()
	return locationSearch.searcher
}

type locationSearchRequest struct {
	Query    string `json:"query"`
	Language string `json:"language"`
}

type locationSearchResponse struct {
	Results []location.Result `json:"results"`
}

func postLocationSearch(w http.ResponseWriter, r *http.Request) {
	if r.URL.RawQuery != "" {
		writeLocationSearchError(w, r, http.StatusBadRequest, "invalid_request", "URL query parameters are not supported; send the search request as JSON")
		return
	}
	body, ok := decodeLocationSearchRequest(w, r)
	if !ok {
		return
	}
	query, ok := normalizeLocationSearchQuery(w, r, body.Query)
	if !ok {
		return
	}
	language, ok := normalizeLocationSearchLanguage(w, r, body.Language)
	if !ok {
		return
	}
	if currentEngine() == nil {
		writeLocationSearchError(w, r, http.StatusServiceUnavailable, "search_unavailable", "the interception engine is not installed")
		return
	}

	searcher := currentLocationSearcher()
	if searcher == nil {
		writeLocationSearchError(w, r, http.StatusServiceUnavailable, "search_unavailable", "location search is not installed")
		return
	}
	ctx, cancel := contextWithTimeout(r, locationSearchRequestTimeout)
	defer cancel()
	results, err := searcher.Search(ctx, query, language)
	if err != nil {
		writeLocationSearcherError(w, r, err)
		return
	}
	if results == nil {
		results = []location.Result{}
	} else if len(results) > maxLocationSearchResults {
		results = results[:maxLocationSearchResults]
	}
	render.JSON(w, r, locationSearchResponse{Results: results})
}

func decodeLocationSearchRequest(w http.ResponseWriter, r *http.Request) (locationSearchRequest, bool) {
	mediaType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/json" {
		writeLocationSearchError(w, r, http.StatusUnsupportedMediaType, "unsupported_media_type", "Content-Type must be application/json")
		return locationSearchRequest{}, false
	}
	raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxLocationSearchRequestBytes))
	if err != nil {
		writeLocationDecodeError(w, r, err)
		return locationSearchRequest{}, false
	}
	if !utf8.Valid(raw) {
		writeLocationSearchError(w, r, http.StatusBadRequest, "invalid_request", "request body must contain valid UTF-8 JSON")
		return locationSearchRequest{}, false
	}
	body, err := parseLocationSearchRequest(raw)
	if err != nil {
		writeLocationDecodeError(w, r, err)
		return locationSearchRequest{}, false
	}
	return body, true
}

func parseLocationSearchRequest(raw []byte) (locationSearchRequest, error) {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	opening, err := decoder.Token()
	if err != nil || opening != json.Delim('{') {
		return locationSearchRequest{}, errors.New("request must be a JSON object")
	}
	seen := make(map[string]struct{}, 2)
	var request locationSearchRequest
	for decoder.More() {
		token, err := decoder.Token()
		if err != nil {
			return locationSearchRequest{}, err
		}
		key, ok := token.(string)
		if !ok || key != "query" && key != "language" {
			return locationSearchRequest{}, errors.New("request contains an unsupported field")
		}
		if _, duplicate := seen[key]; duplicate {
			return locationSearchRequest{}, errors.New("request contains a duplicate field")
		}
		seen[key] = struct{}{}
		var encoded json.RawMessage
		if err := decoder.Decode(&encoded); err != nil {
			return locationSearchRequest{}, err
		}
		value, err := decodeStrictJSONString(encoded)
		if err != nil {
			return locationSearchRequest{}, err
		}
		if key == "query" {
			request.Query = value
		} else {
			request.Language = value
		}
	}
	closing, err := decoder.Token()
	if err != nil || closing != json.Delim('}') {
		return locationSearchRequest{}, errors.New("request must be a JSON object")
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return locationSearchRequest{}, errors.New("request body must contain exactly one JSON object")
	}
	return request, nil
}

func decodeStrictJSONString(raw json.RawMessage) (string, error) {
	raw = bytes.TrimSpace(raw)
	if len(raw) < 2 || raw[0] != '"' || raw[len(raw)-1] != '"' || !validJSONSurrogates(raw) {
		return "", errors.New("request fields must be valid Unicode strings")
	}
	var value string
	if err := json.Unmarshal(raw, &value); err != nil {
		return "", errors.New("request fields must be valid Unicode strings")
	}
	return value, nil
}

func validJSONSurrogates(raw []byte) bool {
	end := len(raw) - 1
	for index := 1; index < end; {
		if raw[index] != '\\' {
			index++
			continue
		}
		if index+1 >= end {
			return false
		}
		if raw[index+1] != 'u' {
			index += 2
			continue
		}
		codepoint, ok := jsonHexCodepoint(raw, index, end)
		if !ok {
			return false
		}
		if codepoint >= 0xDC00 && codepoint <= 0xDFFF {
			return false
		}
		if codepoint < 0xD800 || codepoint > 0xDBFF {
			index += 6
			continue
		}
		next := index + 6
		if next+1 >= end || raw[next] != '\\' || raw[next+1] != 'u' {
			return false
		}
		low, ok := jsonHexCodepoint(raw, next, end)
		if !ok || low < 0xDC00 || low > 0xDFFF {
			return false
		}
		index = next + 6
	}
	return true
}

func jsonHexCodepoint(raw []byte, slash, end int) (uint16, bool) {
	if slash+6 > end {
		return 0, false
	}
	value, err := strconv.ParseUint(string(raw[slash+2:slash+6]), 16, 16)
	return uint16(value), err == nil
}

func writeLocationDecodeError(w http.ResponseWriter, r *http.Request, err error) {
	var tooLarge *http.MaxBytesError
	if errors.As(err, &tooLarge) {
		writeLocationSearchError(w, r, http.StatusRequestEntityTooLarge, "request_too_large", "location search request exceeds 1024 bytes")
		return
	}
	writeLocationSearchError(w, r, http.StatusBadRequest, "invalid_request", "request body must be a valid JSON object containing only query and language")
}

func normalizeLocationSearchQuery(w http.ResponseWriter, r *http.Request, raw string) (string, bool) {
	for _, value := range raw {
		if unicode.IsControl(value) {
			writeLocationSearchError(w, r, http.StatusBadRequest, "invalid_query", "query must not contain control characters")
			return "", false
		}
	}
	query := strings.Join(strings.Fields(raw), " ")
	if query == "" {
		writeLocationSearchError(w, r, http.StatusBadRequest, "invalid_query", "query is required")
		return "", false
	}
	if !utf8.ValidString(query) || len(query) > maxLocationSearchQueryBytes || utf8.RuneCountInString(query) > maxLocationSearchQueryRunes {
		writeLocationSearchError(w, r, http.StatusBadRequest, "invalid_query", "query must not exceed 256 bytes or 128 characters")
		return "", false
	}
	return query, true
}

func normalizeLocationSearchLanguage(w http.ResponseWriter, r *http.Request, raw string) (string, bool) {
	languageText := strings.TrimSpace(raw)
	if languageText == "" {
		return "en", true
	}
	if len(languageText) > maxLocationLanguageBytes || !usesBCP47TagCharacters(languageText) {
		writeLocationSearchError(w, r, http.StatusBadRequest, "invalid_language", "language must be one BCP 47 language tag of at most 32 bytes")
		return "", false
	}
	tag, err := language.Parse(languageText)
	if err != nil {
		writeLocationSearchError(w, r, http.StatusBadRequest, "invalid_language", "language must be one BCP 47 language tag of at most 32 bytes")
		return "", false
	}
	canonical := tag.String()
	if canonical == "" || len(canonical) > maxLocationLanguageBytes {
		writeLocationSearchError(w, r, http.StatusBadRequest, "invalid_language", "language must be one BCP 47 language tag of at most 32 bytes")
		return "", false
	}
	return canonical, true
}

func usesBCP47TagCharacters(value string) bool {
	for index := 0; index < len(value); index++ {
		character := value[index]
		if character >= 'a' && character <= 'z' || character >= 'A' && character <= 'Z' ||
			character >= '0' && character <= '9' || character == '-' {
			continue
		}
		return false
	}
	return true
}

func writeLocationSearcherError(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, location.ErrRateLimited):
		retryAfter := time.Second
		var rateLimit *location.RateLimitError
		if errors.As(err, &rateLimit) && rateLimit.RetryAfter > 0 {
			retryAfter = rateLimit.RetryAfter
		}
		if retryAfter > maxLocationRetryAfter {
			retryAfter = maxLocationRetryAfter
		}
		seconds := int64((retryAfter-time.Nanosecond)/time.Second) + 1
		w.Header().Set("Retry-After", strconv.FormatInt(seconds, 10))
		writeLocationSearchError(w, r, http.StatusTooManyRequests, "rate_limited", "location search is rate limited; retry later")
	case errors.Is(err, location.ErrUpstreamTimeout):
		writeLocationSearchError(w, r, http.StatusGatewayTimeout, "upstream_timeout", "location search upstream timed out")
	default:
		writeLocationSearchError(w, r, http.StatusBadGateway, "upstream_unavailable", "location search upstream is unavailable")
	}
}

func writeLocationSearchError(w http.ResponseWriter, r *http.Request, status int, code, message string) {
	render.Status(r, status)
	render.JSON(w, r, render.M{"code": code, "message": message})
}
