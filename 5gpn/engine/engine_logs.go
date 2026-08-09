package engine

import (
	cryptorand "crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode/utf8"
)

const (
	engineLogRingCapacity    = 1000
	maxEngineLogMessageBytes = 2048
	maxEngineLogURLBytes     = 4096
	maxEngineLogJSONBytes    = 8 << 10
)

// EngineLogMaxLimit is the maximum number of retained events one API response
// can carry. It is the ring capacity, so increasing a request limit can never
// turn this memory-only diagnostic surface into an unbounded response.
const EngineLogMaxLimit = engineLogRingCapacity

// EngineLogCursor is a uint64 internally and a canonical decimal string on the
// wire. JavaScript cannot exactly represent every uint64 as a number, while a
// cursor is opaque to the Console and needs no arithmetic there.
type EngineLogCursor uint64

func (c EngineLogCursor) MarshalJSON() ([]byte, error) {
	return json.Marshal(strconv.FormatUint(uint64(c), 10))
}

func (c *EngineLogCursor) UnmarshalJSON(body []byte) error {
	var raw string
	if err := json.Unmarshal(body, &raw); err != nil {
		return errors.New("engine log cursor must be a decimal string")
	}
	value, err := parseEngineLogCursor(raw)
	if err != nil {
		return err
	}
	*c = EngineLogCursor(value)
	return nil
}

func parseEngineLogCursor(raw string) (uint64, error) {
	if raw == "0" {
		return 0, nil
	}
	if raw == "" || raw[0] < '1' || raw[0] > '9' {
		return 0, errors.New("engine log cursor must be a canonical decimal string")
	}
	for index := 1; index < len(raw); index++ {
		if raw[index] < '0' || raw[index] > '9' {
			return 0, errors.New("engine log cursor must be a canonical decimal string")
		}
	}
	value, err := strconv.ParseUint(raw, 10, 64)
	if err != nil {
		return 0, errors.New("engine log cursor is out of range")
	}
	return value, nil
}

type EngineLog struct {
	Seq          EngineLogCursor `json:"seq"`
	Time         string          `json:"time"`
	Level        string          `json:"level"`
	Source       string          `json:"source"`
	Extension    string          `json:"extension,omitempty"`
	Action       string          `json:"action,omitempty"`
	Phase        string          `json:"phase,omitempty"`
	DurationMS   float64         `json:"duration_ms,omitempty"`
	URL          string          `json:"url,omitempty"`
	ScriptDigest string          `json:"script_digest,omitempty"`
	Message      string          `json:"message"`
}

type engineLogPublisher interface {
	Enabled() bool
	Publish(EngineLog)
	// Dropped counts events this publisher refused.
	//
	// Publish returns nothing, so a producer and the validator disagreeing about
	// a field is indistinguishable from an idle engine. That is not
	// hypothetical: bundle_manager's eight lifecycle messages declared a source
	// the validator does not accept and were discarded, and since that file
	// imports no logging package they were not going to stderr either. A
	// non-zero count here is always a build-time mistake, never a runtime
	// condition.
	Dropped() uint64
}

func engineLogPublishingEnabled(publisher engineLogPublisher) bool {
	return publisher != nil && publisher.Enabled()
}

type engineLogHub struct {
	mu       sync.Mutex
	ring     [][]byte
	next     uint64
	streamID string
	closed   bool
	now      func() time.Time
	dropped  atomic.Uint64
}

var engineLogStreamFallback atomic.Uint64

// Dropped reports how many events this hub refused.
func (h *engineLogHub) Dropped() uint64 { return h.dropped.Load() }

func newEngineLogHub(capacity int) *engineLogHub {
	return newEngineLogHubWithEntropy(capacity, cryptorand.Reader)
}

func newEngineLogHubWithEntropy(capacity int, entropy io.Reader) *engineLogHub {
	if capacity <= 0 || capacity > engineLogRingCapacity {
		capacity = engineLogRingCapacity
	}
	return &engineLogHub{
		ring:     make([][]byte, capacity),
		streamID: newEngineLogStreamID(entropy),
		now:      time.Now,
	}
}

func newEngineLogStreamID(entropy io.Reader) string {
	var random [16]byte
	if entropy != nil {
		if _, err := io.ReadFull(entropy, random[:]); err == nil {
			return hex.EncodeToString(random[:])
		}
	}
	// stream_id is an opaque generation marker, not a credential. If OS entropy
	// is unavailable, time, process identity and a process-local counter still
	// keep independently created rings distinguishable without making engine
	// construction fall back to an empty or reusable identifier.
	counter := engineLogStreamFallback.Add(1)
	seed := fmt.Sprintf("%d:%d:%d", time.Now().UnixNano(), os.Getpid(), counter)
	digest := sha256.Sum256([]byte(seed))
	return hex.EncodeToString(digest[:16])
}

// Enabled reports whether events are worth building. The bounded ring is
// always active so failures are retained before an operator opens the log.
func (h *engineLogHub) Enabled() bool {
	return h != nil
}

func (h *engineLogHub) Publish(event EngineLog) {
	if h == nil {
		return
	}
	h.mu.Lock()
	if h.closed {
		h.mu.Unlock()
		return
	}
	now := h.now
	h.mu.Unlock()

	normalized, err := normalizeEngineLog(event, now().UTC())
	if err != nil {
		h.dropped.Add(1)
		return
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.closed {
		return
	}
	sequence := h.next + 1
	normalized.Seq = EngineLogCursor(sequence)
	payload, err := json.Marshal(normalized)
	if err != nil || len(payload) > maxEngineLogJSONBytes {
		h.dropped.Add(1)
		return
	}
	h.ring[(sequence-1)%uint64(len(h.ring))] = payload
	h.next = sequence
}

// EngineLogQuery narrows a snapshot and optionally continues one stream.
type EngineLogQuery struct {
	// Extension matches EngineLog.Extension exactly. Empty matches any.
	Extension string
	// Level matches EngineLog.Level exactly. Empty matches any.
	Level string
	// Contains matches Message case-insensitively. Empty matches any.
	Contains string
	// Limit caps the returned events. Zero or negative means the whole ring.
	Limit int
	// StreamID and After form one cursor. After is exclusive. A nil After is an
	// initial tail read, while a non-nil value requests forward pagination.
	StreamID string
	After    *uint64
}

// EngineLogPage is one immutable view of the ring.
type EngineLogPage struct {
	Logs      []EngineLog     `json:"logs"`
	StreamID  string          `json:"stream_id"`
	OldestSeq EngineLogCursor `json:"oldest_seq"`
	LatestSeq EngineLogCursor `json:"latest_seq"`
	// Dropped counts sequence numbers that a same-stream cursor missed because
	// the ring overwrote them. Cross-stream loss is unknowable and is reported
	// by Reset instead.
	Dropped EngineLogCursor `json:"dropped"`
	Reset   bool            `json:"reset"`
}

// Snapshot returns retained events oldest first. Initial and reset reads keep
// the most recent limit; a valid cursor reads forward from after and stops at
// the first limit matching events so filtered pagination cannot skip a match.
//
// It unmarshals from the retained ring rather than keeping a second copy of
// every event in struct form. A snapshot is taken when a human presses refresh;
// paying the decode there is cheaper than paying the memory always.
func (h *engineLogHub) Snapshot(query EngineLogQuery) EngineLogPage {
	page := EngineLogPage{Logs: make([]EngineLog, 0)}
	if h == nil {
		return page
	}
	h.mu.Lock()
	size := uint64(len(h.ring))
	page.StreamID = h.streamID
	page.LatestSeq = EngineLogCursor(h.next)
	retained := uint64(page.LatestSeq)
	if retained > size {
		retained = size
	}
	if retained > 0 {
		page.OldestSeq = EngineLogCursor(uint64(page.LatestSeq) - retained + 1)
	}
	incremental := query.After != nil
	if incremental && (query.StreamID == "" || query.StreamID != page.StreamID || *query.After > uint64(page.LatestSeq)) {
		page.Reset = true
		incremental = false
	}
	first := uint64(page.OldestSeq)
	if incremental && page.OldestSeq > 0 {
		expected := *query.After + 1
		if expected < uint64(page.OldestSeq) {
			page.Dropped = EngineLogCursor(uint64(page.OldestSeq) - expected)
		} else {
			first = expected
		}
	}
	payloads := make([][]byte, 0, size)
	if first > 0 && first <= uint64(page.LatestSeq) {
		for sequence := first; sequence <= uint64(page.LatestSeq); sequence++ {
			if payload := h.ring[(sequence-1)%size]; payload != nil {
				payloads = append(payloads, payload)
			}
		}
	}
	h.mu.Unlock()

	limit := query.Limit
	if limit <= 0 || limit > engineLogRingCapacity {
		limit = engineLogRingCapacity
	}
	want := strings.ToLower(query.Contains)
	out := make([]EngineLog, 0, len(payloads))
	for _, payload := range payloads {
		var event EngineLog
		if err := json.Unmarshal(payload, &event); err != nil {
			continue
		}
		if query.Extension != "" && event.Extension != query.Extension {
			continue
		}
		if query.Level != "" && event.Level != query.Level {
			continue
		}
		if want != "" && !strings.Contains(strings.ToLower(event.Message), want) {
			continue
		}
		out = append(out, event)
		if incremental && len(out) == limit {
			break
		}
	}
	if !incremental && len(out) > limit {
		out = out[len(out)-limit:]
	}
	page.Logs = out
	return page
}

func normalizeEngineLog(event EngineLog, now time.Time) (EngineLog, error) {
	event.Seq = 0
	switch event.Level {
	case "info", "warn", "error":
	default:
		return EngineLog{}, errors.New("invalid engine log level")
	}
	switch event.Source {
	case "script", "engine":
	default:
		return EngineLog{}, errors.New("invalid engine log source")
	}
	if event.Extension != "" && !validModuleID(event.Extension) {
		return EngineLog{}, errors.New("invalid engine log extension")
	}
	if event.Action != "" && !validSettingKey(event.Action) {
		return EngineLog{}, errors.New("invalid engine log action")
	}
	if event.Source == "script" && (event.Extension == "" || event.Action == "") {
		return EngineLog{}, errors.New("script log is missing its extension or action")
	}
	if event.Phase != "" && event.Phase != "request" && event.Phase != "response" {
		return EngineLog{}, errors.New("invalid engine log phase")
	}
	if event.ScriptDigest != "" && !validEngineLogDigest(event.ScriptDigest) {
		return EngineLog{}, errors.New("invalid engine log script digest")
	}
	if math.IsNaN(event.DurationMS) || math.IsInf(event.DurationMS, 0) || event.DurationMS < 0 {
		return EngineLog{}, errors.New("invalid engine log duration")
	}
	if event.DurationMS > 300000 {
		event.DurationMS = 300000
	}
	event.Time = now.Format(time.RFC3339Nano)
	event.URL = sanitizeEngineLogURL(event.URL)
	event.Message = truncateEngineLogField(event.Message, maxEngineLogMessageBytes)
	return event, nil
}

func sanitizeEngineLogURL(raw string) string {
	if raw == "" {
		return ""
	}
	raw = truncateEngineLogField(raw, maxEngineLogURLBytes)
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return ""
	}
	parsed.User = nil
	parsed.RawQuery = ""
	parsed.ForceQuery = false
	parsed.Fragment = ""
	parsed.RawFragment = ""
	return truncateEngineLogField(parsed.String(), maxEngineLogURLBytes)
}

func validEngineLogDigest(value string) bool {
	if len(value) != 64 {
		return false
	}
	for _, item := range value {
		if (item < '0' || item > '9') && (item < 'a' || item > 'f') {
			return false
		}
	}
	return true
}

func truncateEngineLogField(value string, limit int) string {
	if limit <= 0 {
		return ""
	}
	truncated := len(value) > limit
	if truncated && limit <= 3 {
		return strings.Repeat(".", limit)
	}
	budget := limit
	if truncated {
		budget -= 3
	}
	if len(value) > budget {
		value = value[:budget]
	}
	value = strings.ToValidUTF8(value, "�")
	if len(value) > budget {
		value = value[:budget]
	}
	prefix := value
	for len(prefix) > 0 && !utf8.ValidString(prefix) {
		prefix = prefix[:len(prefix)-1]
	}
	if truncated {
		return prefix + "..."
	}
	return prefix
}

func (h *engineLogHub) Close() {
	if h == nil {
		return
	}
	h.mu.Lock()
	h.closed = true
	h.mu.Unlock()
}
