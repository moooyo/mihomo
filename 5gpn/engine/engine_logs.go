package engine

import (
	"encoding/json"
	"errors"
	"math"
	"net/url"
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

type EngineLog struct {
	Time         string  `json:"time"`
	Level        string  `json:"level"`
	Source       string  `json:"source"`
	Extension    string  `json:"extension,omitempty"`
	Action       string  `json:"action,omitempty"`
	Phase        string  `json:"phase,omitempty"`
	DurationMS   float64 `json:"duration_ms,omitempty"`
	URL          string  `json:"url,omitempty"`
	ScriptDigest string  `json:"script_digest,omitempty"`
	Message      string  `json:"message"`
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
	mu      sync.Mutex
	ring    [][]byte
	next    uint64
	closed  bool
	now     func() time.Time
	dropped atomic.Uint64
}

// Dropped reports how many events this hub refused.
func (h *engineLogHub) Dropped() uint64 { return h.dropped.Load() }

func newEngineLogHub(capacity int) *engineLogHub {
	if capacity <= 0 || capacity > engineLogRingCapacity {
		capacity = engineLogRingCapacity
	}
	return &engineLogHub{
		ring: make([][]byte, capacity),
		now:  time.Now,
	}
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
	payload, err := json.Marshal(normalized)
	if err != nil || len(payload) > maxEngineLogJSONBytes {
		h.dropped.Add(1)
		return
	}

	h.mu.Lock()
	defer h.mu.Unlock()
	if h.closed {
		return
	}
	sequence := h.next
	h.ring[sequence%uint64(len(h.ring))] = payload
	h.next++
}

// EngineLogFilter narrows a snapshot. A zero value matches everything.
type EngineLogFilter struct {
	// Extension matches EngineLog.Extension exactly. Empty matches any.
	Extension string
	// Level matches EngineLog.Level exactly. Empty matches any.
	Level string
	// Contains matches Message case-insensitively. Empty matches any.
	Contains string
	// Limit caps the returned events. Zero or negative means the whole ring.
	Limit int
}

// Snapshot returns retained events oldest first, which is the order a log is
// read in.
//
// It unmarshals from the retained ring rather than keeping a second copy of
// every event in struct form. A snapshot is taken when a human presses refresh;
// paying the decode there is cheaper than paying the memory always.
func (h *engineLogHub) Snapshot(filter EngineLogFilter) []EngineLog {
	if h == nil {
		return nil
	}
	h.mu.Lock()
	size := uint64(len(h.ring))
	next := h.next
	payloads := make([][]byte, 0, size)
	if size > 0 {
		first := uint64(0)
		if next > size {
			first = next - size
		}
		for sequence := first; sequence < next; sequence++ {
			if payload := h.ring[sequence%size]; payload != nil {
				payloads = append(payloads, payload)
			}
		}
	}
	h.mu.Unlock()

	want := strings.ToLower(filter.Contains)
	out := make([]EngineLog, 0, len(payloads))
	for _, payload := range payloads {
		var event EngineLog
		if err := json.Unmarshal(payload, &event); err != nil {
			continue
		}
		if filter.Extension != "" && event.Extension != filter.Extension {
			continue
		}
		if filter.Level != "" && event.Level != filter.Level {
			continue
		}
		if want != "" && !strings.Contains(strings.ToLower(event.Message), want) {
			continue
		}
		out = append(out, event)
	}
	// Trim from the FRONT: a limit on a log means "the most recent N", and
	// dropping the newest would answer a different question.
	if filter.Limit > 0 && len(out) > filter.Limit {
		out = out[len(out)-filter.Limit:]
	}
	return out
}

func normalizeEngineLog(event EngineLog, now time.Time) (EngineLog, error) {
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
