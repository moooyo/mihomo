package dns

import (
	"net"
	"strings"
	"sync"
	"time"

	D "github.com/miekg/dns"
)

// The query log is a small in-memory ring with a short retention window, served
// to the console so an operator can answer "what just resolved on this box, and
// why did it get that verdict".
//
// Deliberately ephemeral: nothing is written to disk and a restart empties it.
// Its job is "just now", not analytics, and a resolver's query stream is the
// most sensitive thing this process sees -- keeping it in memory means it is
// not sitting in a journal after the question that prompted it was answered.
const (
	// queryLogCapacity bounds the ring regardless of QPS. At about 27 queries a
	// second the window still covers the full retention period; above that the
	// oldest entries rotate out early, which is the right trade -- memory stays
	// fixed under a flood.
	queryLogCapacity = 8192

	queryLogRetention = 5 * time.Minute

	// queryLogMaxIPs caps the addresses stored per entry, so one pathological
	// answer cannot make an entry unbounded.
	queryLogMaxIPs = 8
)

// QueryLogEntry is one resolved query as the API reports it.
type QueryLogEntry struct {
	Time       time.Time `json:"time"`
	Client     string    `json:"client,omitempty"`
	Name       string    `json:"name"`
	Qtype      string    `json:"qtype"`
	Verdict    string    `json:"verdict,omitempty"`
	Reason     string    `json:"reason,omitempty"`
	Upstream   string    `json:"upstream,omitempty"`
	CacheHit   bool      `json:"cacheHit"`
	Rcode      string    `json:"rcode"`
	IPs        []string  `json:"ips,omitempty"`
	DurationMs float64   `json:"durationMs"`
}

// queryLog is a fixed-capacity ring with retention applied on read. add runs on
// the hot path and costs one lock and one slot write.
type queryLog struct {
	mu        sync.Mutex
	buf       []QueryLogEntry
	next      int
	filled    bool
	retention time.Duration
}

func newQueryLog(capacity int, retention time.Duration) *queryLog {
	if capacity <= 0 {
		capacity = queryLogCapacity
	}
	if retention <= 0 {
		retention = queryLogRetention
	}
	return &queryLog{buf: make([]QueryLogEntry, capacity), retention: retention}
}

func (l *queryLog) add(e QueryLogEntry) {
	if l == nil {
		return
	}
	l.mu.Lock()
	l.buf[l.next] = e
	l.next++
	if l.next == len(l.buf) {
		l.next = 0
		l.filled = true
	}
	l.mu.Unlock()
}

// search returns up to limit entries inside the retention window, newest first,
// whose name or client contains q case-insensitively. An empty q matches
// everything.
func (l *queryLog) search(q string, limit int, now time.Time) []QueryLogEntry {
	if l == nil {
		return nil
	}
	if limit <= 0 {
		limit = 200
	}
	q = strings.ToLower(strings.TrimSpace(q))
	cutoff := now.Add(-l.retention)

	l.mu.Lock()
	defer l.mu.Unlock()

	n := l.next
	if l.filled {
		n = len(l.buf)
	}
	out := make([]QueryLogEntry, 0, min(limit, n))
	for i := 0; i < n && len(out) < limit; i++ {
		idx := l.next - 1 - i
		if idx < 0 {
			idx += len(l.buf)
		}
		e := l.buf[idx]
		if e.Time.Before(cutoff) {
			// The ring is in time order, so everything behind this is older.
			break
		}
		if q != "" &&
			!strings.Contains(strings.ToLower(e.Name), q) &&
			!strings.Contains(strings.ToLower(e.Client), q) {
			continue
		}
		out = append(out, e)
	}
	return out
}

// clientHost extracts the client address without its port. Nil-safe, because
// test writers and the in-process origin resolver have no remote address.
func clientHost(w D.ResponseWriter) string {
	if w == nil {
		return ""
	}
	ra := w.RemoteAddr()
	if ra == nil {
		return ""
	}
	if host, _, err := net.SplitHostPort(ra.String()); err == nil {
		return host
	}
	return ra.String()
}

// answerIPs returns up to max A addresses from the answer section.
func answerIPs(resp *D.Msg, max int) []string {
	if resp == nil {
		return nil
	}
	var ips []string
	for _, rr := range resp.Answer {
		if a, ok := rr.(*D.A); ok {
			ips = append(ips, a.A.String())
			if len(ips) == max {
				break
			}
		}
	}
	return ips
}
