package engine

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

// The log has to exist before anyone looks at it.
//
// Enabled gates whether the runtime builds an event at all. The bounded ring
// stays enabled before any read because an operator opens the log only after
// something breaks. The console then reads the retained snapshot.
func TestEngineLogsRetainBeforeRead(t *testing.T) {
	t.Parallel()

	hub := newEngineLogHub(8)
	defer hub.Close()

	if !hub.Enabled() {
		t.Fatal("the hub reports disabled before a read; scripts would emit nothing")
	}

	// A script event carries its extension and its action; the engine validates
	// both, so a test that skips them is testing the validator, not the ring.
	hub.Publish(EngineLog{Level: "info", Source: "script", Extension: "io.example.one", Action: "rewrite", Message: "hello"})
	hub.Publish(EngineLog{Level: "warn", Source: "script", Extension: "io.example.two", Action: "rewrite", Message: "careful"})

	page := hub.Snapshot(EngineLogQuery{})
	got := page.Logs
	if len(got) != 2 {
		t.Fatalf("retained %d events with nobody subscribed, want 2", len(got))
	}
	if got[0].Message != "hello" || got[1].Message != "careful" {
		t.Errorf("snapshot is not oldest-first: %+v", got)
	}
	for _, event := range got {
		if event.Seq == 0 || event.Time == "" {
			t.Errorf("event has no timestamp: %+v", event)
		}
	}
	if page.StreamID == "" || page.OldestSeq != 1 || page.LatestSeq != 2 || page.Reset || page.Dropped != 0 {
		t.Errorf("initial cursor page = %+v", page)
	}
}

// A limit on a log means the most recent N. Trimming the other end would answer
// a different question, and the ring itself must drop the oldest, not refuse
// the newest.
func TestEngineLogsKeepTheNewest(t *testing.T) {
	t.Parallel()

	hub := newEngineLogHub(4)
	defer hub.Close()

	for i := range 10 {
		hub.Publish(EngineLog{
			Level:   "info",
			Source:  "engine",
			Message: string(rune('a' + i)),
		})
	}

	allPage := hub.Snapshot(EngineLogQuery{})
	all := allPage.Logs
	if len(all) != 4 {
		t.Fatalf("ring of 4 retained %d events", len(all))
	}
	if all[len(all)-1].Message != "j" {
		t.Errorf("newest event is %q, want the last one published", all[len(all)-1].Message)
	}
	if all[0].Message != "g" {
		t.Errorf("oldest retained is %q; the ring dropped the wrong end", all[0].Message)
	}

	limited := hub.Snapshot(EngineLogQuery{Limit: 2}).Logs
	if len(limited) != 2 || limited[1].Message != "j" {
		t.Errorf("limit did not keep the most recent: %+v", limited)
	}
}

func TestEngineLogFilters(t *testing.T) {
	t.Parallel()

	hub := newEngineLogHub(16)
	defer hub.Close()

	hub.Publish(EngineLog{Level: "info", Source: "script", Extension: "one", Action: "rewrite", Message: "alpha ready"})
	hub.Publish(EngineLog{Level: "error", Source: "script", Extension: "one", Action: "rewrite", Message: "BETA failed"})
	hub.Publish(EngineLog{Level: "info", Source: "script", Extension: "two", Action: "rewrite", Message: "alpha ready"})

	if got := hub.Snapshot(EngineLogQuery{Extension: "one"}).Logs; len(got) != 2 {
		t.Errorf("extension filter returned %d, want 2", len(got))
	}
	if got := hub.Snapshot(EngineLogQuery{Level: "error"}).Logs; len(got) != 1 {
		t.Errorf("level filter returned %d, want 1", len(got))
	}
	// Case-insensitive, because an operator searching a log types what they
	// remember, not what the script happened to capitalise.
	if got := hub.Snapshot(EngineLogQuery{Contains: "beta"}).Logs; len(got) != 1 {
		t.Errorf("message filter is case sensitive: %d matches for \"beta\"", len(got))
	}
	if got := hub.Snapshot(EngineLogQuery{Extension: "one", Level: "info"}).Logs; len(got) != 1 {
		t.Errorf("combined filters returned %d, want 1", len(got))
	}
}

// A closed hub must not retain or panic: shutdown races with a script that is
// still finishing.
func TestEngineLogsAfterClose(t *testing.T) {
	t.Parallel()

	hub := newEngineLogHub(4)
	hub.Publish(EngineLog{Level: "info", Source: "engine", Message: "before"})
	hub.Close()
	hub.Publish(EngineLog{Level: "info", Source: "engine", Message: "after"})

	for _, event := range hub.Snapshot(EngineLogQuery{}).Logs {
		if strings.Contains(event.Message, "after") {
			t.Error("an event published after Close was retained")
		}
	}
}

func TestEngineLogCursorPaginatesFilteredEventsWithoutSkipping(t *testing.T) {
	hub := newEngineLogHub(8)
	defer hub.Close()
	hub.streamID = "stream-a"

	for index, extension := range []string{"one", "two", "one", "two", "one"} {
		hub.Publish(EngineLog{
			Seq: 999, Level: "info", Source: "script", Extension: extension,
			Action: "rewrite", Message: string(rune('a' + index)),
		})
	}
	after := uint64(0)
	first := hub.Snapshot(EngineLogQuery{
		Extension: "one", Limit: 2, StreamID: "stream-a", After: &after,
	})
	if len(first.Logs) != 2 || first.Logs[0].Seq != 1 || first.Logs[1].Seq != 3 || first.LatestSeq != 5 {
		t.Fatalf("first filtered cursor page = %+v", first)
	}
	after = uint64(first.Logs[len(first.Logs)-1].Seq)
	second := hub.Snapshot(EngineLogQuery{
		Extension: "one", Limit: 2, StreamID: "stream-a", After: &after,
	})
	if len(second.Logs) != 1 || second.Logs[0].Seq != 5 || second.Reset || second.Dropped != 0 {
		t.Fatalf("second filtered cursor page = %+v", second)
	}
}

func TestEngineLogCursorReportsRetentionLoss(t *testing.T) {
	hub := newEngineLogHub(4)
	defer hub.Close()
	hub.streamID = "stream-a"
	for index := range 6 {
		hub.Publish(EngineLog{Level: "info", Source: "engine", Message: string(rune('a' + index))})
	}
	after := uint64(1)
	page := hub.Snapshot(EngineLogQuery{Limit: 4, StreamID: "stream-a", After: &after})
	if page.OldestSeq != 3 || page.LatestSeq != 6 || page.Dropped != 1 || page.Reset {
		t.Fatalf("retention-loss page = %+v", page)
	}
	if len(page.Logs) != 4 || page.Logs[0].Seq != 3 || page.Logs[3].Seq != 6 {
		t.Fatalf("retention-loss logs = %+v", page.Logs)
	}
}

func TestEngineLogCursorResetsAcrossStreamsAndFutureSequences(t *testing.T) {
	hub := newEngineLogHub(8)
	defer hub.Close()
	hub.streamID = "current"
	for index := range 4 {
		hub.Publish(EngineLog{Level: "info", Source: "engine", Message: string(rune('a' + index))})
	}

	after := uint64(2)
	wrongStream := hub.Snapshot(EngineLogQuery{Limit: 2, StreamID: "old", After: &after})
	if !wrongStream.Reset || wrongStream.Dropped != 0 || len(wrongStream.Logs) != 2 || wrongStream.Logs[0].Seq != 3 || wrongStream.Logs[1].Seq != 4 {
		t.Fatalf("cross-stream reset page = %+v", wrongStream)
	}
	after = 99
	future := hub.Snapshot(EngineLogQuery{Limit: 2, StreamID: "current", After: &after})
	if !future.Reset || len(future.Logs) != 2 || future.Logs[1].Seq != 4 {
		t.Fatalf("future-cursor reset page = %+v", future)
	}
	after = 4
	current := hub.Snapshot(EngineLogQuery{Limit: 2, StreamID: "current", After: &after})
	if current.Reset || len(current.Logs) != 0 || current.LatestSeq != 4 {
		t.Fatalf("current empty page = %+v", current)
	}
}

type failingEngineLogEntropy struct{}

func (failingEngineLogEntropy) Read([]byte) (int, error) {
	return 0, errors.New("entropy unavailable")
}

func TestEngineLogStreamIDFallbackIsNonEmptyAndUnique(t *testing.T) {
	first := newEngineLogHubWithEntropy(4, failingEngineLogEntropy{})
	second := newEngineLogHubWithEntropy(4, failingEngineLogEntropy{})
	defer first.Close()
	defer second.Close()
	if len(first.streamID) != 32 || len(second.streamID) != 32 || first.streamID == second.streamID {
		t.Fatalf("fallback stream ids = %q and %q", first.streamID, second.streamID)
	}
}

func TestEngineLogCursorWirePreservesValuesBeyondJavaScriptIntegerRange(t *testing.T) {
	const beyondJavaScriptInteger = EngineLogCursor(9007199254740993)
	page := EngineLogPage{
		Logs:      []EngineLog{{Seq: beyondJavaScriptInteger, Level: "info", Source: "engine", Message: "large cursor"}},
		StreamID:  "stream-a",
		OldestSeq: beyondJavaScriptInteger,
		LatestSeq: beyondJavaScriptInteger,
		Dropped:   beyondJavaScriptInteger,
	}
	raw, err := json.Marshal(page)
	if err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{"seq", "oldest_seq", "latest_seq", "dropped"} {
		want := `"` + field + `":"9007199254740993"`
		if !strings.Contains(string(raw), want) {
			t.Fatalf("cursor field %s was not a decimal string: %s", field, raw)
		}
	}
	var decoded EngineLogPage
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.Logs[0].Seq != beyondJavaScriptInteger || decoded.LatestSeq != beyondJavaScriptInteger || decoded.Dropped != beyondJavaScriptInteger {
		t.Fatalf("decoded large cursor page = %+v", decoded)
	}
	var event EngineLog
	if err := json.Unmarshal([]byte(`{"seq":9007199254740993}`), &event); err == nil {
		t.Fatal("numeric engine log cursor was accepted")
	}
}
