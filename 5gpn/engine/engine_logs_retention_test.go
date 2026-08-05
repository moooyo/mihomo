package engine

import (
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

	got := hub.Snapshot(EngineLogFilter{})
	if len(got) != 2 {
		t.Fatalf("retained %d events with nobody subscribed, want 2", len(got))
	}
	if got[0].Message != "hello" || got[1].Message != "careful" {
		t.Errorf("snapshot is not oldest-first: %+v", got)
	}
	for _, event := range got {
		if event.Time == "" {
			t.Errorf("event has no timestamp: %+v", event)
		}
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

	all := hub.Snapshot(EngineLogFilter{})
	if len(all) != 4 {
		t.Fatalf("ring of 4 retained %d events", len(all))
	}
	if all[len(all)-1].Message != "j" {
		t.Errorf("newest event is %q, want the last one published", all[len(all)-1].Message)
	}
	if all[0].Message != "g" {
		t.Errorf("oldest retained is %q; the ring dropped the wrong end", all[0].Message)
	}

	limited := hub.Snapshot(EngineLogFilter{Limit: 2})
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

	if got := hub.Snapshot(EngineLogFilter{Extension: "one"}); len(got) != 2 {
		t.Errorf("extension filter returned %d, want 2", len(got))
	}
	if got := hub.Snapshot(EngineLogFilter{Level: "error"}); len(got) != 1 {
		t.Errorf("level filter returned %d, want 1", len(got))
	}
	// Case-insensitive, because an operator searching a log types what they
	// remember, not what the script happened to capitalise.
	if got := hub.Snapshot(EngineLogFilter{Contains: "beta"}); len(got) != 1 {
		t.Errorf("message filter is case sensitive: %d matches for \"beta\"", len(got))
	}
	if got := hub.Snapshot(EngineLogFilter{Extension: "one", Level: "info"}); len(got) != 1 {
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

	for _, event := range hub.Snapshot(EngineLogFilter{}) {
		if strings.Contains(event.Message, "after") {
			t.Error("an event published after Close was retained")
		}
	}
}
