package state

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

type doc struct {
	Hosts []string `json:"hosts"`
	Count int      `json:"count"`
}

func newDoc(t *testing.T) (*Doc[doc], string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "modules.json")
	d, err := New(path, doc{})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return d, path
}

func TestNewCreatesTheDocumentWhenAbsent(t *testing.T) {
	d, path := newDoc(t)
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("document not created: %v", err)
	}
	if got := d.Get(); got.Revision == "" {
		t.Error("a freshly created document has no revision")
	}
}

// A revision is the point of the design: two operators with the same page open
// in two tabs must not silently overwrite each other. This is the entire
// replacement for the overlay's two-key compare-and-swap.
func TestUpdateRefusesAStaleRevision(t *testing.T) {
	d, _ := newDoc(t)
	first := d.Get()

	if _, err := d.Update(first.Revision, func(v doc) (doc, error) {
		v.Count = 1
		return v, nil
	}); err != nil {
		t.Fatalf("first update: %v", err)
	}

	// The second caller still holds the revision it read before the first wrote.
	_, err := d.Update(first.Revision, func(v doc) (doc, error) {
		v.Count = 99
		return v, nil
	})
	if !errors.Is(err, ErrRevisionConflict) {
		t.Fatalf("stale update returned %v, want ErrRevisionConflict", err)
	}
	if got := d.Get().Value.Count; got != 1 {
		t.Errorf("Count = %d after a refused update, want 1", got)
	}
}

func TestUpdateWithoutExpectationAlwaysApplies(t *testing.T) {
	d, _ := newDoc(t)
	if _, err := d.Update("", func(v doc) (doc, error) {
		v.Count = 7
		return v, nil
	}); err != nil {
		t.Fatalf("unconditional update: %v", err)
	}
	if got := d.Get().Value.Count; got != 7 {
		t.Errorf("Count = %d, want 7", got)
	}
}

// A mutate that fails must leave both memory and disk exactly as they were.
func TestUpdateRollsBackWhenMutateFails(t *testing.T) {
	d, path := newDoc(t)
	before := d.Get()
	sentinel := errors.New("nope")

	if _, err := d.Update("", func(doc) (doc, error) { return doc{}, sentinel }); !errors.Is(err, sentinel) {
		t.Fatalf("Update returned %v, want the mutate error", err)
	}
	if after := d.Get(); after.Revision != before.Revision {
		t.Error("a failed mutate advanced the revision")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read back: %v", err)
	}
	var onDisk doc
	if err := json.Unmarshal(raw, &onDisk); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if onDisk.Count != 0 {
		t.Errorf("disk shows Count = %d after a failed mutate", onDisk.Count)
	}
}

func TestReopenRecoversTheRevision(t *testing.T) {
	d, path := newDoc(t)
	after, err := d.Update("", func(v doc) (doc, error) {
		v.Hosts = []string{"a.example.com"}
		return v, nil
	})
	if err != nil {
		t.Fatalf("update: %v", err)
	}

	reopened, err := New(path, doc{})
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	got := reopened.Get()
	if got.Revision != after.Revision {
		t.Errorf("revision after reopen = %q, want %q", got.Revision, after.Revision)
	}
	if len(got.Value.Hosts) != 1 || got.Value.Hosts[0] != "a.example.com" {
		t.Errorf("value after reopen = %+v", got.Value)
	}
}

// Refusing is the only safe response to a document that will not parse. The
// tempting alternative -- reset to defaults and carry on -- discards the
// operator's extensions and policy without ever saying so.
func TestNewRefusesAnUnreadableDocument(t *testing.T) {
	path := filepath.Join(t.TempDir(), "modules.json")
	if err := os.WriteFile(path, []byte("{not json"), 0o600); err != nil {
		t.Fatalf("seed: %v", err)
	}
	if _, err := New(path, doc{}); err == nil {
		t.Fatal("New accepted an unparseable document")
	}
}

// The rename must be all-or-nothing: a reader concurrent with a write sees the
// old bytes or the new ones, never a truncated file.
func TestWriteFileIsAtomic(t *testing.T) {
	path := filepath.Join(t.TempDir(), "doc.json")
	if err := WriteFile(path, []byte(`{"count":1}`)); err != nil {
		t.Fatalf("first write: %v", err)
	}
	if err := WriteFile(path, []byte(`{"count":2}`)); err != nil {
		t.Fatalf("second write: %v", err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(raw) != `{"count":2}` {
		t.Errorf("contents = %q", raw)
	}
	// No temp files may survive a successful write.
	entries, err := os.ReadDir(filepath.Dir(path))
	if err != nil {
		t.Fatalf("readdir: %v", err)
	}
	if len(entries) != 1 {
		names := make([]string, 0, len(entries))
		for _, e := range entries {
			names = append(names, e.Name())
		}
		t.Errorf("directory holds %v, want only doc.json", names)
	}
}
