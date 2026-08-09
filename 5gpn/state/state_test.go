package state

import (
	"bytes"
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

func TestDirUsesFiveGPNStateDirectory(t *testing.T) {
	home := t.TempDir()
	dir, err := Dir(home)
	if err != nil {
		t.Fatal(err)
	}
	want := filepath.Join(home, "5gpn")
	if dir != want {
		t.Fatalf("Dir() = %q, want %q", dir, want)
	}
	info, err := os.Stat(dir)
	if err != nil {
		t.Fatalf("stat state directory: %v", err)
	}
	if !info.IsDir() {
		t.Fatalf("state path %q is not a directory", dir)
	}
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

func TestStrictJSONRejectsAmbiguousInputs(t *testing.T) {
	tests := []struct {
		name string
		raw  []byte
	}{
		{name: "unknown field", raw: []byte(`{"hosts":[],"count":0,"coutn":1}`)},
		{name: "duplicate field", raw: []byte(`{"hosts":[],"count":0,"Count":1}`)},
		{name: "trailing value", raw: []byte(`{"hosts":[],"count":0} {}`)},
		{name: "invalid UTF-8", raw: append([]byte(`{"hosts":["`), 0xff, '"', ']', ',', '"', 'c', 'o', 'u', 'n', 't', '"', ':', '0', '}')},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var decoded doc
			if err := DecodeJSON(bytes.NewReader(test.raw), MaxDocumentBytes, &decoded); err == nil {
				t.Fatalf("DecodeJSON accepted %q", test.raw)
			}

			path := filepath.Join(t.TempDir(), "modules.json")
			if err := os.WriteFile(path, test.raw, 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := New(path, doc{}); err == nil {
				t.Fatalf("New accepted %q", test.raw)
			}
		})
	}
}

func TestNewBoundsExistingDocumentSize(t *testing.T) {
	path := filepath.Join(t.TempDir(), "modules.json")
	file, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if err := file.Truncate(MaxDocumentBytes + 1); err != nil {
		file.Close()
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := New(path, doc{}); err == nil {
		t.Fatal("New accepted an oversized document")
	}
}

func TestNewRefusesSymlinkDocument(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target.json")
	if err := os.WriteFile(target, []byte(`{"hosts":[],"count":0}`), 0o600); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "modules.json")
	if err := os.Symlink(target, path); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	if _, err := New(path, doc{}); err == nil {
		t.Fatal("New followed a symlink document")
	}
}

func TestNewRefusesHardLinkedDocument(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "modules.json")
	if err := os.WriteFile(path, []byte(`{"hosts":[],"count":0}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(path, filepath.Join(dir, "second-name.json")); err != nil {
		t.Skipf("hard links unavailable: %v", err)
	}
	if _, err := New(path, doc{}); err == nil {
		t.Fatal("New accepted a document with multiple hard links")
	}
}

func TestRenameThenDirectorySyncFailureIsCommitAmbiguous(t *testing.T) {
	path := filepath.Join(t.TempDir(), "doc.json")
	syncErr := errors.New("directory sync failed")
	reported := make(chan error, 1)
	SetCommitAmbiguousHandler(func(err error) { reported <- err })
	t.Cleanup(func() { SetCommitAmbiguousHandler(nil) })

	err := writeFile(path, []byte(`{"count":1}`), func(string) error { return syncErr })
	if !errors.Is(err, ErrCommitAmbiguous) || !errors.Is(err, syncErr) {
		t.Fatalf("writeFile error = %v, want typed commit ambiguity wrapping %v", err, syncErr)
	}
	select {
	case fatalErr := <-reported:
		if !errors.Is(fatalErr, ErrCommitAmbiguous) {
			t.Fatalf("fatal report = %v, want ErrCommitAmbiguous", fatalErr)
		}
	default:
		t.Fatal("commit ambiguity did not reach the process-owner handler")
	}
	raw, readErr := os.ReadFile(path)
	if readErr != nil {
		t.Fatal(readErr)
	}
	if got, want := string(raw), `{"count":1}`; got != want {
		t.Fatalf("renamed bytes = %q, want %q", got, want)
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

// A mutator must not be able to reach the memory readers are holding.
//
// Doc publishes through an atomic pointer precisely so readers never take the
// lock, which means anything a writer touches in place is a data race against
// them. Passing T by value is not enough: the struct copies, its slices and
// maps do not. This caught a real one -- the resolver's subscription goroutine
// ranged over Policy.Rules while a console edit assigned to Rules[0].
func TestUpdateGivesTheMutatorPrivateMemory(t *testing.T) {
	d, _ := newDoc(t)
	if _, err := d.Update("", func(v doc) (doc, error) {
		v.Hosts = []string{"first", "second"}
		return v, nil
	}); err != nil {
		t.Fatalf("seed: %v", err)
	}

	published := d.Get().Value

	// Mutate an element in place, the way an edit to one rule reads, then fail
	// the update so nothing is written. The published slice must be untouched:
	// if the mutator's argument aliased it, the write already happened and no
	// error can take it back.
	wantErr := errors.New("refused")
	if _, err := d.Update("", func(v doc) (doc, error) {
		v.Hosts[0] = "clobbered"
		return v, wantErr
	}); !errors.Is(err, wantErr) {
		t.Fatalf("Update: %v, want %v", err, wantErr)
	}

	if published.Hosts[0] != "first" {
		t.Errorf("the mutator wrote through to the published document: %q", published.Hosts[0])
	}
	if got := d.Get().Value.Hosts[0]; got != "first" {
		t.Errorf("a failed update changed the current value: %q", got)
	}
}
