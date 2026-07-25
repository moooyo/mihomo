package overlay

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"
)

// storeSchemaVersion versions the on-disk layout independently of the document
// schema. A store written by a newer build is refused, never repaired: the
// downgrade contract requires the operator to purge deliberately rather than
// let an older binary reinterpret state it does not understand.
const storeSchemaVersion = 1

const (
	metaFile        = "meta.json"
	pointerFile     = "pointer.json"
	generationsDir  = "generations"
	generationSufix = ".json"
	tempSuffix      = ".tmp"
)

// Record is one durable generation artifact.
type Record struct {
	StoreSchema int      `json:"storeSchema"`
	Document    Document `json:"document"`
	Digests     Digests  `json:"digests"`
	State       State    `json:"state"`
	StagedAt    int64    `json:"stagedAt"`
	ActivatedAt int64    `json:"activatedAt,omitempty"`
	RevokedAt   int64    `json:"revokedAt,omitempty"`
	// RecordDigest covers every field above. A record whose digest does not
	// recompute is corrupt, and corruption is reported rather than silently
	// tolerated: an overlay is a security boundary and a half-written one has
	// no safe interpretation.
	RecordDigest string `json:"recordDigest"`
}

func (r *Record) computeDigest() string {
	c := newCanonical()
	c.str("overlay-record/v1")
	c.uint(uint64(r.StoreSchema))
	c.str(r.Digests.Overall)
	c.str(r.Digests.Projection)
	c.str(string(r.State))
	c.uint(uint64(r.StagedAt))
	c.uint(uint64(r.ActivatedAt))
	c.uint(uint64(r.RevokedAt))
	// Bind the document itself, not only its digest, so a tampered document
	// with a stale digest field cannot pass.
	c.writeProjection(&r.Document)
	c.str(r.Document.SidecarBundleDigest)
	c.str(r.Document.CertificateHostSetDigest)
	return c.sum()
}

// Pointer is the durable recovery decision: which generation this process must
// load before it opens client listeners.
//
// It is written before the live snapshot swap, so a crash between persistence
// and the swap is recoverable by rolling forward. It is not itself the online
// linearization point — readback reports the persisted and the live active
// generation separately precisely so a coordinator can tell the two apart.
type Pointer struct {
	StoreSchema int    `json:"storeSchema"`
	Active      string `json:"active"`
	// Draining lists generations whose capabilities must be reconstructed in
	// disabled state after a restart. A boot epoch invalidates their leases;
	// the artifacts themselves survive.
	Draining []string `json:"draining,omitempty"`
	// CoreRevision records the dependency-closure revision the active
	// generation was committed against.
	CoreRevision uint64 `json:"coreRevision"`
	UpdatedAt    int64  `json:"updatedAt"`
	Digest       string `json:"digest"`
}

func (p *Pointer) computeDigest() string {
	c := newCanonical()
	c.str("overlay-pointer/v1")
	c.uint(uint64(p.StoreSchema))
	c.str(p.Active)
	c.list(len(p.Draining))
	for _, d := range p.Draining {
		c.str(d)
	}
	c.uint(p.CoreRevision)
	c.uint(uint64(p.UpdatedAt))
	return c.sum()
}

type storeMeta struct {
	StoreSchema int    `json:"storeSchema"`
	Owner       string `json:"owner"`
	CreatedAt   int64  `json:"createdAt"`
}

// Store is the durable generation store. Every mutation is atomic-rename plus
// fsync of the file and, where the platform supports it, of the containing
// directory. Without the directory fsync the rename itself can be lost on a
// power failure even though the file contents were durable.
type Store struct {
	mu    sync.Mutex
	dir   string
	owner string
}

// OpenStore prepares the store directory, creating it if necessary.
func OpenStore(dir, owner string) (*Store, error) {
	if dir == "" {
		return nil, fmt.Errorf("%w: empty store directory", ErrInvalidDocument)
	}
	if err := validateID("owner", owner); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Join(dir, generationsDir), 0o700); err != nil {
		return nil, fmt.Errorf("overlay: create store directory: %w", err)
	}
	s := &Store{dir: dir, owner: owner}

	metaPath := filepath.Join(dir, metaFile)
	raw, err := os.ReadFile(metaPath)
	switch {
	case errors.Is(err, os.ErrNotExist):
		m := storeMeta{StoreSchema: storeSchemaVersion, Owner: owner, CreatedAt: time.Now().Unix()}
		if err := s.writeJSON(metaPath, &m); err != nil {
			return nil, err
		}
	case err != nil:
		return nil, fmt.Errorf("overlay: read store metadata: %w", err)
	default:
		var m storeMeta
		if err := json.Unmarshal(raw, &m); err != nil {
			return nil, fmt.Errorf("%w: store metadata is unreadable: %s", ErrStoreCorrupt, err)
		}
		if m.StoreSchema > storeSchemaVersion {
			return nil, fmt.Errorf("%w: store was written by schema %d, this build understands %d; purge the overlay state before downgrading",
				ErrUnsupportedSchema, m.StoreSchema, storeSchemaVersion)
		}
		if m.StoreSchema < storeSchemaVersion {
			return nil, fmt.Errorf("%w: store schema %d predates this build's %d and has no migration",
				ErrUnsupportedSchema, m.StoreSchema, storeSchemaVersion)
		}
		if m.Owner != owner {
			return nil, fmt.Errorf("%w: store belongs to owner %q, not %q", ErrInvalidDocument, m.Owner, owner)
		}
	}
	return s, nil
}

// Dir reports the store's root directory.
func (s *Store) Dir() string { return s.dir }

func (s *Store) generationPath(id string) (string, error) {
	if err := validateID("generationId", id); err != nil {
		return "", err
	}
	return filepath.Join(s.dir, generationsDir, id+generationSufix), nil
}

// PutGeneration writes one generation artifact durably.
func (s *Store) PutGeneration(rec *Record) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	path, err := s.generationPath(rec.Document.GenerationID)
	if err != nil {
		return err
	}
	rec.StoreSchema = storeSchemaVersion
	rec.RecordDigest = rec.computeDigest()
	return s.writeJSON(path, rec)
}

// GetGeneration loads one artifact and verifies its digest.
func (s *Store) GetGeneration(id string) (*Record, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.getGenerationLocked(id)
}

func (s *Store) getGenerationLocked(id string) (*Record, error) {
	path, err := s.generationPath(id)
	if err != nil {
		return nil, err
	}
	raw, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("%w: %s", ErrNotFound, id)
	}
	if err != nil {
		return nil, fmt.Errorf("overlay: read generation %s: %w", id, err)
	}
	var rec Record
	if err := json.Unmarshal(raw, &rec); err != nil {
		return nil, fmt.Errorf("%w: generation %s is unreadable: %s", ErrStoreCorrupt, id, err)
	}
	if rec.StoreSchema > storeSchemaVersion {
		return nil, fmt.Errorf("%w: generation %s was written by store schema %d", ErrUnsupportedSchema, id, rec.StoreSchema)
	}
	want := rec.computeDigest()
	if rec.RecordDigest != want {
		return nil, fmt.Errorf("%w: generation %s failed its integrity check", ErrStoreCorrupt, id)
	}
	if rec.Document.GenerationID != id {
		return nil, fmt.Errorf("%w: generation %s contains id %q", ErrStoreCorrupt, id, rec.Document.GenerationID)
	}
	return &rec, nil
}

// DeleteGeneration removes an artifact. A missing artifact is not an error:
// deletion is idempotent so garbage collection can be retried freely.
func (s *Store) DeleteGeneration(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	path, err := s.generationPath(id)
	if err != nil {
		return err
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("overlay: delete generation %s: %w", id, err)
	}
	return syncDir(filepath.Dir(path))
}

// ListGenerations returns every artifact id present, sorted.
func (s *Store) ListGenerations() ([]string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	entries, err := os.ReadDir(filepath.Join(s.dir, generationsDir))
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("overlay: list generations: %w", err)
	}
	out := make([]string, 0, len(entries))
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, generationSufix) {
			continue
		}
		out = append(out, strings.TrimSuffix(name, generationSufix))
	}
	sort.Strings(out)
	return out, nil
}

// PutPointer writes the durable recovery decision.
func (s *Store) PutPointer(p *Pointer) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	p.StoreSchema = storeSchemaVersion
	p.UpdatedAt = time.Now().Unix()
	p.Digest = p.computeDigest()
	return s.writeJSON(filepath.Join(s.dir, pointerFile), p)
}

// GetPointer loads the recovery decision. A missing pointer means no overlay
// has ever been committed, which is a valid empty state rather than an error.
func (s *Store) GetPointer() (*Pointer, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	raw, err := os.ReadFile(filepath.Join(s.dir, pointerFile))
	if errors.Is(err, os.ErrNotExist) {
		return &Pointer{StoreSchema: storeSchemaVersion}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("overlay: read pointer: %w", err)
	}
	var p Pointer
	if err := json.Unmarshal(raw, &p); err != nil {
		return nil, fmt.Errorf("%w: pointer is unreadable: %s", ErrStoreCorrupt, err)
	}
	if p.StoreSchema > storeSchemaVersion {
		return nil, fmt.Errorf("%w: pointer was written by store schema %d", ErrUnsupportedSchema, p.StoreSchema)
	}
	if p.Digest != p.computeDigest() {
		return nil, fmt.Errorf("%w: pointer failed its integrity check", ErrStoreCorrupt)
	}
	return &p, nil
}

// Purge removes every durable artifact and the pointer. This is the downgrade
// contract's step 2: leaving artifacts behind lets a later upgrade rediscover
// and resurrect a generation the operator believes was rolled back.
func (s *Store) Purge() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if err := os.RemoveAll(filepath.Join(s.dir, generationsDir)); err != nil {
		return fmt.Errorf("overlay: purge generations: %w", err)
	}
	if err := os.Remove(filepath.Join(s.dir, pointerFile)); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("overlay: purge pointer: %w", err)
	}
	if err := os.MkdirAll(filepath.Join(s.dir, generationsDir), 0o700); err != nil {
		return fmt.Errorf("overlay: recreate generations directory: %w", err)
	}
	return syncDir(s.dir)
}

// writeJSON writes v atomically: temp file, fsync, rename, fsync directory.
func (s *Store) writeJSON(path string, v any) error {
	raw, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return fmt.Errorf("overlay: encode %s: %w", filepath.Base(path), err)
	}
	raw = append(raw, '\n')

	dir := filepath.Dir(path)
	tmp := path + tempSuffix
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return fmt.Errorf("overlay: create %s: %w", tmp, err)
	}
	if _, err := f.Write(raw); err != nil {
		f.Close()
		os.Remove(tmp)
		return fmt.Errorf("overlay: write %s: %w", tmp, err)
	}
	if err := f.Sync(); err != nil {
		f.Close()
		os.Remove(tmp)
		return fmt.Errorf("overlay: fsync %s: %w", tmp, err)
	}
	if err := f.Close(); err != nil {
		os.Remove(tmp)
		return fmt.Errorf("overlay: close %s: %w", tmp, err)
	}
	if err := os.Rename(tmp, path); err != nil {
		os.Remove(tmp)
		return fmt.Errorf("overlay: publish %s: %w", path, err)
	}
	return syncDir(dir)
}

// syncDir fsyncs a directory so a rename survives a power failure. Windows
// cannot open a directory as a file, and its rename is metadata-journalled, so
// the call is skipped there rather than failing the write.
func syncDir(dir string) error {
	if runtime.GOOS == "windows" {
		return nil
	}
	f, err := os.Open(dir)
	if err != nil {
		return fmt.Errorf("overlay: open directory %s: %w", dir, err)
	}
	defer f.Close()
	if err := f.Sync(); err != nil {
		return fmt.Errorf("overlay: fsync directory %s: %w", dir, err)
	}
	return nil
}
