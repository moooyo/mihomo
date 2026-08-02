// Package state is the whole persistence story.
//
// It replaces component/overlay: a generation store, a two-key compare-and-swap,
// a lease registry with per-boot fencing tokens, a commit-intent journal, roll
// forward recovery, quarantine and draining states, and a duplicated wire schema
// on each side of a unix socket. Roughly fourteen thousand lines whose entire
// job was letting one process learn what another was serving and prove it had
// not changed underneath.
//
// None of it was wrong. All of it answered a question that only exists when the
// reader and the writer are different processes that can crash independently
// and disagree about whether a commit landed. In one address space the reader is
// a field load, so what is left is a file written atomically, a pointer swapped
// atomically, and a hash so two operators editing the same page in two browser
// tabs cannot silently overwrite each other.
package state

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"sync/atomic"
)

// ErrRevisionConflict is returned when an update names a revision that is no
// longer current.
//
// This is the one piece of concurrency control that survives, and it survives
// for a reason that has nothing to do with processes: two operators with the
// extensions page open in two tabs will otherwise last-write-wins each other
// silently. The API turns this into a 409.
var ErrRevisionConflict = errors.New("gpn/state: revision conflict")

// Doc is a JSON document held in memory and mirrored to disk.
//
// Reads are lock free and never touch the filesystem: whatever is serving
// traffic reads the pointer. Writes take the mutex, marshal, fsync, rename, and
// swap the pointer, in that order -- the pointer moves only after the bytes are
// durable, so a reader can never observe a value that a crash would un-observe.
type Doc[T any] struct {
	path string
	mu   sync.Mutex
	cur  atomic.Pointer[Snapshot[T]]
}

// Snapshot is an immutable view of a document plus the revision that names it.
type Snapshot[T any] struct {
	Value    T
	Revision string
}

// New opens the document at path, creating it with zero if absent.
func New[T any](path string, zero T) (*Doc[T], error) {
	d := &Doc[T]{path: path}
	raw, err := os.ReadFile(path)
	switch {
	case err == nil:
		var value T
		if err := json.Unmarshal(raw, &value); err != nil {
			// Refuse rather than silently reset. A document that fails to parse
			// is either a bug or a partial write nothing else can explain, and
			// replacing it with defaults would discard the operator's
			// extensions and policy without saying so.
			return nil, fmt.Errorf("gpn/state: %s is unreadable: %w", path, err)
		}
		d.cur.Store(&Snapshot[T]{Value: value, Revision: revisionOf(raw)})
		return d, nil
	case errors.Is(err, os.ErrNotExist):
		if err := d.write(zero); err != nil {
			return nil, err
		}
		return d, nil
	default:
		return nil, fmt.Errorf("gpn/state: read %s: %w", path, err)
	}
}

// Get returns the current snapshot. It never blocks and never fails.
func (d *Doc[T]) Get() Snapshot[T] {
	if s := d.cur.Load(); s != nil {
		return *s
	}
	var zero Snapshot[T]
	return zero
}

// Update applies mutate to the current value and publishes the result.
//
// An empty expected revision means "I do not care what it was" and is for
// internal callers that own the document outright. Any other value must match
// the current revision or the update is refused; that is the whole of the
// optimistic concurrency the system needs.
func (d *Doc[T]) Update(expected string, mutate func(T) (T, error)) (Snapshot[T], error) {
	d.mu.Lock()
	defer d.mu.Unlock()

	current := d.Get()
	if expected != "" && expected != current.Revision {
		return current, ErrRevisionConflict
	}
	// The mutator gets a private copy, never the published value.
	//
	// T is a struct, so passing it by value copies the top level -- but every
	// slice and map inside it still points at the published document's memory.
	// A mutator that writes d.Policy.Rules[0].Intent, which is the obvious way
	// to say "change this one rule", would be writing into the value every
	// reader is holding. Readers deliberately do not take d.mu; that is the
	// whole point of publishing through an atomic pointer, and it is what makes
	// the write a race rather than merely surprising.
	//
	// Returning a fresh document from the mutator is not enough on its own,
	// because the natural way to build one is to start from the argument. The
	// copy has to happen here, where it cannot be forgotten.
	//
	// It goes through the same JSON the write below does, so it cannot drift
	// from what is persisted: anything a round trip loses was never going to
	// survive the write either. One extra marshal per update, against updates
	// that happen a few times an hour.
	private, err := clonePrivate(current.Value)
	if err != nil {
		return current, err
	}
	next, err := mutate(private)
	if err != nil {
		return current, err
	}
	if err := d.write(next); err != nil {
		return current, err
	}
	return d.Get(), nil
}

// clonePrivate deep-copies a document so a mutator cannot reach published memory.
func clonePrivate[T any](value T) (T, error) {
	var zero T
	raw, err := json.Marshal(value)
	if err != nil {
		return zero, fmt.Errorf("gpn/state: clone document: %w", err)
	}
	var out T
	if err := json.Unmarshal(raw, &out); err != nil {
		return zero, fmt.Errorf("gpn/state: clone document: %w", err)
	}
	return out, nil
}

// write marshals, persists durably, then publishes. Callers hold d.mu.
func (d *Doc[T]) write(value T) error {
	raw, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return fmt.Errorf("gpn/state: marshal %s: %w", d.path, err)
	}
	if err := WriteFile(d.path, raw); err != nil {
		return err
	}
	// Only now. A reader that saw this value before the rename could outlive a
	// crash that un-wrote it, and would then be acting on a document no longer
	// on disk.
	d.cur.Store(&Snapshot[T]{Value: value, Revision: revisionOf(raw)})
	return nil
}

// WriteFile persists data at path so that a crash leaves either the old
// contents or the new ones, never a truncated file and never a dangling name.
//
// The directory fsync is the part that is easy to omit and expensive to omit:
// without it the rename is not durable, so the directory entry can still name
// the old inode -- or the temp file that was then removed. A caller who was told
// the write succeeded would be wrong in a way nothing reports.
func WriteFile(path string, data []byte) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, filepath.Base(path)+".*.tmp")
	if err != nil {
		return fmt.Errorf("gpn/state: create temp in %s: %w", dir, err)
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName) // no-op once the rename succeeds

	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return fmt.Errorf("gpn/state: write %s: %w", tmpName, err)
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return fmt.Errorf("gpn/state: fsync %s: %w", tmpName, err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("gpn/state: close %s: %w", tmpName, err)
	}
	if err := os.Chmod(tmpName, 0o600); err != nil {
		return fmt.Errorf("gpn/state: chmod %s: %w", tmpName, err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("gpn/state: rename onto %s: %w", path, err)
	}
	return syncDir(dir)
}

func syncDir(dir string) error {
	if runtime.GOOS == "windows" {
		return nil
	}
	f, err := os.Open(dir)
	if err != nil {
		return fmt.Errorf("gpn/state: open %s: %w", dir, err)
	}
	defer f.Close()
	if err := f.Sync(); err != nil {
		return fmt.Errorf("gpn/state: fsync %s: %w", dir, err)
	}
	return nil
}

// revisionOf names a document by its bytes.
//
// A content hash rather than a counter because the only question asked of it is
// "is this still what I read", and a hash answers that without anyone having to
// own, persist or monotonically advance a number. The overlay design needed a
// counter as well, because a coordinator had to distinguish "different from"
// from "newer than" across a process boundary. There is no such boundary left.
func revisionOf(raw []byte) string {
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:16])
}

// WritePublicFile persists data readable by anyone, for the one kind of
// document that another program must read.
//
// Everything else here is 0600, and stays that way: the interception document
// carries script bodies and typed settings an operator may have put a
// credential in. The exception is the certificate request, whose entire content
// ends up in a leaf's SAN list — a list every client that connects is handed.
// Publishing it 0600 and then widening the consumer's privileges to read it
// would be protecting a secret that is not one, by giving a process that holds
// the CA signing key a capability it does not otherwise need.
func WritePublicFile(path string, data []byte) error {
	if err := WriteFile(path, data); err != nil {
		return err
	}
	if err := os.Chmod(path, 0o644); err != nil {
		return fmt.Errorf("gpn/state: chmod %s: %w", path, err)
	}
	return nil
}

// Dir returns the 5gpn state directory beneath mihomo's home, creating it.
//
// 0711 rather than 0700: the certificate oneshot runs as root with an empty
// capability bounding set, so it is subject to ordinary permission checks and
// cannot traverse a directory owned by the service user. Execute-without-read
// lets it reach the one file it is meant to while still refusing a listing —
// and every document in here is 0600 regardless, so traversal alone opens
// nothing.
func Dir(home string) (string, error) {
	dir := filepath.Join(home, "gpn")
	if err := os.MkdirAll(dir, 0o711); err != nil {
		return "", fmt.Errorf("gpn/state: create %s: %w", dir, err)
	}
	// MkdirAll leaves an existing directory's mode alone, and a gateway
	// installed before this change has one at 0700.
	if err := os.Chmod(dir, 0o711); err != nil {
		return "", fmt.Errorf("gpn/state: chmod %s: %w", dir, err)
	}
	return dir, nil
}
