package engine

import (
	"encoding/json"
	"fmt"
	"sync"
	"testing"
	"time"
)

func TestCommittedConfigViewKeepsConfigAndRevisionTogether(t *testing.T) {
	e := newTestEngine(t, twoExtensionDocument)
	store := e.config

	// Canonicalize the initial hand-written fixture through the same marshal
	// path every subsequent committed view uses.
	if _, _, err := store.Update("", func(current Config) (Config, error) {
		current.MITM.HTTP2 = false
		return current, nil
	}); err != nil {
		t.Fatalf("canonicalize config: %v", err)
	}

	const writes = 200
	const readers = 8
	start := make(chan struct{})
	errs := make(chan error, readers+1)
	var wg sync.WaitGroup

	for reader := 0; reader < readers; reader++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			for read := 0; read < writes*4; read++ {
				view, err := e.CommittedView()
				if err != nil {
					errs <- err
					return
				}
				raw, err := json.MarshalIndent(view.Config, "", "  ")
				if err != nil {
					errs <- err
					return
				}
				if got := documentRevision(raw); got != view.Revision {
					errs <- fmt.Errorf("config/revision torn: config hashes to %q, view reports %q", got, view.Revision)
					return
				}
			}
		}()
	}

	wg.Add(1)
	go func() {
		defer wg.Done()
		<-start
		for write := 0; write < writes; write++ {
			view, err := store.CommittedView()
			if err != nil {
				errs <- err
				return
			}
			if _, _, err := store.Update(view.Revision, func(current Config) (Config, error) {
				current.MITM.HTTP2 = !current.MITM.HTTP2
				return current, nil
			}); err != nil {
				errs <- err
				return
			}
		}
	}()

	close(start)
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
}

func TestWithCurrentLockedSerializesNonDocumentWorkWithUpdates(t *testing.T) {
	e := newTestEngine(t, twoExtensionDocument)
	store := e.config
	want, err := store.CommittedView()
	if err != nil {
		t.Fatal(err)
	}

	entered := make(chan struct{})
	release := make(chan struct{})
	lockedDone := make(chan error, 1)
	go func() {
		lockedDone <- store.WithCurrentLocked(func(cfg Config, revision string) error {
			if revision != want.Revision || cfg.generation != want.Config.generation {
				return fmt.Errorf("locked view = generation %d revision %q, want generation %d revision %q",
					cfg.generation, revision, want.Config.generation, want.Revision)
			}
			close(entered)
			<-release
			return nil
		})
	}()
	<-entered

	updateDone := make(chan error, 1)
	go func() {
		_, _, err := store.Update(want.Revision, func(current Config) (Config, error) {
			current.MITM.HTTP2 = !current.MITM.HTTP2
			return current, nil
		})
		updateDone <- err
	}()

	select {
	case err := <-updateDone:
		t.Fatalf("Update completed while WithCurrentLocked held the write lock: %v", err)
	case <-time.After(25 * time.Millisecond):
	}
	close(release)
	if err := <-lockedDone; err != nil {
		t.Fatal(err)
	}
	if err := <-updateDone; err != nil {
		t.Fatal(err)
	}
}
