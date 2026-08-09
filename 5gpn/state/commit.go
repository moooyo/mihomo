package state

import (
	"errors"
	"fmt"
	"sync/atomic"
)

// ErrCommitAmbiguous marks a write whose rename succeeded but whose directory
// fsync failed. The new pathname is visible to this process, but crash recovery
// cannot prove which revision will survive.
var ErrCommitAmbiguous = errors.New("5gpn/state: commit durability is ambiguous")

// CommitAmbiguousError carries the file and underlying durability failure.
type CommitAmbiguousError struct {
	Path string
	Err  error
}

func (e *CommitAmbiguousError) Error() string {
	return fmt.Sprintf("%v for %s after rename: %v", ErrCommitAmbiguous, e.Path, e.Err)
}

func (e *CommitAmbiguousError) Unwrap() error { return e.Err }

func (e *CommitAmbiguousError) Is(target error) bool {
	return target == ErrCommitAmbiguous
}

type ambiguousCommitHandler struct {
	fn func(error)
}

var commitAmbiguousHandler atomic.Pointer[ambiguousCommitHandler]

// SetCommitAmbiguousHandler installs the process-owner boundary for a rename
// that cannot be proven durable. Production installs the monolith fatal
// handler; nil leaves one-shot callers with the typed error.
func SetCommitAmbiguousHandler(handler func(error)) {
	if handler == nil {
		commitAmbiguousHandler.Store(nil)
		return
	}
	commitAmbiguousHandler.Store(&ambiguousCommitHandler{fn: handler})
}

func reportCommitAmbiguous(path string, cause error) error {
	err := &CommitAmbiguousError{Path: path, Err: cause}
	if handler := commitAmbiguousHandler.Load(); handler != nil {
		handler.fn(err)
	}
	return err
}
