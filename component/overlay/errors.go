package overlay

import "errors"

// Stable sentinel errors. The control socket maps each one onto a fixed
// machine-readable code and HTTP status, so a coordinator can branch on the
// outcome without parsing prose. Never reuse a code for a different meaning:
// the coordinator's recovery path depends on telling "retry the same
// idempotent operation" apart from "this operation can never succeed".
var (
	// ErrInvalidDocument means the submitted generation is structurally wrong.
	// Terminal: retrying the identical document cannot succeed.
	ErrInvalidDocument = errors.New("overlay: invalid document")

	// ErrUnsupportedSchema means the document, or a durable artifact found on
	// disk, was written by a schema version this build does not understand.
	// Terminal, and on the durable path deliberately not "repair by guessing".
	ErrUnsupportedSchema = errors.New("overlay: unsupported schema version")

	// ErrQuotaExceeded means a fixed fork limit was exceeded. Terminal.
	ErrQuotaExceeded = errors.New("overlay: quota exceeded")

	// ErrCASConflict means the compare-and-swap preconditions did not hold:
	// the active generation or the core configuration revision moved. The
	// coordinator must read back and decide, never blind-rollback.
	ErrCASConflict = errors.New("overlay: compare-and-swap conflict")

	// ErrNotFound means the named generation is not in the store.
	ErrNotFound = errors.New("overlay: generation not found")

	// ErrWrongState means the operation is not legal from the generation's
	// current state, for example aborting something already active.
	ErrWrongState = errors.New("overlay: generation is in the wrong state")

	// ErrDependencyMissing means the configuration the commit would run under
	// does not satisfy the generation: a group vanished, a processor proxy is
	// not declared, or a resolver profile cannot be built.
	ErrDependencyMissing = errors.New("overlay: dependency missing")

	// ErrAnchorInvalid means the anchor structure required to evaluate the
	// overlay is absent, duplicated or misplaced. This is fail-closed: without
	// valid anchors the overlay cannot be enforced, so it must not be enabled.
	ErrAnchorInvalid = errors.New("overlay: anchor structure invalid")

	// ErrModeConflict means the core is not in rule mode, or an in-scope
	// listener, tunnel entry or rule can route around the anchors.
	ErrModeConflict = errors.New("overlay: routing mode or listener conflicts with an active overlay")

	// ErrNotReady means the generation is committed but its processor has not
	// presented a valid readiness lease, so matching traffic fails closed.
	ErrNotReady = errors.New("overlay: processor not ready")

	// ErrStoreCorrupt means a durable artifact failed its own digest check.
	ErrStoreCorrupt = errors.New("overlay: durable state corrupt")

	// ErrDisabled means no overlay is configured on this instance.
	ErrDisabled = errors.New("overlay: not enabled")
)

// Code is the stable machine-readable error identity carried on the wire.
type Code string

const (
	CodeInvalidDocument   Code = "invalid_document"
	CodeUnsupportedSchema Code = "unsupported_schema"
	CodeQuotaExceeded     Code = "quota_exceeded"
	CodeCASConflict       Code = "cas_conflict"
	CodeNotFound          Code = "not_found"
	CodeWrongState        Code = "wrong_state"
	CodeDependencyMissing Code = "dependency_missing"
	CodeAnchorInvalid     Code = "anchor_invalid"
	CodeModeConflict      Code = "mode_conflict"
	CodeNotReady          Code = "not_ready"
	CodeStoreCorrupt      Code = "store_corrupt"
	CodeDisabled          Code = "disabled"
	CodeInternal          Code = "internal"
)

// CodeOf maps an error onto its stable code, defaulting to internal.
func CodeOf(err error) Code {
	switch {
	case err == nil:
		return ""
	case errors.Is(err, ErrInvalidDocument):
		return CodeInvalidDocument
	case errors.Is(err, ErrUnsupportedSchema):
		return CodeUnsupportedSchema
	case errors.Is(err, ErrQuotaExceeded):
		return CodeQuotaExceeded
	case errors.Is(err, ErrCASConflict):
		return CodeCASConflict
	case errors.Is(err, ErrNotFound):
		return CodeNotFound
	case errors.Is(err, ErrWrongState):
		return CodeWrongState
	case errors.Is(err, ErrDependencyMissing):
		return CodeDependencyMissing
	case errors.Is(err, ErrAnchorInvalid):
		return CodeAnchorInvalid
	case errors.Is(err, ErrModeConflict):
		return CodeModeConflict
	case errors.Is(err, ErrNotReady):
		return CodeNotReady
	case errors.Is(err, ErrStoreCorrupt):
		return CodeStoreCorrupt
	case errors.Is(err, ErrDisabled):
		return CodeDisabled
	}
	return CodeInternal
}

// Retryable reports whether repeating the identical idempotent operation could
// plausibly succeed later. A terminal error means the coordinator must build a
// new generation instead of retrying this one.
func (c Code) Retryable() bool {
	switch c {
	case CodeDependencyMissing, CodeNotReady, CodeInternal:
		return true
	}
	return false
}
