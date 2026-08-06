// Package nodes manages static proxy nodes in the operator-owned mihomo YAML.
//
// It is a local, one-shot configuration helper. It does not expose a network
// API and it does not apply the resulting configuration to a running process.
package nodes

import (
	"errors"
	"fmt"
)

const (
	// MaxImportBytes bounds pasted subscriptions before parsing.
	MaxImportBytes = 1 << 20
	// MaxStaticNodes is the largest static proxy list this helper will create.
	MaxStaticNodes = 512
	// MaxNameBytes keeps terminal and JSON selection surfaces bounded.
	MaxNameBytes = 256
)

var (
	// ErrRevisionConflict means the operator file changed after it was read.
	ErrRevisionConflict = errors.New("5gpn/nodes: revision conflict")
	// ErrInvalidInput means a request or imported document is invalid.
	ErrInvalidInput = errors.New("5gpn/nodes: invalid input")
)

// RevisionConflictError includes the current raw-file revision.
type RevisionConflictError struct {
	Current string
}

func (e *RevisionConflictError) Error() string {
	return fmt.Sprintf("%s: current revision is %s", ErrRevisionConflict, e.Current)
}

func (e *RevisionConflictError) Unwrap() error { return ErrRevisionConflict }

// NodeView is the narrow projection used by the root management TUI.
type NodeView struct {
	Name      string `json:"name"`
	Type      string `json:"type"`
	Server    any    `json:"server"`
	Port      any    `json:"port"`
	InProxies bool   `json:"in_proxies"`
}

// View describes the current static nodes and the file revision that names it.
type View struct {
	Revision string     `json:"revision"`
	Group    string     `json:"group"`
	Nodes    []NodeView `json:"nodes"`
}

// ImportResult describes a committed import.
type ImportResult struct {
	Revision string     `json:"revision"`
	Added    []string   `json:"added"`
	Nodes    []NodeView `json:"nodes"`
}

// ImportPreview describes a fully parsed import that has not been written.
type ImportPreview struct {
	Revision          string     `json:"revision"`
	CandidateRevision string     `json:"candidate_revision"`
	Added             []string   `json:"added"`
	Nodes             []NodeView `json:"nodes"`
}

// DeleteResult describes a committed deletion.
type DeleteResult struct {
	Revision string     `json:"revision"`
	Removed  string     `json:"removed"`
	Nodes    []NodeView `json:"nodes"`
}
