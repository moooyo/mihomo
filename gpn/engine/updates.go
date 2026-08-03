package engine

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync/atomic"
)

// Import, update check, and update apply.
//
// The shape of all three is the same: fetch a candidate through the guarded
// path, show the operator exactly what it is, and only then let it become
// installed state. Nothing here auto-enables, and nothing applies an update the
// operator has not seen the digest of.

var importerRef atomic.Pointer[Importer]

// SetImporter installs the fetcher used by imports and update checks. The
// façade wires one in once the resolver exists, because an extension fetch has
// to resolve names through the gateway's own trust group rather than through
// whatever the host's resolver would say.
func SetImporter(imp *Importer) { importerRef.Store(imp) }

func currentImporter() (*Importer, error) {
	if imp := importerRef.Load(); imp != nil {
		return imp, nil
	}
	return nil, fmt.Errorf("%w: extension fetching is not available yet", ErrInvalidRequest)
}

// SnapshotDigest names an extension by everything an operator agreed to.
//
// It covers the manifest bytes, every script that will run, and the immutable
// capability shape -- capture hosts, permissions, routing rules, and each
// action's match. It deliberately excludes the operator's own state: the egress
// binding, the resolver binding, and the entered setting values are not part of
// what the publisher offered, and including them would make the digest change
// every time the operator edited a field, so "this is what you reviewed" would
// stop meaning anything.
func SnapshotDigest(m Module) string {
	shape := struct {
		Source       string         `json:"source"`
		CaptureHosts []string       `json:"capture_hosts"`
		Mappings     []HostMapping  `json:"mappings"`
		Routing      RoutingRules   `json:"routing"`
		Storage      bool           `json:"storage"`
		Network      bool           `json:"network"`
		EgressReq    bool           `json:"egress_required"`
		Actions      []actionShape  `json:"actions"`
		Settings     []settingShape `json:"settings"`
	}{
		Source:       m.Source.Digest,
		CaptureHosts: m.CaptureHosts,
		Mappings:     m.HostMappings,
		Routing:      m.RoutingRules,
		Storage:      m.PersistentStorage,
		Network:      m.Network,
		EgressReq:    m.EgressGroupRequired,
	}
	for _, s := range m.Scripts {
		shape.Actions = append(shape.Actions, actionShape{
			ID: s.ID, Phase: s.Phase, Match: s.Match, BodyMode: s.BodyMode,
			Entry: s.Entry, Digest: s.ScriptDigest, JQ: s.JQProgram, Reject: s.Reject,
		})
	}
	for _, s := range m.Settings {
		shape.Settings = append(shape.Settings, settingShape{
			Key: s.Key, Type: s.Type, Required: s.Required, Options: s.Options,
		})
	}
	// Marshalling cannot fail for this shape: every field is a string, bool,
	// number, or a slice of those.
	raw, _ := json.Marshal(shape)
	return digestText(string(raw))
}

type actionShape struct {
	ID       string      `json:"id"`
	Phase    string      `json:"phase"`
	Match    ActionMatch `json:"match"`
	BodyMode string      `json:"body_mode"`
	Entry    string      `json:"entry,omitempty"`
	Digest   string      `json:"digest,omitempty"`
	JQ       string      `json:"jq,omitempty"`
	Reject   bool        `json:"reject,omitempty"`
}

type settingShape struct {
	Key      string   `json:"key"`
	Type     string   `json:"type"`
	Required bool     `json:"required"`
	Options  []string `json:"options,omitempty"`
}

// Candidate is a fetched extension that is not installed state yet.
type Candidate struct {
	Detail ModuleDetail `json:"detail"`
	// Digest is what an apply must quote back. It is the operator's proof that
	// what lands is what they were shown, and it is checked against a fresh
	// fetch rather than against anything cached -- a publisher who changes the
	// manifest between the review and the confirmation must not slip through.
	Digest string `json:"digest"`
	// Installed is the digest of what is installed under this id, empty when
	// nothing is. The client renders the difference; the server does not
	// pretend to know which changes an operator cares about.
	Installed string `json:"installed,omitempty"`
	// InstalledVersion lets a client say "1.2.0 to 1.3.0" without a second read.
	InstalledVersion string `json:"installedVersion,omitempty"`
}

// Fetch retrieves and parses a candidate without touching installed state.
//
// This is the review step for both a fresh install and an update check. They
// are the same operation: fetch, parse, and report. What differs is only
// whether anything is installed under the id already, which the response says.
func (e *Engine) Fetch(ctx context.Context, request ImportRequest) (Candidate, error) {
	imp, err := currentImporter()
	if err != nil {
		return Candidate{}, err
	}
	module, err := imp.Import(ctx, request)
	if err != nil {
		return Candidate{}, err
	}
	candidate := Candidate{Detail: detailOf(module), Digest: SnapshotDigest(module)}

	cfg, cfgErr := e.config.Current()
	if cfgErr == nil {
		for _, installed := range cfg.Modules {
			if installed.ID == module.ID {
				candidate.Installed = SnapshotDigest(installed)
				candidate.InstalledVersion = installed.Version
			}
		}
	}
	return candidate, nil
}

// CheckUpdate re-fetches an installed extension from the URL it came from.
//
// Only a URL-sourced extension can be checked. A pasted manifest has no
// authority to re-read, and inventing one -- guessing at a registry -- would
// silently change where an operator's code comes from.
//
// A catalog can change it, but only because the operator picked that entry:
// see ApplyCatalogUpdate. The distinction that matters is not "may the source
// ever change" but "may it change without being asked".
func (e *Engine) CheckUpdate(ctx context.Context, id string) (Candidate, error) {
	cfg, err := e.config.Current()
	if err != nil {
		return Candidate{}, err
	}
	for _, m := range cfg.Modules {
		if m.ID != id {
			continue
		}
		if strings.TrimSpace(m.Source.URL) == "" {
			return Candidate{}, fmt.Errorf("%w: extension %q was imported from a pasted manifest and has no source to check", ErrInvalidRequest, id)
		}
		candidate, err := e.Fetch(ctx, ImportRequest{URL: m.Source.URL})
		if err != nil {
			return Candidate{}, err
		}
		if candidate.Detail.ID != id {
			// The URL now serves a different extension. Applying it would
			// replace one extension with another under the operator's existing
			// bindings, which is not an update.
			return Candidate{}, fmt.Errorf("%w: %s now serves extension %q, not %q", ErrInvalidRequest, m.Source.URL, candidate.Detail.ID, id)
		}
		return candidate, nil
	}
	return Candidate{}, fmt.Errorf("%w: %q", ErrModuleNotFound, id)
}

// InstallRequest is an import the operator has reviewed and confirmed.
type InstallRequest struct {
	ImportRequest
	// Digest is the candidate digest from the review. Required, and checked
	// against a fresh fetch.
	Digest string `json:"digest"`
}

// Install fetches, verifies against the reviewed digest, and stores the
// extension disabled.
//
// The re-fetch is the point. Holding the candidate from the review in memory
// and installing that would be simpler and would make the digest ceremonial;
// fetching again and comparing is what makes it a check on the publisher rather
// than on our own bookkeeping.
func (e *Engine) Install(ctx context.Context, revision string, request InstallRequest) (Snapshot, string, error) {
	if strings.TrimSpace(request.Digest) == "" {
		return Snapshot{}, revision, fmt.Errorf("%w: digest is required; review the extension first and quote what it returned", ErrInvalidRequest)
	}
	imp, err := currentImporter()
	if err != nil {
		return Snapshot{}, revision, err
	}
	module, err := imp.Import(ctx, request.ImportRequest)
	if err != nil {
		return Snapshot{}, revision, err
	}
	if got := SnapshotDigest(module); got != request.Digest {
		return Snapshot{}, revision, fmt.Errorf("%w: the extension changed since you reviewed it (%s, not %s)", ErrInvalidRequest, got, request.Digest)
	}
	return e.install(revision, module)
}

// ApplyUpdate replaces an installed extension with a reviewed candidate.
//
// The extension must be disabled. An update swaps every script the engine is
// running, and doing that underneath live captured sessions would have requests
// mid-flight served partly by the old code and partly by the new -- so the
// operator disables, updates, reviews and re-enables, which is three deliberate
// steps and one clear state at each of them.
func (e *Engine) ApplyUpdate(ctx context.Context, revision, id, digest string) (Snapshot, string, error) {
	cfg, err := e.config.Current()
	if err != nil {
		return Snapshot{}, revision, err
	}
	installed, err := updatableModule(cfg, id)
	if err != nil {
		return Snapshot{}, revision, err
	}
	if strings.TrimSpace(installed.Source.URL) == "" {
		return Snapshot{}, revision, fmt.Errorf("%w: extension %q has no source URL to update from", ErrInvalidRequest, id)
	}
	return e.applyUpdateFrom(ctx, revision, id, installed.Source.URL, digest, nil)
}

// updatableModule finds an installed extension that is in a state an update may
// replace.
//
// Disabled is the requirement. An update swaps every script the engine is
// running, and doing that underneath live captured sessions would have requests
// mid-flight served partly by the old code and partly by the new -- so the
// operator disables, updates, reviews and re-enables, which is three deliberate
// steps and one clear state at each of them.
func updatableModule(cfg Config, id string) (Module, error) {
	for _, m := range cfg.Modules {
		if m.ID != id {
			continue
		}
		if m.Enabled {
			return Module{}, fmt.Errorf("%w: disable extension %q before updating it", ErrInvalidRequest, id)
		}
		return m, nil
	}
	return Module{}, fmt.Errorf("%w: %q", ErrModuleNotFound, id)
}

// applyUpdateFrom is the shared tail of both update paths: fetch, prove it is
// still the same extension, prove it is what was reviewed, install.
//
// verify is the catalog path's extra check and is nil for the ordinary one.
func (e *Engine) applyUpdateFrom(
	ctx context.Context,
	revision, id, sourceURL, digest string,
	verify func(Module) error,
) (Snapshot, string, error) {
	if strings.TrimSpace(digest) == "" {
		return Snapshot{}, revision, fmt.Errorf("%w: digest is required; check for an update first and quote what it returned", ErrInvalidRequest)
	}
	imp, err := currentImporter()
	if err != nil {
		return Snapshot{}, revision, err
	}
	module, err := imp.Import(ctx, ImportRequest{URL: sourceURL})
	if err != nil {
		return Snapshot{}, revision, err
	}
	if module.ID != id {
		// Applying it would replace one extension with another under the
		// operator's existing bindings, which is not an update.
		return Snapshot{}, revision, fmt.Errorf("%w: %s now serves extension %q, not %q", ErrInvalidRequest, sourceURL, module.ID, id)
	}
	if got := SnapshotDigest(module); got != digest {
		return Snapshot{}, revision, fmt.Errorf("%w: the extension changed since you reviewed it (%s, not %s)", ErrInvalidRequest, got, digest)
	}
	if verify != nil {
		if err := verify(module); err != nil {
			return Snapshot{}, revision, err
		}
	}
	return e.install(revision, module)
}
