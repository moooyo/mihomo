package engine

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
)

// The management surface. Every one of these is the same shape: quote the
// revision you read, mutate one thing, and get back the snapshot the change
// produced. The document is validated and compiled before it is published, so
// a mutation that would produce a configuration the engine cannot serve is
// refused with the running one untouched.
//
// The console and the bot both call these. Neither has a private path to the
// document, which is what stops the two surfaces from disagreeing about what is
// installed.

var (
	// ErrModuleNotFound is wrapped by every "no extension with this id".
	ErrModuleNotFound = errors.New("5gpn/engine: extension not found")
	// ErrInvalidRequest wraps a caller-caused failure the API answers 400 for.
	ErrInvalidRequest = errors.New("5gpn/engine: invalid request")
	// ErrReviewConflict marks a candidate that no longer matches the review the
	// operator confirmed. The API answers 409 so clients can preserve entered
	// settings, fetch a fresh candidate, and require a new confirmation.
	ErrReviewConflict = errors.New("5gpn/engine: reviewed candidate is stale")
	// ErrUnprocessable marks a syntactically valid management request whose
	// complete proposed state cannot run. The API answers it with 422 while it
	// remains an ErrInvalidRequest for callers that classify engine failures.
	ErrUnprocessable = errors.New("5gpn/engine: unprocessable request")
)

type unprocessableRequestError struct{ message string }

func (e unprocessableRequestError) Error() string {
	return ErrInvalidRequest.Error() + ": " + e.message
}

func (e unprocessableRequestError) Unwrap() []error {
	return []error{ErrInvalidRequest, ErrUnprocessable}
}

func unprocessableRequest(format string, args ...any) error {
	return unprocessableRequestError{message: fmt.Sprintf(format, args...)}
}

type reviewConflictError struct{ message string }

func (e reviewConflictError) Error() string {
	return ErrInvalidRequest.Error() + ": " + e.message
}

func (e reviewConflictError) Unwrap() []error {
	return []error{ErrInvalidRequest, ErrReviewConflict}
}

func reviewConflictf(format string, args ...any) error {
	return reviewConflictError{message: fmt.Sprintf(format, args...)}
}

// Revision names the current document.
func (e *Engine) Revision() string { return e.config.Revision() }

// ReadDocument returns the current document and its revision.
func (e *Engine) ReadDocument() (Config, string) {
	view, err := e.CommittedView()
	if err != nil {
		return Config{}, ""
	}
	return view.Config, view.Revision
}

// Detail is one extension in full, minus the script bodies.
//
// The bodies are excluded because a manifest can run to megabytes and the
// review that needs this does not read them -- it reports their digests, which
// is what "the code has not changed since you approved it" actually rests on.
func (e *Engine) Detail(id string) (ModuleDetail, error) {
	detail, _, err := e.DetailView(id)
	return detail, err
}

// DetailView pairs detail with the revision of the exact committed Config it
// came from. The runtime phase is derived from that same config rather than a
// second read that a concurrent write could overtake.
func (e *Engine) DetailView(id string) (ModuleDetail, string, error) {
	view, err := e.CommittedView()
	if err != nil {
		return ModuleDetail{}, "", err
	}
	for _, m := range view.Config.Modules {
		if m.ID == id {
			detail := detailOf(m)
			detail.Runtime = e.extensionRuntimeStateForConfig(view.Config, id)
			return detail, view.Revision, nil
		}
	}
	return ModuleDetail{}, view.Revision, fmt.Errorf("%w: %q", ErrModuleNotFound, id)
}

// ModuleDetail is everything a review has to state before an operator confirms.
type ModuleDetail struct {
	ModuleSummary
	Description string `json:"description,omitempty"`
	ImportedAt  string `json:"imported_at,omitempty"`
	SourceURL   string `json:"source_url,omitempty"`
	// SourceDigest is the digest of the manifest snapshot. Script digests are
	// reported with Actions; Candidate.Digest is the complete review digest.
	SourceDigest string `json:"source_digest,omitempty"`
	// SnapshotDigest covers the complete immutable capability and code shape.
	// Unlike SourceDigest it includes scripts and normalized declarations, and
	// unlike the document revision it excludes operator-owned bindings.
	SnapshotDigest string `json:"snapshot_digest"`

	// Network is the unrestricted grant. It carries no destination list, so
	// every surface must present it as "any host it can reach" rather than as a
	// reviewed set -- naming a set would describe a boundary that does not
	// exist.
	Network           bool `json:"network"`
	PersistentStorage bool `json:"persistent_storage"`

	Settings     []ModuleSetting  `json:"settings,omitempty"`
	Actions      []ActionSummary  `json:"actions,omitempty"`
	RoutingRules RoutingRules     `json:"routing_rules,omitempty"`
	HostMappings []MappingSummary `json:"upstream_mappings,omitempty"`
}

// ActionSummary describes one script action without its source.
type ActionSummary struct {
	ID       string   `json:"id"`
	Phase    string   `json:"phase"`
	Hosts    []string `json:"hosts,omitempty"`
	Schemes  []string `json:"schemes,omitempty"`
	Methods  []string `json:"methods,omitempty"`
	Path     string   `json:"path,omitempty"`
	Statuses []int    `json:"statuses,omitempty"`
	// Digest is the identity of the code that will run.
	Digest string `json:"digest,omitempty"`
}

// MappingSummary is one upstream mapping, with the form named.
type MappingSummary struct {
	Pattern string `json:"pattern"`
	Target  string `json:"target"`
	// Resolver marks the "server:" form, which names nameservers rather than a
	// destination. The distinction matters to a reviewer: one changes where a
	// captured request goes, the other changes only how its origin is looked up.
	Resolver bool `json:"resolver"`
}

func detailOf(m Module) ModuleDetail {
	d := ModuleDetail{
		ModuleSummary:     summariseModule(m),
		Description:       m.Description,
		ImportedAt:        m.ImportedAt,
		SourceURL:         m.Source.URL,
		SourceDigest:      m.Source.Digest,
		SnapshotDigest:    SnapshotDigest(m),
		Network:           m.Network,
		PersistentStorage: m.PersistentStorage,
		Settings:          cloneModuleSettings(m.Settings),
		RoutingRules:      append(RoutingRules(nil), m.RoutingRules...),
	}
	for _, s := range m.Scripts {
		d.Actions = append(d.Actions, ActionSummary{
			ID:       s.ID,
			Phase:    s.Phase,
			Hosts:    append([]string(nil), s.Match.Hosts...),
			Schemes:  append([]string(nil), s.Match.Schemes...),
			Methods:  append([]string(nil), s.Match.Methods...),
			Path:     s.Match.PathRegex,
			Statuses: append([]int(nil), s.Match.StatusCodes...),
			// The digest of the fetched script, not of the body as stored: it is
			// what the operator approved and what an update check compares.
			Digest: s.ScriptDigest,
		})
	}
	for _, h := range m.HostMappings {
		d.HostMappings = append(d.HostMappings, MappingSummary{
			Pattern:  h.Pattern,
			Target:   h.Target,
			Resolver: h.resolverForm(),
		})
	}
	return d
}

// mutate is the shared write: quote a revision, change one thing, publish.
func (e *Engine) mutate(revision string, fn func(*Config) error) (Snapshot, string, error) {
	compiled, next, err := e.config.Update(revision, func(current Config) (Config, error) {
		candidate := cloneConfig(current)
		if err := fn(&candidate); err != nil {
			return current, err
		}
		return candidate, nil
	})
	if err != nil {
		return Snapshot{}, next, err
	}
	if e.trafficChanged != nil {
		e.trafficChanged()
	}
	snapshot, err := e.SnapshotFromConfig(compiled)
	return snapshot, next, err
}

// cloneConfig deep-copies the slices a mutation touches.
//
// The compiled snapshot is shared with every in-flight request, so mutating its
// backing arrays in place would change what a running session is matching
// against, halfway through matching against it.
//
// Every copy below preserves emptiness rather than collapsing it to nil.
// `append([]string(nil), empty...)` returns nil, nil marshals to `null`, and
// the decode that follows a write rejects a null execution order — so on a
// gateway with no extensions installed, which is every gateway on its first
// day, the very first write failed with "execution_order must be an array".
func cloneConfig(c Config) Config {
	out := c
	out.runtime = nil
	out.ExecutionOrder = copyStrings(c.ExecutionOrder)
	out.Catalogs = append([]CatalogSource{}, c.Catalogs...)
	out.Modules = make([]Module, len(c.Modules))
	for i, m := range c.Modules {
		m.CaptureHosts = copyStrings(m.CaptureHosts)
		m.Settings = cloneModuleSettings(m.Settings)
		m.Scripts = append([]ScriptRule(nil), m.Scripts...)
		m.HostMappings = append([]HostMapping(nil), m.HostMappings...)
		m.RoutingRules = append(RoutingRules(nil), m.RoutingRules...)
		out.Modules[i] = m
	}
	return out
}

func cloneModuleSettings(settings []ModuleSetting) []ModuleSetting {
	out := make([]ModuleSetting, len(settings))
	for i, setting := range settings {
		setting.Options = append([]string(nil), setting.Options...)
		setting.Default = append(json.RawMessage(nil), setting.Default...)
		setting.Value = append(json.RawMessage(nil), setting.Value...)
		if setting.Min != nil {
			value := *setting.Min
			setting.Min = &value
		}
		if setting.Max != nil {
			value := *setting.Max
			setting.Max = &value
		}
		out[i] = setting
	}
	return out
}

// copyStrings returns a non-nil copy, so a field that serialises without
// omitempty stays `[]` rather than becoming `null`.
func copyStrings(in []string) []string {
	return append(make([]string, 0, len(in)), in...)
}

func findModule(c *Config, id string) (*Module, error) {
	for i := range c.Modules {
		if c.Modules[i].ID == id {
			return &c.Modules[i], nil
		}
	}
	return nil, fmt.Errorf("%w: %q", ErrModuleNotFound, id)
}

// SetSettings replaces the master switch and the protocol settings.
//
// Turning the master off is atomic in the only sense that matters: the document
// is published in one rename, and the capture table the resolver and the
// interceptor consult is derived from it, so there is no window in which one of
// them thinks capture is on and the other thinks it is off.
func (e *Engine) SetSettings(revision string, s MITMSettings) (Snapshot, string, error) {
	return e.mutate(revision, func(c *Config) error {
		c.MITM = s
		return nil
	})
}

// SetEnabled turns one extension on or off.
//
// Enabling is the confirmed operation: it authorizes the complete snapshot --
// capture hosts, scripts, storage, the network grant, routing rules and the
// egress binding -- at once. The review that precedes it is the client's to
// render from Detail; this call is what the operator confirmed.
func (e *Engine) SetEnabled(revision, id string, enabled bool) (Snapshot, string, error) {
	return e.mutate(revision, func(c *Config) error {
		m, err := findModule(c, id)
		if err != nil {
			return err
		}
		if enabled && strings.TrimSpace(m.EgressGroup) == "" {
			return fmt.Errorf("%w: extension %q has no explicit egress binding", ErrInvalidRequest, id)
		}
		if enabled && m.EgressGroup != "" && !e.validEgressGroup(m.EgressGroup) {
			return fmt.Errorf("%w: extension %q egress group %q is unavailable", ErrInvalidRequest, id, m.EgressGroup)
		}
		m.Enabled = enabled
		return nil
	})
}

// Reorder rewrites the execution order.
//
// Separately confirmed from everything else, because order decides which
// extension owns an overlapping capture host -- and therefore which script acts
// on it, which egress binding wins, and which resolver group looks up its
// origin. Two extensions can both be perfectly configured and still produce
// different traffic depending only on this list.
func (e *Engine) Reorder(revision string, ids []string) (Snapshot, string, error) {
	return e.mutate(revision, func(c *Config) error {
		if len(ids) != len(c.Modules) {
			return fmt.Errorf("%w: the order lists %d extensions, %d are installed", ErrInvalidRequest, len(ids), len(c.Modules))
		}
		known := make(map[string]struct{}, len(c.Modules))
		for _, m := range c.Modules {
			known[m.ID] = struct{}{}
		}
		next := make([]string, 0, len(ids))
		for _, id := range ids {
			if _, ok := known[id]; !ok {
				return fmt.Errorf("%w: the order names unknown extension %q", ErrInvalidRequest, id)
			}
			delete(known, id) // a repeat is now unknown, which rejects duplicates
			next = append(next, id)
		}
		c.ExecutionOrder = next
		return nil
	})
}

// SetEgressGroup binds an extension's transformed traffic to an operator proxy
// group. Every extension always has a binding; an empty value is invalid.
//
// The extension cannot name the group, inspect it, or learn that it changed:
// the manifest may declare that one is required and nothing more. This is the
// operator's choice about where decrypted traffic leaves the box.
func (e *Engine) SetEgressGroup(revision, id, group string) (Snapshot, string, error) {
	group = strings.TrimSpace(group)
	if group == "" {
		return Snapshot{}, revision, fmt.Errorf("%w: egress group must be DIRECT or an available proxy group", ErrInvalidRequest)
	}
	if !e.validEgressGroup(group) {
		return Snapshot{}, revision, fmt.Errorf("%w: egress group %q is unavailable", ErrInvalidRequest, group)
	}
	return e.mutate(revision, func(c *Config) error {
		m, err := findModule(c, id)
		if err != nil {
			return err
		}
		m.EgressGroup = group
		return nil
	})
}

// SetCaptureDNS binds an extension's captured hosts to a resolver group for
// origin lookups.
func (e *Engine) SetCaptureDNS(revision, id, resolver string) (Snapshot, string, error) {
	resolver = strings.TrimSpace(resolver)
	if resolver != "trust" && resolver != "china" {
		return Snapshot{}, revision, fmt.Errorf("%w: capture DNS must be trust or china", ErrInvalidRequest)
	}
	return e.mutate(revision, func(c *Config) error {
		m, err := findModule(c, id)
		if err != nil {
			return err
		}
		m.CaptureDNS = resolver
		return nil
	})
}

// SettingValues is one complete operator-owned settings document. Values stay
// as JSON until they are checked against the publisher's typed declarations.
type SettingValues map[string]json.RawMessage

// SetSettingValues replaces every setting value for one extension atomically.
//
// A partial per-key write can leave action gates observing a combination the
// operator never submitted. Requiring the exact declared key set lets the
// engine validate and compile one proposed snapshot, then publish it in one
// pointer swap. Optional values may be null to clear them; required values must
// be complete.
func (e *Engine) SetSettingValues(revision, id string, values SettingValues) (Snapshot, string, error) {
	return e.mutate(revision, func(c *Config) error {
		m, err := findModule(c, id)
		if err != nil {
			return err
		}
		if values == nil {
			return unprocessableRequest("settings values must be an object containing every declared key")
		}
		next, err := settingsWithCompleteValues(m.Settings, values)
		if err != nil {
			return err
		}
		m.Settings = next
		return nil
	})
}

func settingsWithCompleteValues(settings []ModuleSetting, values SettingValues) ([]ModuleSetting, error) {
	declared := make(map[string]struct{}, len(settings))
	for _, setting := range settings {
		declared[setting.Key] = struct{}{}
	}
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		if _, ok := declared[key]; !ok {
			return nil, unprocessableRequest("settings contain unknown key %q", key)
		}
	}

	next := cloneModuleSettings(settings)
	for i := range next {
		raw, ok := values[next[i].Key]
		if !ok {
			return nil, unprocessableRequest("settings omit declared key %q", next[i].Key)
		}
		if err := validateSettingValue(next[i], raw, next[i].Required); err != nil {
			return nil, unprocessableRequest("setting %q: %v", next[i].Key, err)
		}
		if bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
			next[i].Value = nil
			continue
		}
		next[i].Value = append(json.RawMessage(nil), raw...)
	}
	return next, nil
}

// install adds a new extension, always disabled. Installed IDs can change only
// through the reviewed Marketplace update path.
//
// Disabled is not a default a caller can override. An import is a decision to
// have the code on the box; enabling it is a separate decision about letting it
// see traffic, and collapsing the two would mean one click on a marketplace
// entry starts decrypting.
//
// Unexported because there is exactly one way in: a reviewed, digest-checked
// fetch. See updates.go.
func (e *Engine) install(revision string, m Module) (Snapshot, string, error) {
	return e.mutate(revision, func(c *Config) error {
		for _, installed := range c.Modules {
			if installed.ID == m.ID {
				return fmt.Errorf("%w: extension %q is already installed; select its Marketplace entry to update", ErrInvalidRequest, m.ID)
			}
		}
		return installMutation(m)(c)
	})
}

func (e *Engine) update(revision string, m Module, values SettingValues) (Snapshot, string, error) {
	return e.mutate(revision, updateMutation(m, values))
}

// validateInstall applies the install mutation to a private copy and runs the
// same JSON decode, document validation, and runtime compilation as the write
// path. It deliberately stops before configStore.Update can persist or publish
// anything. The returned config is the snapshot the dry run started from.
func (e *Engine) validateInstall(m Module) (CommittedConfigView, error) {
	view, err := e.CommittedView()
	if err != nil {
		return CommittedConfigView{}, err
	}
	candidate := cloneConfig(view.Config)
	if err := installMutation(m)(&candidate); err != nil {
		return CommittedConfigView{}, err
	}
	raw, err := json.MarshalIndent(candidate, "", "  ")
	if err != nil {
		return CommittedConfigView{}, fmt.Errorf("5gpn/engine: marshal config: %w", err)
	}
	compiled, err := decodeConfig(raw)
	if err != nil {
		return CommittedConfigView{}, err
	}
	if err := e.config.validateGuestCode(raw, compiled); err != nil {
		return CommittedConfigView{}, err
	}
	return view, nil
}

// installMutation is shared by review and apply so both validate the exact
// document that an install would produce, including retained operator state.
func installMutation(m Module) func(*Config) error {
	return func(c *Config) error {
		m.Enabled = false
		m.Settings = cloneModuleSettings(m.Settings)
		if strings.TrimSpace(m.EgressGroup) == "" {
			m.EgressGroup = defaultExtensionEgressGroup
		}
		if strings.TrimSpace(m.CaptureDNS) == "" {
			m.CaptureDNS = "trust"
		}
		for i := range c.Modules {
			if c.Modules[i].ID != m.ID {
				continue
			}
			// Replacing keeps the operator's own state: the egress binding, the
			// resolver binding, and the settings they filled in. Those are not
			// the publisher's to reset, and an update that silently cleared them
			// would leave a required setting empty and the extension refusing to
			// enable with no explanation.
			m.EgressGroup = c.Modules[i].EgressGroup
			if strings.TrimSpace(m.EgressGroup) == "" {
				m.EgressGroup = defaultExtensionEgressGroup
			}
			m.CaptureDNS = c.Modules[i].CaptureDNS
			m.Settings = carryOverSettingValues(c.Modules[i].Settings, m.Settings)
			c.Modules[i] = m
			return nil
		}
		c.Modules = append(c.Modules, m)
		c.ExecutionOrder = append(c.ExecutionOrder, m.ID)
		return nil
	}
}

// updateMutation replaces an installed extension without changing whether the
// operator authorized it. The immutable Config pointer is the handoff: requests
// already holding the previous pointer finish on the old programs, while new
// requests can only acquire the fully compiled replacement.
func updateMutation(incoming Module, values SettingValues) func(*Config) error {
	return func(c *Config) error {
		for i := range c.Modules {
			if c.Modules[i].ID != incoming.ID {
				continue
			}
			prepared, err := prepareUpdatedModule(c.Modules[i], incoming, values, c.Modules[i].Enabled)
			if err != nil {
				return err
			}
			c.Modules[i] = prepared
			return nil
		}
		return fmt.Errorf("%w: %q", ErrModuleNotFound, incoming.ID)
	}
}

// prepareUpdatedModule carries only operator-owned state. Publisher-owned
// defaults remain the fallback: an old value wins when its key and type still
// match, otherwise the incoming default stays in place.
func prepareUpdatedModule(previous, incoming Module, values SettingValues, requireReady bool) (Module, error) {
	incoming.Enabled = previous.Enabled
	incoming.EgressGroup = previous.EgressGroup
	if strings.TrimSpace(incoming.EgressGroup) == "" {
		incoming.EgressGroup = defaultExtensionEgressGroup
	}
	incoming.CaptureDNS = previous.CaptureDNS
	if strings.TrimSpace(incoming.CaptureDNS) == "" {
		incoming.CaptureDNS = "trust"
	}
	incoming.Settings = carryOverSettingValues(previous.Settings, cloneModuleSettings(incoming.Settings))
	if values != nil {
		var err error
		incoming.Settings, err = settingsWithCompleteValues(incoming.Settings, values)
		if err != nil {
			return Module{}, err
		}
	}
	if !requireReady {
		return incoming, nil
	}
	if err := validateModuleSettings(incoming.Settings, true); err != nil {
		return Module{}, unprocessableRequest("extension %q settings are not ready: %v", incoming.ID, err)
	}
	if strings.TrimSpace(incoming.EgressGroup) == "" {
		return Module{}, unprocessableRequest("extension %q has no explicit egress binding", incoming.ID)
	}
	return incoming, nil
}

// carryOverSettingValues copies previously entered values onto the incoming
// declaration, by key and only when the type and new constraints still accept
// them.
//
// A type change means the old value is no longer meaningful, and carrying it
// over would store something the new declaration cannot validate.
func carryOverSettingValues(previous, incoming []ModuleSetting) []ModuleSetting {
	incoming = cloneModuleSettings(incoming)
	byKey := make(map[string]ModuleSetting, len(previous))
	for _, s := range previous {
		byKey[s.Key] = s
	}
	for i := range incoming {
		old, ok := byKey[incoming[i].Key]
		if !ok || old.Type != incoming[i].Type || len(old.Value) == 0 ||
			validateSettingValue(incoming[i], old.Value, false) != nil {
			continue
		}
		incoming[i].Value = append(json.RawMessage(nil), old.Value...)
	}
	return incoming
}

// Uninstall removes an extension and its place in the order.
func (e *Engine) Uninstall(revision, id string) (Snapshot, string, error) {
	return e.mutate(revision, func(c *Config) error {
		found := false
		modules := make([]Module, 0, len(c.Modules))
		for _, m := range c.Modules {
			if m.ID == id {
				found = true
				continue
			}
			modules = append(modules, m)
		}
		if !found {
			return fmt.Errorf("%w: %q", ErrModuleNotFound, id)
		}
		order := make([]string, 0, len(c.ExecutionOrder))
		for _, existing := range c.ExecutionOrder {
			if existing != id {
				order = append(order, existing)
			}
		}
		c.Modules = modules
		c.ExecutionOrder = order
		return nil
	})
}
