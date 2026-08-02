package engine

import (
	"encoding/json"
	"errors"
	"fmt"
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
	ErrModuleNotFound = errors.New("gpn/engine: extension not found")
	// ErrInvalidRequest wraps a caller-caused failure the API answers 400 for.
	ErrInvalidRequest = errors.New("gpn/engine: invalid request")
)

// Revision names the current document.
func (e *Engine) Revision() string { return e.config.Revision() }

// ReadDocument returns the current document and its revision.
func (e *Engine) ReadDocument() (Config, string) {
	cfg, _ := e.config.Current()
	return cfg, e.config.Revision()
}

// Detail is one extension in full, minus the script bodies.
//
// The bodies are excluded because a manifest can run to megabytes and the
// review that needs this does not read them -- it reports their digests, which
// is what "the code has not changed since you approved it" actually rests on.
func (e *Engine) Detail(id string) (ModuleDetail, error) {
	cfg, err := e.config.Current()
	if err != nil {
		return ModuleDetail{}, err
	}
	for _, m := range cfg.Modules {
		if m.ID == id {
			return detailOf(m), nil
		}
	}
	return ModuleDetail{}, fmt.Errorf("%w: %q", ErrModuleNotFound, id)
}

// ModuleDetail is everything a review has to state before an operator confirms.
type ModuleDetail struct {
	ModuleSummary
	Description string `json:"description,omitempty"`
	ImportedAt  string `json:"imported_at,omitempty"`
	SourceURL   string `json:"source_url,omitempty"`
	// SourceDigest covers the manifest and every fetched script, so a review can
	// say "this is byte for byte what you approved" without shipping the bytes.
	SourceDigest string `json:"source_digest,omitempty"`

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
		Network:           m.Network,
		PersistentStorage: m.PersistentStorage,
		Settings:          append([]ModuleSetting(nil), m.Settings...),
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
	_, next, err := e.config.Update(revision, func(current Config) (Config, error) {
		candidate := cloneConfig(current)
		if err := fn(&candidate); err != nil {
			return current, err
		}
		return candidate, nil
	})
	if err != nil {
		return Snapshot{}, next, err
	}
	snapshot, err := e.Snapshot()
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
	out.Modules = make([]Module, len(c.Modules))
	for i, m := range c.Modules {
		m.CaptureHosts = copyStrings(m.CaptureHosts)
		m.Settings = append([]ModuleSetting(nil), m.Settings...)
		m.Scripts = append([]ScriptRule(nil), m.Scripts...)
		m.HostMappings = append([]HostMapping(nil), m.HostMappings...)
		m.RoutingRules = append(RoutingRules(nil), m.RoutingRules...)
		out.Modules[i] = m
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
		if enabled && m.EgressGroupRequired && strings.TrimSpace(m.EgressGroup) == "" {
			// Fail closed rather than fall back to a group nobody chose. An
			// extension that declared it needs a specific egress and is enabled
			// without one would otherwise send captured traffic out somewhere
			// the operator did not pick.
			return fmt.Errorf("%w: extension %q requires an egress group binding before it can be enabled", ErrInvalidRequest, id)
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
// group. An empty value clears the binding.
//
// The extension cannot name the group, inspect it, or learn that it changed:
// the manifest may declare that one is required and nothing more. This is the
// operator's choice about where decrypted traffic leaves the box.
func (e *Engine) SetEgressGroup(revision, id, group string) (Snapshot, string, error) {
	return e.mutate(revision, func(c *Config) error {
		m, err := findModule(c, id)
		if err != nil {
			return err
		}
		m.EgressGroup = strings.TrimSpace(group)
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

// SetSettingValue writes one typed setting.
//
// The value is stored raw and validated by the document decode that follows, so
// there is exactly one implementation of what a `select` accepts or what a
// `number` may range over -- the one the engine itself uses.
func (e *Engine) SetSettingValue(revision, id, key string, value json.RawMessage) (Snapshot, string, error) {
	return e.mutate(revision, func(c *Config) error {
		m, err := findModule(c, id)
		if err != nil {
			return err
		}
		for i := range m.Settings {
			if m.Settings[i].Key != key {
				continue
			}
			m.Settings[i].Value = append(json.RawMessage(nil), value...)
			return nil
		}
		return fmt.Errorf("%w: extension %q has no setting %q", ErrInvalidRequest, id, key)
	})
}

// install adds or replaces an extension, always disabled.
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
		m.Enabled = false
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
			m.CaptureDNS = c.Modules[i].CaptureDNS
			m.Settings = carryOverSettingValues(c.Modules[i].Settings, m.Settings)
			c.Modules[i] = m
			return nil
		}
		c.Modules = append(c.Modules, m)
		c.ExecutionOrder = append(c.ExecutionOrder, m.ID)
		return nil
	})
}

// carryOverSettingValues copies previously entered values onto the incoming
// declaration, by key and only when the type still matches.
//
// A type change means the old value is no longer meaningful, and carrying it
// over would store something the new declaration cannot validate.
func carryOverSettingValues(previous, incoming []ModuleSetting) []ModuleSetting {
	byKey := make(map[string]ModuleSetting, len(previous))
	for _, s := range previous {
		byKey[s.Key] = s
	}
	for i := range incoming {
		old, ok := byKey[incoming[i].Key]
		if !ok || old.Type != incoming[i].Type || len(old.Value) == 0 {
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
