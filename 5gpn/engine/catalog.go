package engine

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/metacubex/mihomo/log"
)

// Extension discovery.
//
// The install path has never been the missing piece: review, digest, install
// and update-check are complete and each one is a decision the operator makes
// about a specific manifest URL. What was missing is finding the URL at all,
// which meant an operator had to already know what they wanted and where it
// lived.
//
// So a catalog is a list of manifests and nothing else. It is fetched through
// the same guarded client an import uses, it is never persisted, and it grants
// no authority: installing from an entry runs exactly the review-then-confirm
// path a pasted URL runs, and the digest the operator confirms is computed from
// a fresh fetch of the manifest rather than from anything the catalog said.
//
// What the catalog *is* allowed to do is contradict itself, and that is worth
// checking. An entry states the manifest's SHA-256 and the shape of what it
// declares -- how many hosts it captures, whether it takes the network grant.
// If the fetched manifest disagrees with the entry that advertised it, the
// catalog and the publisher have diverged, and an operator reading a listing
// that says "no network access" would be confirming something else. That is
// refused rather than reported, because the review is the screen where the
// operator decides, and the wrong description reaching it is the failure.
//
// A catalog does not become an update source by existing. CheckUpdate re-reads
// the URL an extension was installed from and never an entry that happens to
// share its id, because a source that could change on its own would mean adding
// a catalog silently redirects installed code.
//
// It can change one when asked. ApplyCatalogUpdate takes a specific entry in a
// specific catalog for a specific extension, and moves that extension's source
// to it. The distinction is not "may the source ever change" but "may it change
// without being asked".

const (
	// The first-party catalog, seeded into every new document. An operator who
	// does not want it can disable or remove it; it is a default, not a
	// built-in.
	officialCatalogID  = "io.5gpn.official"
	officialCatalogURL = "https://moooyo.github.io/5gpn-extensions/marketplace/v2/index.json"

	maxCatalogSources    = 16
	maxCatalogEntries    = 512
	maxCatalogIndexBytes = 2 << 20
	maxCatalogNameBytes  = 128

	// How long a fetched index is reused. The extensions page is opened,
	// scrolled and reopened; refetching per render would put a request on a
	// third-party host for every one of those. An operator who wants the newest
	// listing asks for it, and that bypasses this.
	catalogCacheTTL = 5 * time.Minute

	catalogAPIVersion = "5gpn.io/marketplace/v1"
	catalogKind       = "ExtensionMarketplace"
)

// CatalogSource is one configured catalog. This is the only part of discovery
// that is operator state, and it lives in the interception document with every
// other interception decision.
type CatalogSource struct {
	ID string `json:"id"`
	// Name is the operator's own label, which survives whatever the index calls
	// itself. A source that cannot be fetched still has to be nameable in the
	// list it is removed from.
	Name    string `json:"name,omitempty"`
	URL     string `json:"url"`
	Enabled bool   `json:"enabled"`
}

// CatalogMetadata is what an index says about itself.
type CatalogMetadata struct {
	ID          string `json:"id,omitempty"`
	Name        string `json:"name,omitempty"`
	Description string `json:"description,omitempty"`
	Homepage    string `json:"homepage,omitempty"`
}

// CatalogResource is a fetchable artefact with its digest.
type CatalogResource struct {
	URL    string `json:"url"`
	SHA256 string `json:"sha256"`
	Size   int64  `json:"size,omitempty"`
}

// CatalogLicense is the entry's stated licence.
type CatalogLicense struct {
	SPDX string `json:"spdx,omitempty"`
	URL  string `json:"url,omitempty"`
}

// CatalogCapabilities is the shape the publisher says the manifest has.
//
// It is the listing's claim about what enabling this extension would authorize,
// and it is what an operator reads before deciding to review at all. Every
// field here is checked against the parsed manifest before a review is
// returned; see reviewMismatch.
//
// RoutingRuleCount is a pointer because an index that predates the field must
// be unverified rather than treated as claiming zero.
type CatalogCapabilities struct {
	CaptureHostCount     int  `json:"captureHostCount"`
	ActionCount          int  `json:"actionCount"`
	SettingCount         int  `json:"settingCount"`
	Network              bool `json:"network"`
	PersistentStorage    bool `json:"persistentStorage"`
	UpstreamMappingCount int  `json:"upstreamMappingCount"`
	EgressGroupRequired  bool `json:"egressGroupRequired"`
	RoutingRuleCount     *int `json:"routingRuleCount"`
}

// CatalogEntry is one extension as the index advertises it.
type CatalogEntry struct {
	ID               string              `json:"id"`
	Name             string              `json:"name,omitempty"`
	Version          string              `json:"version,omitempty"`
	Description      string              `json:"description,omitempty"`
	Tags             []string            `json:"tags,omitempty"`
	License          CatalogLicense      `json:"license,omitempty"`
	DocumentationURL string              `json:"documentationUrl,omitempty"`
	Manifest         CatalogResource     `json:"manifest"`
	Capabilities     CatalogCapabilities `json:"capabilities"`

	// InstalledVersion is filled in by this gateway, not by the index: it is
	// what is installed under this id here, empty when nothing is. It lets the
	// listing say "2.1.0 installed, 2.2.0 available" without a second read.
	InstalledVersion string `json:"installed_version,omitempty"`
}

// catalogIndex is the wire shape. It is decoded leniently -- unknown fields are
// ignored rather than rejected.
//
// The previous implementation rejected them, and the comment it left behind is
// the argument against doing so again: the index is a contract with every
// deployed gateway, so a field added for newer cores made older ones refuse the
// whole document, and a catalog nobody can read is worse than one carrying a
// field this build does not use. The published index carries exactly such a
// field today -- a `policy` projection of the retired overlay compiler, which
// means nothing to a monolith gateway and is ignored here.
type catalogIndex struct {
	APIVersion string          `json:"apiVersion"`
	Kind       string          `json:"kind"`
	Metadata   CatalogMetadata `json:"metadata"`
	Entries    []CatalogEntry  `json:"entries"`
}

// CatalogSourceView is one source as the console renders it: the operator's
// configuration, plus whatever the last fetch produced.
//
// Error and Entries are alternatives. A source that failed still appears, with
// the reason, because the page it would otherwise break is the only place it
// can be corrected or removed.
type CatalogSourceView struct {
	ID        string          `json:"id"`
	Name      string          `json:"name,omitempty"`
	URL       string          `json:"url"`
	Enabled   bool            `json:"enabled"`
	Error     string          `json:"error,omitempty"`
	FetchedAt string          `json:"fetched_at,omitempty"`
	Metadata  CatalogMetadata `json:"metadata"`
	Entries   []CatalogEntry  `json:"entries"`
}

// CatalogView is every configured source, in the order the document lists them.
type CatalogView struct {
	Sources []CatalogSourceView `json:"sources"`
}

// Catalog fetches every enabled source and reports what they list.
//
// A disabled source is reported without being fetched: it is still the
// operator's configuration and still has to be visible to re-enable.
func (e *Engine) Catalog(ctx context.Context, refresh bool) (CatalogView, error) {
	cfg, err := e.config.Current()
	if err != nil {
		return CatalogView{}, err
	}
	installed := make(map[string]string, len(cfg.Modules))
	for _, m := range cfg.Modules {
		installed[m.ID] = m.Version
	}

	view := CatalogView{Sources: make([]CatalogSourceView, 0, len(cfg.Catalogs))}
	for _, source := range cfg.Catalogs {
		rendered := CatalogSourceView{
			ID: source.ID, Name: source.Name, URL: source.URL, Enabled: source.Enabled,
			Entries: []CatalogEntry{},
		}
		if !source.Enabled {
			view.Sources = append(view.Sources, rendered)
			continue
		}
		index, fetchedAt, err := e.catalogIndexFor(ctx, source.URL, refresh)
		if err != nil {
			rendered.Error = err.Error()
			view.Sources = append(view.Sources, rendered)
			continue
		}
		rendered.Metadata = index.Metadata
		rendered.FetchedAt = fetchedAt.UTC().Format(time.RFC3339)
		for _, entry := range index.Entries {
			entry.InstalledVersion = installed[entry.ID]
			rendered.Entries = append(rendered.Entries, entry)
		}
		view.Sources = append(view.Sources, rendered)
	}
	return view, nil
}

// SetCatalogSources replaces the configured catalogs.
//
// One write for the whole list rather than add and remove, because the list is
// ordered and an id is only unique within it: reconciling two independent edits
// would need a per-source revision, which is a lot of machinery for a field an
// operator changes a handful of times in the life of a gateway.
func (e *Engine) SetCatalogSources(revision string, sources []CatalogSource) (Snapshot, string, error) {
	normalised, err := normaliseCatalogSources(sources)
	if err != nil {
		return Snapshot{}, revision, err
	}
	return e.mutate(revision, func(c *Config) error {
		c.Catalogs = normalised
		return nil
	})
}

// ReviewCatalogEntry is the review step for an entry, and the only place the
// catalog's claims are held to the manifest.
//
// It returns exactly what postReview returns for a pasted URL, so installing
// from a catalog is the same confirmation with the same digest and the same
// re-fetch. The difference is entirely in what happens before: the manifest is
// checked against the digest and the shape the entry advertised, and a
// disagreement refuses rather than being reported alongside a review the
// operator would then confirm.
func (e *Engine) ReviewCatalogEntry(ctx context.Context, sourceID, entryID string) (Candidate, error) {
	entry, err := e.catalogEntry(ctx, sourceID, entryID)
	if err != nil {
		return Candidate{}, err
	}
	candidate, err := e.Fetch(ctx, ImportRequest{URL: entry.Manifest.URL})
	if err != nil {
		return Candidate{}, err
	}
	if err := e.verifyAgainstEntry(entry, candidate); err != nil {
		return Candidate{}, err
	}
	return candidate, nil
}

// CatalogEntrySource resolves an entry to the manifest URL an install must
// quote, so a client never has to reconstruct it from the listing.
func (e *Engine) CatalogEntrySource(ctx context.Context, sourceID, entryID string) (string, error) {
	entry, err := e.catalogEntry(ctx, sourceID, entryID)
	if err != nil {
		return "", err
	}
	return entry.Manifest.URL, nil
}

// ApplyCatalogUpdate replaces an installed extension with a catalog entry's
// version, and in doing so changes where that extension's code comes from.
//
// That is the whole weight of this call, and it is why it is a separate one.
// CheckUpdate deliberately re-reads only the URL an extension was installed
// from: a source that could change on its own would mean adding a catalog
// silently redirects installed code. Here the operator picked this entry, in
// this catalog, for this extension — so the redirection is the thing they
// asked for rather than a side effect of configuration.
//
// Everything the ordinary update path checks still applies: the extension must
// be disabled, the fetched manifest must still be the same extension id, and
// its digest must match what was reviewed. On top of that the entry's own
// claims are checked, so a catalog cannot advertise one shape and update to
// another.
func (e *Engine) ApplyCatalogUpdate(ctx context.Context, revision, sourceID, entryID, digest string) (Snapshot, string, error) {
	entry, err := e.catalogEntry(ctx, sourceID, entryID)
	if err != nil {
		return Snapshot{}, revision, err
	}
	cfg, err := e.config.Current()
	if err != nil {
		return Snapshot{}, revision, err
	}
	installed, err := updatableModule(cfg, entry.ID)
	if err != nil {
		return Snapshot{}, revision, err
	}
	// Naming the move explicitly rather than performing it silently: an
	// operator reading the log should see that the source changed.
	if previous := strings.TrimSpace(installed.Source.URL); previous != "" && previous != entry.Manifest.URL {
		log.Infoln("[5GPN] extension %s updates from %s, previously %s", entry.ID, entry.Manifest.URL, previous)
	}
	return e.applyUpdateFrom(ctx, revision, entry.ID, entry.Manifest.URL, digest, func(module Module) error {
		return e.verifyAgainstEntry(entry, Candidate{Detail: detailOf(module)})
	})
}

func (e *Engine) catalogEntry(ctx context.Context, sourceID, entryID string) (CatalogEntry, error) {
	cfg, err := e.config.Current()
	if err != nil {
		return CatalogEntry{}, err
	}
	for _, source := range cfg.Catalogs {
		if source.ID != sourceID {
			continue
		}
		if !source.Enabled {
			return CatalogEntry{}, fmt.Errorf("%w: catalog %q is disabled", ErrInvalidRequest, sourceID)
		}
		index, _, err := e.catalogIndexFor(ctx, source.URL, false)
		if err != nil {
			return CatalogEntry{}, err
		}
		for _, entry := range index.Entries {
			if entry.ID == entryID {
				return entry, nil
			}
		}
		return CatalogEntry{}, fmt.Errorf("%w: catalog %q lists no extension %q", ErrModuleNotFound, sourceID, entryID)
	}
	return CatalogEntry{}, fmt.Errorf("%w: no catalog %q is configured", ErrModuleNotFound, sourceID)
}

// verifyAgainstEntry refuses a review whose manifest does not match the listing
// that led the operator to it.
//
// The digest check is the strong one: it says the bytes are the bytes the
// catalog published. The capability checks are the useful one: they say the
// listing an operator read -- "captures two hosts, no network access" --
// describes the manifest they are about to confirm. A publisher who widens an
// extension without republishing the entry produces exactly that disagreement,
// and the review screen is the last place it can be caught.
func (e *Engine) verifyAgainstEntry(entry CatalogEntry, candidate Candidate) error {
	detail := candidate.Detail
	if detail.ID != entry.ID {
		return fmt.Errorf("%w: %s serves extension %q, which the catalog lists as %q",
			ErrInvalidRequest, entry.Manifest.URL, detail.ID, entry.ID)
	}
	if want := strings.ToLower(strings.TrimSpace(entry.Manifest.SHA256)); want != "" && want != detail.SourceDigest {
		return fmt.Errorf("%w: the manifest at %s does not match the digest the catalog published (%s, not %s)",
			ErrInvalidRequest, entry.Manifest.URL, detail.SourceDigest, want)
	}

	declared := entry.Capabilities
	type claim struct {
		what string
		got  any
		want any
	}
	claims := []claim{
		{"capture hosts", len(detail.CaptureHosts), declared.CaptureHostCount},
		{"actions", len(detail.Actions), declared.ActionCount},
		{"settings", len(detail.Settings), declared.SettingCount},
		{"upstream mappings", len(detail.HostMappings), declared.UpstreamMappingCount},
		{"the network grant", detail.Network, declared.Network},
		{"persistent storage", detail.PersistentStorage, declared.PersistentStorage},
		{"an egress group requirement", detail.EgressGroupRequired, declared.EgressGroupRequired},
	}
	// An index that predates the routing-rule count says nothing about it, which
	// is not the same as claiming zero.
	if declared.RoutingRuleCount != nil {
		claims = append(claims, claim{"routing rules", len(detail.RoutingRules), *declared.RoutingRuleCount})
	}
	for _, c := range claims {
		if c.got != c.want {
			return fmt.Errorf("%w: %s advertises %v for %s but the manifest declares %v; the catalog and the publisher have diverged",
				ErrInvalidRequest, catalogHost(entry.Manifest.URL), c.want, c.what, c.got)
		}
	}
	return nil
}

// catalogIndexFor fetches an index, or reuses one fetched recently.
func (e *Engine) catalogIndexFor(ctx context.Context, rawURL string, refresh bool) (catalogIndex, time.Time, error) {
	if !refresh {
		if cached, at, ok := e.catalogs.get(rawURL); ok {
			return cached, at, nil
		}
	}
	imp, err := currentImporter()
	if err != nil {
		return catalogIndex{}, time.Time{}, err
	}
	index, err := imp.catalog(ctx, rawURL)
	if err != nil {
		return catalogIndex{}, time.Time{}, err
	}
	at := imp.clock().UTC()
	e.catalogs.put(rawURL, index, at)
	return index, at, nil
}

// catalog fetches and decodes one index through the guarded client.
func (imp *Importer) catalog(ctx context.Context, rawURL string) (catalogIndex, error) {
	body, _, err := imp.fetch(ctx, rawURL, maxCatalogIndexBytes)
	if err != nil {
		return catalogIndex{}, fmt.Errorf("fetch catalog: %w", err)
	}
	var index catalogIndex
	if err := json.Unmarshal(body, &index); err != nil {
		return catalogIndex{}, fmt.Errorf("%w: the catalog is not valid JSON: %v", ErrInvalidRequest, err)
	}
	if index.APIVersion != catalogAPIVersion || index.Kind != catalogKind {
		return catalogIndex{}, fmt.Errorf("%w: not an extension catalog (apiVersion %q, kind %q)",
			ErrInvalidRequest, index.APIVersion, index.Kind)
	}
	if len(index.Entries) > maxCatalogEntries {
		return catalogIndex{}, fmt.Errorf("%w: the catalog lists more than %d extensions", ErrInvalidRequest, maxCatalogEntries)
	}
	kept := make([]CatalogEntry, 0, len(index.Entries))
	seen := make(map[string]struct{}, len(index.Entries))
	for _, entry := range index.Entries {
		// A malformed entry is dropped rather than failing the catalog: one bad
		// listing must not hide every other extension a publisher offers.
		if !validModuleID(entry.ID) {
			continue
		}
		if _, duplicate := seen[entry.ID]; duplicate {
			continue
		}
		if err := checkResourceURL(entry.Manifest.URL); err != nil {
			continue
		}
		seen[entry.ID] = struct{}{}
		kept = append(kept, entry)
	}
	index.Entries = kept
	return index, nil
}

// catalogCache holds fetched indexes for catalogCacheTTL. Nothing here is
// persisted: an index is refetchable by definition, and writing one to disk
// would make a stale listing outlive the process that fetched it.
type catalogCache struct {
	mu      sync.Mutex
	entries map[string]catalogCacheEntry
}

type catalogCacheEntry struct {
	index     catalogIndex
	fetchedAt time.Time
}

func (c *catalogCache) get(rawURL string) (catalogIndex, time.Time, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	cached, ok := c.entries[rawURL]
	if !ok || time.Since(cached.fetchedAt) > catalogCacheTTL {
		return catalogIndex{}, time.Time{}, false
	}
	return cached.index, cached.fetchedAt, true
}

func (c *catalogCache) put(rawURL string, index catalogIndex, at time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.entries == nil {
		c.entries = make(map[string]catalogCacheEntry, 4)
	}
	// Bounded by the source limit, and a source that is removed leaves at most
	// one stale entry behind until the process restarts.
	if len(c.entries) > maxCatalogSources {
		c.entries = make(map[string]catalogCacheEntry, 4)
	}
	c.entries[rawURL] = catalogCacheEntry{index: index, fetchedAt: at}
}

// normaliseCatalogSources validates and canonicalises a proposed source list.
func normaliseCatalogSources(sources []CatalogSource) ([]CatalogSource, error) {
	if len(sources) > maxCatalogSources {
		return nil, fmt.Errorf("%w: at most %d catalogs may be configured", ErrInvalidRequest, maxCatalogSources)
	}
	out := make([]CatalogSource, 0, len(sources))
	seenID := make(map[string]struct{}, len(sources))
	seenURL := make(map[string]struct{}, len(sources))
	for _, source := range sources {
		id := strings.TrimSpace(source.ID)
		if !validModuleID(id) {
			return nil, fmt.Errorf("%w: catalog id %q is not a valid identifier", ErrInvalidRequest, source.ID)
		}
		if _, duplicate := seenID[id]; duplicate {
			return nil, fmt.Errorf("%w: catalog id %q is listed twice", ErrInvalidRequest, id)
		}
		raw := strings.TrimSpace(source.URL)
		if err := checkResourceURL(raw); err != nil {
			return nil, fmt.Errorf("%w: catalog %q: %v", ErrInvalidRequest, id, err)
		}
		if _, duplicate := seenURL[raw]; duplicate {
			return nil, fmt.Errorf("%w: %s is listed twice", ErrInvalidRequest, raw)
		}
		name := strings.TrimSpace(source.Name)
		if len(name) > maxCatalogNameBytes {
			return nil, fmt.Errorf("%w: catalog %q name exceeds %d bytes", ErrInvalidRequest, id, maxCatalogNameBytes)
		}
		seenID[id] = struct{}{}
		seenURL[raw] = struct{}{}
		out = append(out, CatalogSource{ID: id, Name: name, URL: raw, Enabled: source.Enabled})
	}
	return out, nil
}

// validateCatalogs is the document-level check, run on every decode so a
// hand-edited file is held to the same rule an API write is.
func validateCatalogs(sources []CatalogSource) error {
	if _, err := normaliseCatalogSources(sources); err != nil {
		return err
	}
	return nil
}

// defaultCatalogSources is what a new document is seeded with.
func defaultCatalogSources() []CatalogSource {
	return []CatalogSource{{
		ID:      officialCatalogID,
		Name:    "5gpn Official Extensions",
		URL:     officialCatalogURL,
		Enabled: true,
	}}
}

// catalogHost is used only in messages, to name the host an operator would have
// to reach without making them read a URL back out of an error.
func catalogHost(rawURL string) string {
	parsed, err := url.Parse(rawURL)
	if err != nil || parsed.Host == "" {
		return rawURL
	}
	return parsed.Host
}
