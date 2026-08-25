package engine

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/metacubex/mihomo/5gpn/state"
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
// So the Marketplace is a list of manifests and nothing else. There is exactly
// one of it, its URL is compiled into this Core, and it is fetched through the
// same guarded client an import uses. It is never persisted, it is not operator
// state, and it grants no authority: installing from an entry runs exactly the
// review-then-confirm path a pasted URL runs, and the digest the operator
// confirms is computed from a fresh fetch of the manifest rather than from
// anything the listing said.
//
// What the listing *is* allowed to do is contradict itself, and that is worth
// checking. An entry states the manifest's SHA-256 and the shape of what it
// declares -- how many hosts it captures, whether it takes the network grant.
// If the fetched manifest disagrees with the entry that advertised it, the
// index and the publisher have diverged, and an operator reading a listing
// that says "no network access" would be confirming something else. That is
// refused rather than reported, because the review is the screen where the
// operator decides, and the wrong description reaching it is the failure.
//
// The Marketplace does not become an update source by existing. CheckUpdate
// re-reads the URL an extension was installed from and never an entry that
// happens to share its id, because a listing that could redirect on its own
// would mean a publisher silently replaces installed code.
//
// It can change one when asked. ApplyCatalogUpdate takes a specific entry for a
// specific extension, and moves that extension's source to it. The distinction
// is not "may the source ever change" but "may it change without being asked".

const (
	maxCatalogEntries    = 512
	maxCatalogIndexBytes = 2 << 20

	// How long a fetched index is reused. The extensions page is opened,
	// scrolled and reopened; refetching per render would put a request on the
	// publishing host for every one of those. An operator who wants the newest
	// listing asks for it, and that bypasses this.
	catalogCacheTTL = 5 * time.Minute

	catalogAPIVersion = "5gpn.io/marketplace/v1"
	catalogKind       = "ExtensionMarketplace"

	// officialCatalogIndexURL is the one Marketplace this Core reads. It is
	// compiled in rather than configured: an operator cannot add, rename,
	// reorder or disable a discovery source, so there is no stored list to
	// reconcile across two Console tabs and no way for a gateway to end up
	// pointed at an index nobody audited. Pasting an arbitrary HTTPS manifest
	// URL is untouched and remains the way to install something that is not
	// listed here; what is retired is the second, persistent kind of trust an
	// operator-added index carried.
	//
	// The /v2/ is the publication path on GitHub Pages, not the wire schema.
	// catalogAPIVersion above is the schema, and it is still v1.
	officialCatalogIndexURL = "https://moooyo.github.io/5gpn-extensions/marketplace/v2/index.json"
)

// CatalogMetadata is what an index says about itself.
type CatalogMetadata struct {
	ID          string `json:"id,omitempty"`
	Name        string `json:"name,omitempty"`
	Description string `json:"description,omitempty"`
	Homepage    string `json:"homepage,omitempty"`
}

// CatalogResource is the entry's manifest reference and digest. External
// scripts remain live snapshot dependencies and are not a parallel catalog
// resource list.
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
	// InstalledCurrent is true when the publisher version and manifest bytes
	// installed on this gateway match this catalog entry. External script URLs
	// are intentionally live and are not part of this listing status.
	InstalledCurrent bool `json:"installed_current,omitempty"`
}

// catalogIndex is the wire shape. It is decoded leniently -- unknown fields are
// ignored rather than rejected.
//
// The index is a contract with every deployed gateway. A publisher may add
// metadata for a newer core, and an older core must keep the fields it
// understands available rather than refusing the complete discovery source.
// Unknown fields therefore remain generic forward-compatible metadata; they
// never become runtime authority.
type catalogIndex struct {
	APIVersion string          `json:"apiVersion"`
	Kind       string          `json:"kind"`
	Metadata   CatalogMetadata `json:"metadata"`
	Entries    []CatalogEntry  `json:"entries"`
}

// CatalogView is the built-in Marketplace as the Console renders it: where it
// was read from, what it says about itself, and whatever the last fetch
// produced.
//
// Error may accompany Entries from the last complete successful fetch. An index
// that has never been reached appears with an empty list and the reason; one
// whose refresh fails keeps its prior snapshot visible so a transient failure
// cannot masquerade as the publisher deleting every extension.
//
// Entries is always an array and never null: the Console reads a length off it
// without checking first.
type CatalogView struct {
	URL       string          `json:"url"`
	Error     string          `json:"error,omitempty"`
	FetchedAt string          `json:"fetched_at,omitempty"`
	Metadata  CatalogMetadata `json:"metadata"`
	Entries   []CatalogEntry  `json:"entries"`
}

// Catalog fetches the Marketplace and reports what it lists.
func (e *Engine) Catalog(ctx context.Context, refresh bool) (CatalogView, error) {
	catalog, _, err := e.CatalogWithRevision(ctx, refresh)
	return catalog, err
}

// CatalogWithRevision pairs discovery with the committed config that supplied
// its installed-version projection. Network fetches may take time, but a
// concurrent edit cannot relabel the resulting old view as new.
func (e *Engine) CatalogWithRevision(ctx context.Context, refresh bool) (CatalogView, string, error) {
	committed, err := e.CommittedView()
	if err != nil {
		return CatalogView{}, "", err
	}
	type installedIdentity struct {
		version        string
		manifestDigest string
	}
	installed := make(map[string]installedIdentity, len(committed.Config.Modules))
	for _, m := range committed.Config.Modules {
		installed[m.ID] = installedIdentity{version: m.Version, manifestDigest: m.Source.Digest}
	}

	view := CatalogView{URL: officialCatalogIndexURL, Entries: []CatalogEntry{}}
	index, fetchedAt, available, err := e.catalogIndexFor(ctx, refresh)
	if err != nil {
		view.Error = err.Error()
		// A refresh attempt is advisory, not a transaction that deletes the last
		// complete discovery snapshot. catalogIndexFor returns that retained
		// index with the fetch error when one exists, so the Console can keep
		// rendering known entries while making the failure visible.
		if !available {
			return view, committed.Revision, nil
		}
	}
	view.Metadata = index.Metadata
	view.FetchedAt = fetchedAt.UTC().Format(time.RFC3339)
	for _, entry := range index.Entries {
		if identity, ok := installed[entry.ID]; ok {
			entry.InstalledVersion = identity.version
			entry.InstalledCurrent = identity.version == entry.Version &&
				validLowerHex(entry.Manifest.SHA256, 64) &&
				strings.EqualFold(identity.manifestDigest, entry.Manifest.SHA256)
		}
		view.Entries = append(view.Entries, entry)
	}
	return view, committed.Revision, nil
}

// ReviewCatalogEntry is the review step for an entry, and the only place the
// Marketplace's claims are held to the manifest.
//
// It returns exactly what postReview returns for a pasted URL, so installing
// from the Marketplace is the same confirmation with the same digest and the
// same re-fetch. The difference is entirely in what happens before: the
// manifest is checked against the digest and the shape the entry advertised,
// and a disagreement refuses rather than being reported alongside a review the
// operator would then confirm.
func (e *Engine) ReviewCatalogEntry(ctx context.Context, entryID string) (Candidate, error) {
	candidate, _, _, err := e.ReviewCatalogEntryView(ctx, entryID)
	return candidate, err
}

// ReviewCatalogEntryView returns the exact URL named by the selected entry and
// the committed revision used by the review. The URL is an opaque review token:
// a redirect may make Candidate.Detail.SourceURL different, and a client must
// still quote this selected-entry URL rather than reconstructing it.
func (e *Engine) ReviewCatalogEntryView(ctx context.Context, entryID string) (Candidate, string, string, error) {
	reviewView, err := e.CommittedView()
	if err != nil {
		return Candidate{}, "", "", err
	}
	entry, err := e.catalogEntry(ctx, entryID)
	if err != nil {
		return Candidate{}, "", reviewView.Revision, err
	}
	candidate, candidateView, err := e.fetchCandidateView(ctx, ImportRequest{URL: entry.Manifest.URL})
	if err != nil {
		if current := e.Revision(); current != reviewView.Revision {
			return Candidate{}, entry.Manifest.URL, current, state.ErrRevisionConflict
		}
		return Candidate{}, entry.Manifest.URL, reviewView.Revision, err
	}
	if candidateView.Revision != reviewView.Revision {
		return Candidate{}, entry.Manifest.URL, candidateView.Revision, state.ErrRevisionConflict
	}
	if err := e.verifyAgainstEntry(entry, candidate); err != nil {
		return Candidate{}, entry.Manifest.URL, candidateView.Revision, err
	}
	return candidate, entry.Manifest.URL, candidateView.Revision, nil
}

// ApplyCatalogUpdate replaces an installed extension with a Marketplace entry's
// version, and in doing so changes where that extension's code comes from.
//
// That is the whole weight of this call, and it is why it is a separate one.
// CheckUpdate deliberately re-reads only the URL an extension was installed
// from: a source that could change on its own would mean a republished listing
// silently redirects installed code. Here the operator picked this entry for
// this extension — so the redirection is the thing they asked for rather than a
// side effect of a listing moving underneath them.
//
// Everything the ordinary update path checks still applies: the fetched
// manifest must still be the same extension id and its digest must match what
// was reviewed. On top of that the entry's own claims are checked, so the
// Marketplace cannot advertise one shape and update to another.
func (e *Engine) ApplyCatalogUpdate(ctx context.Context, revision, entryID, reviewedURL, digest string) (Snapshot, string, error) {
	return e.ApplyCatalogUpdateWithSettings(ctx, revision, entryID, reviewedURL, digest, nil)
}

// ApplyCatalogUpdateWithSettings is the Marketplace variant of
// ApplyUpdateWithSettings. Values, when present, are the complete proposed
// settings document for the freshly fetched candidate.
func (e *Engine) ApplyCatalogUpdateWithSettings(
	ctx context.Context,
	revision, entryID, reviewedURL, digest string,
	values SettingValues,
) (Snapshot, string, error) {
	reviewedURL = strings.TrimSpace(reviewedURL)
	if reviewedURL == "" {
		return Snapshot{}, revision, fmt.Errorf("%w: reviewed catalog manifest URL is required", ErrInvalidRequest)
	}
	view, err := e.CommittedView()
	if err != nil {
		return Snapshot{}, revision, err
	}
	if revision != "" && revision != view.Revision {
		return Snapshot{}, view.Revision, state.ErrRevisionConflict
	}
	entry, err := e.catalogEntry(ctx, entryID)
	if err != nil {
		if errors.Is(err, ErrModuleNotFound) {
			return Snapshot{}, revision, reviewConflictf("the selected Marketplace entry changed since you reviewed it: %v", err)
		}
		return Snapshot{}, revision, err
	}
	if entry.Manifest.URL != reviewedURL {
		return Snapshot{}, revision, reviewConflictf(
			"the selected Marketplace entry changed manifest URL since you reviewed it (%s, not %s)",
			entry.Manifest.URL, reviewedURL,
		)
	}
	installed, err := updatableModule(view.Config, entry.ID)
	if err != nil {
		return Snapshot{}, revision, err
	}
	// Naming the move explicitly rather than performing it silently: an
	// operator reading the log should see that the source changed.
	if previous := strings.TrimSpace(installed.Source.URL); previous != "" && previous != entry.Manifest.URL {
		log.Infoln("[5GPN] extension %s updates from %s, previously %s", entry.ID, entry.Manifest.URL, previous)
	}
	return e.applyUpdateFrom(ctx, revision, entry.ID, reviewedURL, digest, values, func(module Module) error {
		return e.verifyAgainstEntry(entry, Candidate{Detail: detailOf(module)})
	})
}

// catalogEntry is the only path from an entry id to a manifest URL, and both
// review and apply take it.
//
// An entry the index no longer lists is ErrModuleNotFound rather than a plain
// failure, because ApplyCatalogUpdateWithSettings turns exactly that error into
// a review conflict: the operator reviewed something that has since been
// withdrawn, which is a stale confirmation and not a missing route.
func (e *Engine) catalogEntry(ctx context.Context, entryID string) (CatalogEntry, error) {
	index, _, _, err := e.catalogIndexFor(ctx, false)
	if err != nil {
		return CatalogEntry{}, err
	}
	for _, entry := range index.Entries {
		if entry.ID == entryID {
			return entry, nil
		}
	}
	return CatalogEntry{}, fmt.Errorf("%w: the Marketplace lists no extension %q", ErrModuleNotFound, entryID)
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
	if detail.Version != entry.Version {
		return fmt.Errorf("%w: %s serves version %q, which the catalog lists as %q",
			ErrInvalidRequest, entry.Manifest.URL, detail.Version, entry.Version)
	}
	if want := strings.ToLower(strings.TrimSpace(entry.Manifest.SHA256)); !validLowerHex(want, 64) || want != detail.SourceDigest {
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

// catalogIndexFor fetches the Marketplace index, or reuses one fetched
// recently. available distinguishes a retained complete snapshot from the zero
// value when a fetch fails; callers that only authorize reviews still treat any
// error as fatal.
func (e *Engine) catalogIndexFor(ctx context.Context, refresh bool) (catalogIndex, time.Time, bool, error) {
	if !refresh {
		if cached, cachedAt, ok := e.catalogs.get(); ok {
			return cached, cachedAt, true, nil
		}
	}
	imp, err := currentImporter()
	if err != nil {
		if retained, retainedAt, retainedOK := e.catalogs.retained(); retainedOK {
			return retained, retainedAt, true, err
		}
		return catalogIndex{}, time.Time{}, false, err
	}
	index, err := imp.catalog(ctx, officialCatalogIndexURL)
	if err != nil {
		if retained, retainedAt, retainedOK := e.catalogs.retained(); retainedOK {
			return retained, retainedAt, true, err
		}
		return catalogIndex{}, time.Time{}, false, err
	}
	at := imp.clock().UTC()
	e.catalogs.put(index, at)
	return index, at, true, nil
}

// catalog fetches and decodes one index through the guarded client.
func (imp *Importer) catalog(ctx context.Context, rawURL string) (catalogIndex, error) {
	body, _, err := imp.fetch(ctx, rawURL, maxCatalogIndexBytes)
	if err != nil {
		return catalogIndex{}, fmt.Errorf("fetch catalog: %w", err)
	}
	if err := state.ValidateJSONBytes(body, maxCatalogIndexBytes); err != nil {
		return catalogIndex{}, fmt.Errorf("%w: the catalog is not valid JSON: %v", ErrInvalidRequest, err)
	}
	var index catalogIndex
	if err := json.Unmarshal(body, &index); err != nil {
		return catalogIndex{}, fmt.Errorf("%w: the catalog is not valid JSON: %v", ErrInvalidRequest, err)
	}
	if index.APIVersion != catalogAPIVersion || index.Kind != catalogKind {
		return catalogIndex{}, fmt.Errorf("%w: not an extension catalog (apiVersion %q, kind %q)",
			ErrInvalidRequest, index.APIVersion, index.Kind)
	}
	if index.Entries == nil {
		return catalogIndex{}, fmt.Errorf("%w: catalog entries must be an array", ErrInvalidRequest)
	}
	if len(index.Entries) > maxCatalogEntries {
		return catalogIndex{}, fmt.Errorf("%w: the catalog lists more than %d extensions", ErrInvalidRequest, maxCatalogEntries)
	}
	seen := make(map[string]struct{}, len(index.Entries))
	for position := range index.Entries {
		entry := &index.Entries[position]
		// A partial parse must never replace a complete cached index. Reject the
		// candidate document as one transaction; catalogIndexFor retains the last
		// successful snapshot and exposes this error beside it.
		if !validModuleID(entry.ID) {
			return catalogIndex{}, fmt.Errorf("%w: catalog entry %d has invalid id %q", ErrInvalidRequest, position+1, entry.ID)
		}
		if _, duplicate := seen[entry.ID]; duplicate {
			return catalogIndex{}, fmt.Errorf("%w: catalog lists extension %q more than once", ErrInvalidRequest, entry.ID)
		}
		if err := checkResourceURL(entry.Manifest.URL); err != nil {
			return catalogIndex{}, fmt.Errorf("%w: catalog entry %q manifest URL: %v", ErrInvalidRequest, entry.ID, err)
		}
		entry.Manifest.SHA256 = strings.ToLower(strings.TrimSpace(entry.Manifest.SHA256))
		if !validLowerHex(entry.Manifest.SHA256, 64) {
			return catalogIndex{}, fmt.Errorf("%w: catalog entry %q has invalid manifest digest", ErrInvalidRequest, entry.ID)
		}
		seen[entry.ID] = struct{}{}
	}
	return index, nil
}

// catalogCache holds the last complete successful index. One slot, because
// there is one Marketplace. catalogCacheTTL controls when normal reads attempt
// another fetch; an older snapshot remains the failure fallback until a
// complete successor replaces it. Nothing here is persisted: an index is
// refetchable by definition, and writing one to disk would make stale discovery
// state survive a process start.
type catalogCache struct {
	mu        sync.Mutex
	present   bool
	index     catalogIndex
	fetchedAt time.Time
}

func (c *catalogCache) get() (catalogIndex, time.Time, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.present || time.Since(c.fetchedAt) > catalogCacheTTL {
		return catalogIndex{}, time.Time{}, false
	}
	return c.index, c.fetchedAt, true
}

// retained returns the last complete successful fetch regardless of age. TTL
// decides when to attempt a refresh; it is not permission to erase discovery
// state when that attempt fails.
func (c *catalogCache) retained() (catalogIndex, time.Time, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.present {
		return catalogIndex{}, time.Time{}, false
	}
	return c.index, c.fetchedAt, true
}

func (c *catalogCache) put(index catalogIndex, at time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.index = index
	c.fetchedAt = at
	c.present = true
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
