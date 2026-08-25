package engine

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/metacubex/mihomo/5gpn/state"
)

// The catalog, at the two points where it can do harm: what it accepts off the
// wire, and whether an entry that misdescribes its manifest can reach a review.

// stubFetch serves canned bodies for exact URLs through the importer's own
// client, so the guarded dialer and its public-unicast rule are not in the way
// of testing what happens after a fetch succeeds.
type stubFetch map[string]string

func (s stubFetch) RoundTrip(r *http.Request) (*http.Response, error) {
	body, ok := s[r.URL.String()]
	if !ok {
		return &http.Response{
			StatusCode: http.StatusNotFound,
			Body:       io.NopCloser(strings.NewReader("not found")),
			Header:     make(http.Header),
			Request:    r,
		}, nil
	}
	return &http.Response{
		StatusCode: http.StatusOK,
		Body:       io.NopCloser(strings.NewReader(body)),
		Header:     make(http.Header),
		Request:    r,
	}, nil
}

type catalogReviewBarrier struct {
	served  stubFetch
	started chan struct{}
	release chan struct{}
}

func (b *catalogReviewBarrier) RoundTrip(request *http.Request) (*http.Response, error) {
	if request.URL.String() != catalogManifestURL {
		return b.served.RoundTrip(request)
	}
	select {
	case <-b.started:
	default:
		close(b.started)
	}
	select {
	case <-b.release:
	case <-request.Context().Done():
		return nil, request.Context().Err()
	}
	return b.served.RoundTrip(request)
}

type catalogRedirectTransport struct {
	served stubFetch
	from   string
	to     string
}

func (t catalogRedirectTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	if request.URL.String() != t.from {
		return t.served.RoundTrip(request)
	}
	return &http.Response{
		StatusCode: http.StatusFound,
		Body:       io.NopCloser(strings.NewReader("redirect")),
		Header:     http.Header{"Location": []string{t.to}},
		Request:    request,
	}, nil
}

func stubImporterTransport(t *testing.T, transport http.RoundTripper) *Importer {
	t.Helper()
	imp := &Importer{client: &http.Client{Transport: transport, CheckRedirect: redirectPolicy}, now: time.Now}
	previous := importerRef.Load()
	SetImporter(imp)
	t.Cleanup(func() { importerRef.Store(previous) })
	return imp
}

func stubImporter(t *testing.T, served stubFetch) *Importer {
	t.Helper()
	return stubImporterTransport(t, served)
}

// catalogIndexURL is the URL the importer-level tests below pass explicitly.
// It is deliberately not officialCatalogIndexURL: imp.catalog parses whatever
// it is pointed at, and keeping the two distinct means an engine-level test
// that stubbed the wrong host fails instead of quietly following whichever
// index this Core happens to be compiled with.
const catalogIndexURL = "https://catalog.example.com/index.json"
const catalogManifestURL = "https://catalog.example.com/example.yaml"

// catalogIndexJSON renders an index whose single entry describes validManifest.
// The caller overrides one field at a time to produce a divergence.
func catalogIndexJSON(t *testing.T, capabilities string, digest string) string {
	t.Helper()
	if digest == "" {
		digest = digestText(validManifest)
	}
	return fmt.Sprintf(`{
  "apiVersion": "5gpn.io/marketplace/v1",
  "kind": "ExtensionMarketplace",
  "metadata": {"id": "io.5gpn.official", "name": "Official", "homepage": "https://example.com"},
  "entries": [
    {
      "id": "example.plugin",
      "name": "Example",
      "version": "1.2.0",
      "tags": ["testing"],
      "license": {"spdx": "MIT"},
      "manifest": {"url": %q, "sha256": %q, "size": 1234},
      "futurePublisherMetadata": {"reviewHint": "newer-core-only"},
      "capabilities": %s
    }
  ]
}`, catalogManifestURL, digest, capabilities)
}

// The capabilities validManifest actually has.
const honestCapabilities = `{
        "captureHostCount": 2,
        "actionCount": 1,
        "settingCount": 1,
        "network": true,
        "persistentStorage": true,
        "upstreamMappingCount": 1,
        "egressGroupRequired": true,
        "routingRuleCount": 1
      }`

// A publisher may add metadata for a newer core. Rejecting that generic field
// would hide every otherwise usable entry from older gateways, so catalog
// decoding remains lenient while review trusts only the fields it understands.
func TestACatalogWithFieldsThisBuildDoesNotUseStillDecodes(t *testing.T) {
	imp := stubImporter(t, stubFetch{catalogIndexURL: catalogIndexJSON(t, honestCapabilities, "")})

	index, err := imp.catalog(context.Background(), catalogIndexURL)
	if err != nil {
		t.Fatalf("catalog: %v", err)
	}
	if len(index.Entries) != 1 {
		t.Fatalf("decoded %d entries, want 1", len(index.Entries))
	}
	if index.Metadata.Name != "Official" {
		t.Errorf("metadata name %q", index.Metadata.Name)
	}
	if index.Entries[0].Manifest.URL != catalogManifestURL {
		t.Errorf("entry manifest URL %q", index.Entries[0].Manifest.URL)
	}
}

// A partially usable response is not a complete snapshot. Publishing only the
// good prefix would make a malformed entry look deleted, so the whole fetch is
// rejected and the cache layer can retain its prior complete index.
func TestAPartialCatalogIsRejectedRatherThanPublished(t *testing.T) {
	index := `{
  "apiVersion": "5gpn.io/marketplace/v1",
  "kind": "ExtensionMarketplace",
  "metadata": {"id": "io.5gpn.official"},
  "entries": [
    {"id": "good.plugin", "manifest": {"url": "https://catalog.example.com/c.yaml", "sha256": "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"}},
    {"id": "bad.plugin", "manifest": {"url": "https://catalog.example.com/b.yaml", "sha256": "short"}}
  ]
}`
	imp := stubImporter(t, stubFetch{catalogIndexURL: index})

	if _, err := imp.catalog(context.Background(), catalogIndexURL); err == nil {
		t.Fatal("a partially valid catalog replaced the complete snapshot")
	} else if !strings.Contains(err.Error(), "bad.plugin") {
		t.Fatalf("partial-catalog error did not identify the bad entry: %v", err)
	}
}

// Something that is not an extension catalog is refused outright, rather than
// decoding to an empty listing an operator would read as "this publisher has
// nothing".
func TestSomethingThatIsNotACatalogIsRefused(t *testing.T) {
	imp := stubImporter(t, stubFetch{catalogIndexURL: `{"apiVersion": "v1", "kind": "ConfigMap", "entries": []}`})

	if _, err := imp.catalog(context.Background(), catalogIndexURL); err == nil {
		t.Fatal("a document that is not a catalog was accepted")
	}
}

func catalogTestEngine(t *testing.T) *Engine {
	t.Helper()
	return newTestEngine(t, `{
  "version": 7,
  "execution_order": [],
  "tls_cert": "/etc/5gpn/intercept/tls/fullchain.pem",
  "tls_key": "/etc/5gpn/intercept/tls/privkey.pem",
  "mitm": {"enabled": false, "http2": true, "http3": false}
}`)
}

// The happy path, which is also what makes the refusals below meaningful: an
// entry that describes its manifest honestly reviews, and what comes back is
// the same Candidate a pasted URL would produce.
func TestAnHonestCatalogEntryReviewsLikeAPastedURL(t *testing.T) {
	stubImporter(t, stubFetch{
		officialCatalogIndexURL: catalogIndexJSON(t, honestCapabilities, ""),
		catalogManifestURL:      validManifest,
	})
	e := catalogTestEngine(t)

	candidate, err := e.ReviewCatalogEntry(context.Background(), "example.plugin")
	if err != nil {
		t.Fatalf("ReviewCatalogEntry: %v", err)
	}
	if candidate.Detail.ID != "example.plugin" {
		t.Errorf("reviewed %q", candidate.Detail.ID)
	}
	if candidate.Digest == "" {
		t.Error("the review returned no digest for the install to quote")
	}
	if candidate.Installed != "" {
		t.Errorf("nothing is installed, but the review reported %q", candidate.Installed)
	}
}

// A review that is still fetching must not be relabelled by a write that lands
// while it waits. The reviewed entry and the revision the operator will quote
// back have to come from the same committed document, so the conflict is
// reported rather than the stale candidate being handed back under a revision
// that no longer describes it.
func TestCatalogReviewDoesNotMixAStaleSourceWithANewRevision(t *testing.T) {
	barrier := &catalogReviewBarrier{
		served: stubFetch{
			officialCatalogIndexURL: catalogIndexJSON(t, honestCapabilities, ""),
			catalogManifestURL:      validManifest,
		},
		started: make(chan struct{}),
		release: make(chan struct{}),
	}
	setTestImporter(t, &Importer{client: &http.Client{Transport: barrier}, now: time.Now})
	e := catalogTestEngine(t)
	initialRevision := e.Revision()
	type result struct {
		revision string
		err      error
	}
	done := make(chan result, 1)
	go func() {
		_, _, revision, err := e.ReviewCatalogEntryView(
			context.Background(), "example.plugin",
		)
		done <- result{revision: revision, err: err}
	}()
	<-barrier.started
	// Any committed write will do; this one touches nothing the review reads,
	// which is the point — the review is stale because the document moved, not
	// because its own inputs changed.
	_, changedRevision, err := e.SetSettings(initialRevision, MITMSettings{Enabled: false, HTTP2: false, HTTP3: false})
	if err != nil {
		t.Fatalf("SetSettings: %v", err)
	}
	if changedRevision == initialRevision {
		t.Fatalf("the concurrent write did not advance the revision from %q", initialRevision)
	}
	close(barrier.release)
	got := <-done
	if !errors.Is(got.err, state.ErrRevisionConflict) {
		t.Fatalf("ReviewCatalogEntryView error = %v, want revision conflict", got.err)
	}
	if got.revision != changedRevision {
		t.Fatalf("review returned revision %q, want current %q", got.revision, changedRevision)
	}
}

func TestCatalogProjectsWhetherTheInstalledManifestIsCurrent(t *testing.T) {
	const oldURL = "https://elsewhere.example.com/example.yaml"

	for _, test := range []struct {
		name             string
		installedBody    string
		wantCurrent      bool
		wantInstalledVer string
	}{
		{
			name:             "matching version and manifest",
			installedBody:    validManifest,
			wantCurrent:      true,
			wantInstalledVer: "1.2.0",
		},
		{
			name: "same version with different manifest bytes",
			installedBody: strings.Replace(
				validManifest,
				"description: A test extension",
				"description: An older test extension",
				1,
			),
			wantCurrent:      false,
			wantInstalledVer: "1.2.0",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			stubImporter(t, stubFetch{
				officialCatalogIndexURL: catalogIndexJSON(t, honestCapabilities, ""),
				oldURL:                  test.installedBody,
			})
			e := catalogTestEngine(t)
			installFromCatalog(t, e, oldURL)

			view, _, err := e.CatalogWithRevision(context.Background(), false)
			if err != nil {
				t.Fatalf("CatalogWithRevision: %v", err)
			}
			if len(view.Entries) != 1 {
				t.Fatalf("catalog view = %+v", view)
			}
			entry := view.Entries[0]
			if entry.InstalledVersion != test.wantInstalledVer || entry.InstalledCurrent != test.wantCurrent {
				t.Fatalf("installed version %q current %v, want %q current %v",
					entry.InstalledVersion, entry.InstalledCurrent, test.wantInstalledVer, test.wantCurrent)
			}
		})
	}
}

// A catalog that advertises something milder than the manifest declares is the
// case this check exists for: the operator reads the listing, and the listing is
// what they believe they are confirming.
func TestAnEntryThatUnderstatesTheManifestIsRefused(t *testing.T) {
	understated := strings.Replace(honestCapabilities, `"network": true`, `"network": false`, 1)
	stubImporter(t, stubFetch{
		officialCatalogIndexURL: catalogIndexJSON(t, understated, ""),
		catalogManifestURL:      validManifest,
	})
	e := catalogTestEngine(t)

	_, err := e.ReviewCatalogEntry(context.Background(), "example.plugin")
	if err == nil {
		t.Fatal("an entry claiming no network grant reviewed a manifest that takes one")
	}
	if !strings.Contains(err.Error(), "network grant") {
		t.Errorf("the refusal does not name what diverged: %v", err)
	}
}

// The digest is the strong check: the bytes are not the bytes the catalog
// published, whatever either of them claims about capabilities.
func TestAnEntryWhoseDigestDoesNotMatchIsRefused(t *testing.T) {
	stubImporter(t, stubFetch{
		officialCatalogIndexURL: catalogIndexJSON(t, honestCapabilities, strings.Repeat("a", 64)),
		catalogManifestURL:      validManifest,
	})
	e := catalogTestEngine(t)

	_, err := e.ReviewCatalogEntry(context.Background(), "example.plugin")
	if err == nil {
		t.Fatal("a manifest that does not match the published digest was reviewed")
	}
	if !strings.Contains(err.Error(), "digest") {
		t.Errorf("the refusal does not name the digest: %v", err)
	}
}

func TestCatalogReviewTreatsExternalScriptsAsLiveSnapshotDependencies(t *testing.T) {
	const scriptURL = "https://scripts.example.com/action.js"
	externalManifest := strings.Replace(
		validManifest,
		`inline: "function transform(context) { return {}; }"`,
		"source: "+scriptURL,
		1,
	)
	if externalManifest == validManifest {
		t.Fatal("the fixture did not replace the inline script")
	}
	index := catalogIndexJSON(t, honestCapabilities, digestText(externalManifest))
	served := stubFetch{
		officialCatalogIndexURL: index,
		catalogManifestURL:      externalManifest,
		scriptURL:               "function transform(context) { return {}; }",
	}
	stubImporter(t, served)
	e := catalogTestEngine(t)

	first, err := e.ReviewCatalogEntry(context.Background(), "example.plugin")
	if err != nil {
		t.Fatalf("first live script review: %v", err)
	}
	served[scriptURL] = "function transform(context) { return {headers: {set: {\"X-Live\": \"changed\"}}}; }"
	second, err := e.ReviewCatalogEntry(context.Background(), "example.plugin")
	if err != nil {
		t.Fatalf("second live script review: %v", err)
	}
	if first.Detail.SourceDigest != second.Detail.SourceDigest {
		t.Fatal("unchanged manifest bytes produced different manifest digests")
	}
	if first.Digest == second.Digest {
		t.Fatal("changed live script bytes did not change the complete snapshot digest")
	}
}

func TestAnEntryWhoseVersionDoesNotMatchIsRefused(t *testing.T) {
	index := strings.Replace(catalogIndexJSON(t, honestCapabilities, ""), `"version": "1.2.0"`, `"version": "9.9.9"`, 1)
	stubImporter(t, stubFetch{
		officialCatalogIndexURL: index,
		catalogManifestURL:      validManifest,
	})
	e := catalogTestEngine(t)

	_, err := e.ReviewCatalogEntry(context.Background(), "example.plugin")
	if err == nil {
		t.Fatal("a catalog version that does not match the manifest was reviewed")
	}
	if !strings.Contains(err.Error(), "version") {
		t.Errorf("the refusal does not name the version drift: %v", err)
	}
}

// An index that predates the routing-rule count says nothing about it, which is
// not a claim of zero. Treating the absent field as zero would refuse every
// extension with a routing rule against every catalog published before the
// field existed.
func TestAnAbsentRoutingRuleCountIsUnverifiedNotZero(t *testing.T) {
	silent := strings.Replace(honestCapabilities, `,
        "routingRuleCount": 1`, "", 1)
	if silent == honestCapabilities {
		t.Fatal("the fixture did not drop routingRuleCount")
	}
	stubImporter(t, stubFetch{
		officialCatalogIndexURL: catalogIndexJSON(t, silent, ""),
		catalogManifestURL:      validManifest,
	})
	e := catalogTestEngine(t)

	if _, err := e.ReviewCatalogEntry(context.Background(), "example.plugin"); err != nil {
		t.Fatalf("an index that predates routingRuleCount was refused: %v", err)
	}
}

// The Marketplace that cannot be fetched still renders, with the reason. The
// page it would otherwise break is the only place an operator learns that
// discovery is down rather than empty.
func TestAnUnreachableCatalogIsReportedRatherThanFailingTheList(t *testing.T) {
	stubImporter(t, stubFetch{})
	e := catalogTestEngine(t)

	view, err := e.Catalog(context.Background(), false)
	if err != nil {
		t.Fatalf("an unreachable Marketplace failed the whole read: %v", err)
	}
	if view.URL != officialCatalogIndexURL {
		t.Fatalf("catalog view URL = %q, want the built-in %q", view.URL, officialCatalogIndexURL)
	}
	if view.Error == "" {
		t.Fatalf("the unreachable Marketplace was not reported: %+v", view)
	}
	if view.FetchedAt != "" || len(view.Entries) != 0 {
		t.Fatalf("a Marketplace that never succeeded invented a snapshot: %+v", view)
	}
}

func TestFailedCatalogRefreshRetainsTheLastCompleteSnapshot(t *testing.T) {
	partial := `{
  "apiVersion": "5gpn.io/marketplace/v1",
  "kind": "ExtensionMarketplace",
  "metadata": {"id": "io.5gpn.official", "name": "Broken replacement"},
  "entries": [
    {"id": "good.plugin", "manifest": {"url": "https://catalog.example.com/good.yaml", "sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}},
    {"id": "bad.plugin", "manifest": {"url": "https://catalog.example.com/bad.yaml", "sha256": "short"}}
  ]
}`
	for name, breakFetch := range map[string]func(stubFetch){
		"network failure": func(served stubFetch) { delete(served, officialCatalogIndexURL) },
		"JSON failure":    func(served stubFetch) { served[officialCatalogIndexURL] = `{"apiVersion":` },
		"duplicate field": func(served stubFetch) {
			served[officialCatalogIndexURL] = strings.Replace(
				served[officialCatalogIndexURL],
				`"kind": "ExtensionMarketplace"`,
				`"kind": "ExtensionMarketplace", "kind": "ExtensionMarketplace"`,
				1,
			)
		},
		"missing entries": func(served stubFetch) {
			served[officialCatalogIndexURL] = `{"apiVersion":"5gpn.io/marketplace/v1","kind":"ExtensionMarketplace","metadata":{}}`
		},
		"partial index": func(served stubFetch) { served[officialCatalogIndexURL] = partial },
	} {
		t.Run(name, func(t *testing.T) {
			served := stubFetch{officialCatalogIndexURL: catalogIndexJSON(t, honestCapabilities, "")}
			stubImporter(t, served)
			e := catalogTestEngine(t)

			before, err := e.Catalog(context.Background(), false)
			if err != nil {
				t.Fatalf("initial catalog: %v", err)
			}
			if len(before.Entries) != 1 || before.Error != "" {
				t.Fatalf("initial complete snapshot = %+v", before)
			}
			breakFetch(served)

			after, err := e.Catalog(context.Background(), true)
			if err != nil {
				t.Fatalf("failed refresh broke the complete listing: %v", err)
			}
			if after.Error == "" {
				t.Fatalf("failed refresh did not report its fetch error: %+v", after)
			}
			if after.FetchedAt != before.FetchedAt || after.Metadata != before.Metadata ||
				len(after.Entries) != 1 || after.Entries[0].ID != before.Entries[0].ID {
				t.Fatalf("failed refresh replaced prior snapshot:\n got %+v\nwant %+v plus error", after, before)
			}
		})
	}
}

func TestExpiredCatalogSurvivesARefreshFailure(t *testing.T) {
	served := stubFetch{officialCatalogIndexURL: catalogIndexJSON(t, honestCapabilities, "")}
	stubImporter(t, served)
	e := catalogTestEngine(t)
	if _, err := e.Catalog(context.Background(), false); err != nil {
		t.Fatalf("initial catalog: %v", err)
	}

	e.catalogs.mu.Lock()
	e.catalogs.fetchedAt = time.Now().Add(-catalogCacheTTL - time.Minute)
	wantFetchedAt := e.catalogs.fetchedAt.UTC().Format(time.RFC3339)
	e.catalogs.mu.Unlock()
	delete(served, officialCatalogIndexURL)

	view, err := e.Catalog(context.Background(), false)
	if err != nil {
		t.Fatalf("expired refresh failure broke the listing: %v", err)
	}
	if view.Error == "" || len(view.Entries) != 1 || view.Entries[0].ID != "example.plugin" {
		t.Fatalf("expired snapshot was treated as deleted: %+v", view)
	}
	if view.FetchedAt != wantFetchedAt {
		t.Fatalf("expired snapshot fetched_at = %q, want retained %q", view.FetchedAt, wantFetchedAt)
	}
}

func TestSuccessfulCatalogRefreshAtomicallyReplacesTheSnapshot(t *testing.T) {
	served := stubFetch{officialCatalogIndexURL: catalogIndexJSON(t, honestCapabilities, "")}
	stubImporter(t, served)
	e := catalogTestEngine(t)
	if _, err := e.Catalog(context.Background(), false); err != nil {
		t.Fatalf("initial catalog: %v", err)
	}
	served[officialCatalogIndexURL] = strings.Replace(
		catalogIndexJSON(t, honestCapabilities, ""),
		`"id": "example.plugin"`, `"id": "next.plugin"`, 1,
	)

	refreshed, err := e.Catalog(context.Background(), true)
	if err != nil {
		t.Fatalf("successful refresh: %v", err)
	}
	if refreshed.Error != "" || len(refreshed.Entries) != 1 || refreshed.Entries[0].ID != "next.plugin" {
		t.Fatalf("successful refresh did not replace the complete snapshot: %+v", refreshed)
	}
	cached, err := e.Catalog(context.Background(), false)
	if err != nil {
		t.Fatalf("read refreshed cache: %v", err)
	}
	if len(cached.Entries) != 1 || cached.Entries[0].ID != "next.plugin" {
		t.Fatalf("cache retained the superseded snapshot: %+v", cached)
	}
}

// The wire-shaped fixture contains generic metadata this build does not
// consume. It proves forward-compatible fields do not hide the manifest and
// capability claims this core does verify.
func TestAForwardCompatibleIndexDecodes(t *testing.T) {
	published, err := os.ReadFile(filepath.Join("testdata", "marketplace-index.json"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(published, []byte(`"futurePublisherMetadata"`)) {
		t.Fatal("the fixture no longer exercises a generic unknown field")
	}
	imp := stubImporter(t, stubFetch{catalogIndexURL: string(published)})

	index, err := imp.catalog(context.Background(), catalogIndexURL)
	if err != nil {
		t.Fatalf("the forward-compatible index did not decode: %v", err)
	}
	if index.Metadata.ID == "" || len(index.Entries) == 0 {
		t.Fatalf("decoded an empty catalog: %+v", index.Metadata)
	}
	for _, entry := range index.Entries {
		if entry.Version == "" || entry.Name == "" {
			t.Errorf("entry %q lost its identity in decoding: %+v", entry.ID, entry)
		}
		if entry.Manifest.URL == "" || len(entry.Manifest.SHA256) != 64 {
			t.Errorf("entry %q has no usable manifest reference: %+v", entry.ID, entry.Manifest)
		}
		// The capability shape is what the review is checked against, so a
		// field that silently decoded to its zero value would make the check
		// pass for the wrong reason.
		if entry.Capabilities.CaptureHostCount == 0 {
			t.Errorf("entry %q decoded as capturing nothing", entry.ID)
		}
		if entry.Capabilities.RoutingRuleCount == nil {
			t.Errorf("entry %q lost its routing rule count, which would leave it unverified", entry.ID)
		}
	}
}

func TestAnUnknownFieldIsRefused(t *testing.T) {
	body := []byte(`{
  "version": 7,
  "execution_order": [],
  "tls_cert": "/etc/5gpn/intercept/tls/fullchain.pem",
  "tls_key": "/etc/5gpn/intercept/tls/privkey.pem",
  "mitm": {"enabled": true, "http2": true, "htp3": true}
}`)
	if _, err := decodeConfig(body); err == nil {
		t.Fatal("a misspelled field was accepted")
	}
}

func TestRetiredQUICFallbackProtectionIsRefused(t *testing.T) {
	body := []byte(`{
  "version": 7,
  "execution_order": [],
  "tls_cert": "/etc/5gpn/intercept/tls/fullchain.pem",
  "tls_key": "/etc/5gpn/intercept/tls/privkey.pem",
  "mitm": {"enabled": true, "http2": true, "quic_fallback_protection": true}
}`)
	if _, err := decodeConfig(body); err == nil {
		t.Fatal("retired quic_fallback_protection key was accepted")
	}
}

// There is one Marketplace and it is compiled into the Core, so a document that
// still carries the operator-configured source list is a document from before
// that decision. It is refused rather than migrated: this project is
// pre-release, and silently dropping a key an operator once used to point the
// gateway somewhere would leave them believing a source they configured is
// still being read.
func TestRetiredCatalogSourcesAreRefused(t *testing.T) {
	body := []byte(`{
  "version": 7,
  "execution_order": [],
  "tls_cert": "/etc/5gpn/intercept/tls/fullchain.pem",
  "tls_key": "/etc/5gpn/intercept/tls/privkey.pem",
  "mitm": {"enabled": false, "http2": true, "http3": false},
  "catalogs": [{"id": "io.5gpn.official", "url": "https://catalog.example.com/index.json", "enabled": true}]
}`)
	if _, err := decodeConfig(body); err == nil {
		t.Fatal("retired catalogs key was accepted")
	}
	// Not even the emptied form, which is what a gateway that had removed every
	// source would have persisted.
	empty := []byte(`{
  "version": 7,
  "execution_order": [],
  "tls_cert": "/etc/5gpn/intercept/tls/fullchain.pem",
  "tls_key": "/etc/5gpn/intercept/tls/privkey.pem",
  "mitm": {"enabled": false, "http2": true, "http3": false},
  "catalogs": []
}`)
	if _, err := decodeConfig(empty); err == nil {
		t.Fatal("an empty retired catalogs key was accepted")
	}
}

// A fresh gateway publishes no discovery state at all. The Marketplace URL is
// compiled in, so there is nothing for the document to carry and nothing for a
// management write to preserve.
func TestFreshDocumentPersistsNoDiscoveryState(t *testing.T) {
	raw, err := json.Marshal(DefaultDocument())
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "catalog") {
		t.Fatalf("fresh document published discovery state: %s", raw)
	}
}

// installFromCatalog is the setup the update tests share: an extension already
// installed from some other URL, disabled, ready to be moved onto the
// Marketplace.
func installFromCatalog(t *testing.T, e *Engine, sourceURL string) string {
	t.Helper()
	_, revision, err := e.Install(context.Background(), e.Revision(), InstallRequest{
		ImportRequest: ImportRequest{URL: sourceURL},
		Digest:        SnapshotDigest(mustImport(t, sourceURL)),
	})
	if err != nil {
		t.Fatalf("Install: %v", err)
	}
	return revision
}

func mustImport(t *testing.T, sourceURL string) Module {
	t.Helper()
	imp, err := currentImporter()
	if err != nil {
		t.Fatal(err)
	}
	module, err := imp.Import(context.Background(), ImportRequest{URL: sourceURL})
	if err != nil {
		t.Fatal(err)
	}
	return module
}

// An update from a catalog entry moves where the extension's code comes from.
// That is the whole point of the call and the reason it is not folded into the
// ordinary update, so it is what the test asserts.
func TestACatalogUpdateMovesTheExtensionsSource(t *testing.T) {
	const oldURL = "https://elsewhere.example.com/example.yaml"
	stubImporter(t, stubFetch{
		officialCatalogIndexURL: catalogIndexJSON(t, honestCapabilities, ""),
		catalogManifestURL:      validManifest,
		oldURL:                  validManifest,
	})
	e := catalogTestEngine(t)
	revision := installFromCatalog(t, e, oldURL)

	before, _ := e.ReadDocument()
	if got := before.Modules[0].Source.URL; got != oldURL {
		t.Fatalf("setup installed from %q", got)
	}

	digest := SnapshotDigest(mustImport(t, catalogManifestURL))
	if _, _, err := e.ApplyCatalogUpdate(context.Background(), revision, "example.plugin", catalogManifestURL, digest); err != nil {
		t.Fatalf("ApplyCatalogUpdate: %v", err)
	}
	after, _ := e.ReadDocument()
	if got := after.Modules[0].Source.URL; got != catalogManifestURL {
		t.Errorf("source is %q, want the catalog entry's %q", got, catalogManifestURL)
	}
}

func TestACatalogUpdateBindsTheReviewedManifestURL(t *testing.T) {
	const (
		oldURL = "https://elsewhere.example.com/example.yaml"
		newURL = "https://catalog.example.com/repointed.yaml"
	)
	served := stubFetch{
		officialCatalogIndexURL: catalogIndexJSON(t, honestCapabilities, ""),
		catalogManifestURL:      validManifest,
		newURL:                  validManifest,
		oldURL:                  validManifest,
	}
	stubImporter(t, served)
	e := catalogTestEngine(t)
	revision := installFromCatalog(t, e, oldURL)
	candidate, reviewedURL, reviewRevision, err := e.ReviewCatalogEntryView(
		context.Background(), "example.plugin",
	)
	if err != nil {
		t.Fatalf("ReviewCatalogEntryView: %v", err)
	}
	if reviewRevision != revision || reviewedURL != catalogManifestURL {
		t.Fatalf("review returned revision %q URL %q, want %q %q", reviewRevision, reviewedURL, revision, catalogManifestURL)
	}

	served[officialCatalogIndexURL] = strings.Replace(served[officialCatalogIndexURL], catalogManifestURL, newURL, 1)
	if _, err := e.Catalog(context.Background(), true); err != nil {
		t.Fatalf("refresh changed catalog: %v", err)
	}
	_, _, err = e.ApplyCatalogUpdate(
		context.Background(), reviewRevision, "example.plugin", reviewedURL, candidate.Digest,
	)
	if !errors.Is(err, ErrReviewConflict) {
		t.Fatalf("ApplyCatalogUpdate error = %v, want review conflict", err)
	}
	after, afterRevision := e.ReadDocument()
	if afterRevision != revision || after.Modules[0].Source.URL != oldURL {
		t.Fatalf("stale review changed revision/source to %q/%q", afterRevision, after.Modules[0].Source.URL)
	}
}

func TestACatalogRedirectKeepsTheReviewedEntryURLAuthoritative(t *testing.T) {
	const (
		oldURL   = "https://elsewhere.example.com/example.yaml"
		finalURL = "https://cdn.example.com/example.yaml"
	)
	served := stubFetch{
		officialCatalogIndexURL: catalogIndexJSON(t, honestCapabilities, ""),
		finalURL:                validManifest,
		oldURL:                  validManifest,
	}
	stubImporterTransport(t, catalogRedirectTransport{
		served: served,
		from:   catalogManifestURL,
		to:     finalURL,
	})
	e := catalogTestEngine(t)
	revision := installFromCatalog(t, e, oldURL)
	candidate, reviewedURL, reviewRevision, err := e.ReviewCatalogEntryView(
		context.Background(), "example.plugin",
	)
	if err != nil {
		t.Fatalf("ReviewCatalogEntryView: %v", err)
	}
	if reviewedURL != catalogManifestURL {
		t.Fatalf("reviewed URL = %q, want selected entry URL %q", reviewedURL, catalogManifestURL)
	}
	if candidate.Detail.SourceURL != finalURL {
		t.Fatalf("candidate source URL = %q, want redirect target %q", candidate.Detail.SourceURL, finalURL)
	}
	if _, _, err := e.ApplyCatalogUpdate(
		context.Background(), reviewRevision, "example.plugin",
		candidate.Detail.SourceURL, candidate.Digest,
	); !errors.Is(err, ErrReviewConflict) {
		t.Fatalf("redirect target apply error = %v, want review conflict", err)
	}
	if current := e.Revision(); current != revision {
		t.Fatalf("wrong reviewed URL changed revision to %q, want %q", current, revision)
	}
	if _, _, err := e.ApplyCatalogUpdate(
		context.Background(), reviewRevision, "example.plugin",
		reviewedURL, candidate.Digest,
	); err != nil {
		t.Fatalf("apply with reviewed entry URL: %v", err)
	}
}

func TestACatalogUpdateTreatsARemovedReviewedEntryAsConflict(t *testing.T) {
	const oldURL = "https://elsewhere.example.com/example.yaml"
	served := stubFetch{
		officialCatalogIndexURL: catalogIndexJSON(t, honestCapabilities, ""),
		catalogManifestURL:      validManifest,
		oldURL:                  validManifest,
	}
	stubImporter(t, served)
	e := catalogTestEngine(t)
	revision := installFromCatalog(t, e, oldURL)
	candidate, reviewedURL, reviewRevision, err := e.ReviewCatalogEntryView(
		context.Background(), "example.plugin",
	)
	if err != nil {
		t.Fatalf("ReviewCatalogEntryView: %v", err)
	}
	served[officialCatalogIndexURL] = `{
  "apiVersion": "5gpn.io/marketplace/v1",
  "kind": "ExtensionMarketplace",
  "metadata": {"id": "io.5gpn.official", "name": "Official", "homepage": "https://example.com"},
  "entries": []
}`
	if _, err := e.Catalog(context.Background(), true); err != nil {
		t.Fatalf("refresh removed catalog entry: %v", err)
	}
	_, _, err = e.ApplyCatalogUpdate(
		context.Background(), reviewRevision, "example.plugin", reviewedURL, candidate.Digest,
	)
	if !errors.Is(err, ErrReviewConflict) {
		t.Fatalf("ApplyCatalogUpdate error = %v, want review conflict", err)
	}
	after, afterRevision := e.ReadDocument()
	if afterRevision != revision || after.Modules[0].Source.URL != oldURL {
		t.Fatalf("removed entry changed revision/source to %q/%q", afterRevision, after.Modules[0].Source.URL)
	}
}

// Catalog updates use the same immutable-snapshot handoff as ordinary updates,
// so an enabled extension remains enabled across the replacement.
func TestACatalogUpdateKeepsAnEnabledExtensionEnabled(t *testing.T) {
	stubImporter(t, stubFetch{
		officialCatalogIndexURL: catalogIndexJSON(t, honestCapabilities, ""),
		catalogManifestURL:      validManifest,
	})
	e := catalogTestEngine(t)
	revision := installFromCatalog(t, e, catalogManifestURL)

	// The extension declares an egress requirement, so bind one before enabling.
	_, revision, err := e.SetEgressGroup(revision, "example.plugin", "Proxies")
	if err != nil {
		t.Fatal(err)
	}
	if _, revision, err = e.SetEnabled(revision, "example.plugin", true); err != nil {
		t.Fatal(err)
	}

	digest := SnapshotDigest(mustImport(t, catalogManifestURL))
	_, _, err = e.ApplyCatalogUpdate(context.Background(), revision, "example.plugin", catalogManifestURL, digest)
	if err != nil {
		t.Fatalf("enabled catalog update: %v", err)
	}
	detail, err := e.Detail("example.plugin")
	if err != nil {
		t.Fatal(err)
	}
	if !detail.Enabled || detail.EgressGroup != "Proxies" {
		t.Fatalf("catalog update lost enabled operator state: %+v", detail.ModuleSummary)
	}
}

// The entry's own claims are still checked on the update path. A catalog that
// advertised one shape and updated to another would make the listing an
// operator read meaningless at exactly the moment it matters.
func TestACatalogUpdateStillChecksWhatTheEntryAdvertised(t *testing.T) {
	understated := strings.Replace(honestCapabilities, `"network": true`, `"network": false`, 1)
	stubImporter(t, stubFetch{
		officialCatalogIndexURL: catalogIndexJSON(t, understated, ""),
		catalogManifestURL:      validManifest,
	})
	e := catalogTestEngine(t)
	revision := installFromCatalog(t, e, catalogManifestURL)

	digest := SnapshotDigest(mustImport(t, catalogManifestURL))
	_, _, err := e.ApplyCatalogUpdate(context.Background(), revision, "example.plugin", catalogManifestURL, digest)
	if err == nil {
		t.Fatal("an entry that understates the manifest updated anyway")
	}
	if !errors.Is(err, ErrReviewConflict) {
		t.Errorf("apply error = %v, want review conflict", err)
	}
	if !strings.Contains(err.Error(), "network grant") {
		t.Errorf("the refusal does not name what diverged: %v", err)
	}
}

// An update still has to quote a digest, and a wrong one is refused — the
// catalog path must not become a way to skip the confirmation.
func TestACatalogUpdateStillRequiresTheReviewedDigest(t *testing.T) {
	stubImporter(t, stubFetch{
		officialCatalogIndexURL: catalogIndexJSON(t, honestCapabilities, ""),
		catalogManifestURL:      validManifest,
	})
	e := catalogTestEngine(t)
	revision := installFromCatalog(t, e, catalogManifestURL)
	digest := SnapshotDigest(mustImport(t, catalogManifestURL))

	if _, _, err := e.ApplyCatalogUpdate(context.Background(), revision, "example.plugin", "", digest); !errors.Is(err, ErrInvalidRequest) {
		t.Errorf("an update without the reviewed URL returned %v, want invalid request", err)
	}
	if _, _, err := e.ApplyCatalogUpdate(context.Background(), revision, "example.plugin", catalogManifestURL, ""); err == nil {
		t.Error("an update with no digest was applied")
	}
	if _, _, err := e.ApplyCatalogUpdate(context.Background(), revision, "example.plugin", catalogManifestURL, strings.Repeat("b", 64)); err == nil {
		t.Error("an update quoting the wrong digest was applied")
	}
}

// CheckUpdate must keep re-reading only the installed source. A catalog that
// merely exists must not redirect anything.
func TestCheckUpdateStillReadsOnlyTheInstalledSource(t *testing.T) {
	const oldURL = "https://elsewhere.example.com/example.yaml"
	stubImporter(t, stubFetch{
		officialCatalogIndexURL: catalogIndexJSON(t, honestCapabilities, ""),
		catalogManifestURL:      validManifest,
		oldURL:                  validManifest,
	})
	e := catalogTestEngine(t)
	installFromCatalog(t, e, oldURL)

	if _, err := e.CheckUpdate(context.Background(), "example.plugin"); err != nil {
		t.Fatalf("CheckUpdate: %v", err)
	}
	after, _ := e.ReadDocument()
	if got := after.Modules[0].Source.URL; got != oldURL {
		t.Errorf("checking for an update moved the source to %q", got)
	}
}
