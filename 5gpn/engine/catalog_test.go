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
	document := fmt.Sprintf(`{
  "version": 6,
  "execution_order": [],
  "tls_cert": "/etc/5gpn/intercept/tls/fullchain.pem",
  "tls_key": "/etc/5gpn/intercept/tls/privkey.pem",
  "mitm": {"enabled": false, "http2": true, "http3": false},
  "catalogs": [{"id": "io.5gpn.official", "name": "Official", "url": %q, "enabled": true}]
}`, catalogIndexURL)
	return newTestEngine(t, document)
}

// The happy path, which is also what makes the refusals below meaningful: an
// entry that describes its manifest honestly reviews, and what comes back is
// the same Candidate a pasted URL would produce.
func TestAnHonestCatalogEntryReviewsLikeAPastedURL(t *testing.T) {
	stubImporter(t, stubFetch{
		catalogIndexURL:    catalogIndexJSON(t, honestCapabilities, ""),
		catalogManifestURL: validManifest,
	})
	e := catalogTestEngine(t)

	candidate, err := e.ReviewCatalogEntry(context.Background(), "io.5gpn.official", "example.plugin")
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

func TestCatalogReviewDoesNotMixAStaleSourceWithANewRevision(t *testing.T) {
	barrier := &catalogReviewBarrier{
		served: stubFetch{
			catalogIndexURL:    catalogIndexJSON(t, honestCapabilities, ""),
			catalogManifestURL: validManifest,
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
			context.Background(), "io.5gpn.official", "example.plugin",
		)
		done <- result{revision: revision, err: err}
	}()
	<-barrier.started
	_, changedRevision, err := e.SetCatalogSources(initialRevision, []CatalogSource{{
		ID: "io.5gpn.official", Name: "Renamed while reviewing", URL: catalogIndexURL, Enabled: true,
	}})
	if err != nil {
		t.Fatalf("SetCatalogSources: %v", err)
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
				catalogIndexURL: catalogIndexJSON(t, honestCapabilities, ""),
				oldURL:          test.installedBody,
			})
			e := catalogTestEngine(t)
			installFromCatalog(t, e, oldURL)

			view, _, err := e.CatalogWithRevision(context.Background(), false)
			if err != nil {
				t.Fatalf("CatalogWithRevision: %v", err)
			}
			if len(view.Sources) != 1 || len(view.Sources[0].Entries) != 1 {
				t.Fatalf("catalog view = %+v", view)
			}
			entry := view.Sources[0].Entries[0]
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
		catalogIndexURL:    catalogIndexJSON(t, understated, ""),
		catalogManifestURL: validManifest,
	})
	e := catalogTestEngine(t)

	_, err := e.ReviewCatalogEntry(context.Background(), "io.5gpn.official", "example.plugin")
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
		catalogIndexURL:    catalogIndexJSON(t, honestCapabilities, strings.Repeat("a", 64)),
		catalogManifestURL: validManifest,
	})
	e := catalogTestEngine(t)

	_, err := e.ReviewCatalogEntry(context.Background(), "io.5gpn.official", "example.plugin")
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
		catalogIndexURL:    index,
		catalogManifestURL: externalManifest,
		scriptURL:          "function transform(context) { return {}; }",
	}
	stubImporter(t, served)
	e := catalogTestEngine(t)

	first, err := e.ReviewCatalogEntry(context.Background(), "io.5gpn.official", "example.plugin")
	if err != nil {
		t.Fatalf("first live script review: %v", err)
	}
	served[scriptURL] = "function transform(context) { return {headers: {set: {\"X-Live\": \"changed\"}}}; }"
	second, err := e.ReviewCatalogEntry(context.Background(), "io.5gpn.official", "example.plugin")
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
		catalogIndexURL:    index,
		catalogManifestURL: validManifest,
	})
	e := catalogTestEngine(t)

	_, err := e.ReviewCatalogEntry(context.Background(), "io.5gpn.official", "example.plugin")
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
		catalogIndexURL:    catalogIndexJSON(t, silent, ""),
		catalogManifestURL: validManifest,
	})
	e := catalogTestEngine(t)

	if _, err := e.ReviewCatalogEntry(context.Background(), "io.5gpn.official", "example.plugin"); err != nil {
		t.Fatalf("an index that predates routingRuleCount was refused: %v", err)
	}
}

// A disabled catalog is still the operator's configuration and still has to be
// listed, but nothing installs from it.
func TestADisabledCatalogIsListedAndNotFetched(t *testing.T) {
	stubImporter(t, stubFetch{})
	document := fmt.Sprintf(`{
  "version": 6,
  "execution_order": [],
  "tls_cert": "/etc/5gpn/intercept/tls/fullchain.pem",
  "tls_key": "/etc/5gpn/intercept/tls/privkey.pem",
  "mitm": {"enabled": false, "http2": true, "http3": false},
  "catalogs": [{"id": "io.5gpn.official", "name": "Official", "url": %q, "enabled": false}]
}`, catalogIndexURL)
	e := newTestEngine(t, document)

	view, err := e.Catalog(context.Background(), false)
	if err != nil {
		t.Fatalf("Catalog: %v", err)
	}
	if len(view.Sources) != 1 {
		t.Fatalf("listed %d sources, want the disabled one", len(view.Sources))
	}
	// It was not fetched, so it carries neither entries nor a fetch failure.
	if view.Sources[0].Error != "" {
		t.Errorf("a disabled source reported a fetch error: %q", view.Sources[0].Error)
	}
	if _, err := e.ReviewCatalogEntry(context.Background(), "io.5gpn.official", "example.plugin"); err == nil {
		t.Fatal("an entry was installed from a disabled catalog")
	}
}

// A source that cannot be fetched still appears, with the reason. The page it
// would otherwise break is the only place it can be corrected or removed.
func TestAnUnreachableCatalogIsReportedRatherThanFailingTheList(t *testing.T) {
	stubImporter(t, stubFetch{})
	e := catalogTestEngine(t)

	view, err := e.Catalog(context.Background(), false)
	if err != nil {
		t.Fatalf("one unreachable source failed the whole list: %v", err)
	}
	if len(view.Sources) != 1 || view.Sources[0].Error == "" {
		t.Fatalf("the unreachable source was not reported: %+v", view.Sources)
	}
	if view.Sources[0].FetchedAt != "" || len(view.Sources[0].Entries) != 0 {
		t.Fatalf("a source that never succeeded invented a snapshot: %+v", view.Sources[0])
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
		"network failure": func(served stubFetch) { delete(served, catalogIndexURL) },
		"JSON failure":    func(served stubFetch) { served[catalogIndexURL] = `{"apiVersion":` },
		"duplicate field": func(served stubFetch) {
			served[catalogIndexURL] = strings.Replace(
				served[catalogIndexURL],
				`"kind": "ExtensionMarketplace"`,
				`"kind": "ExtensionMarketplace", "kind": "ExtensionMarketplace"`,
				1,
			)
		},
		"missing entries": func(served stubFetch) {
			served[catalogIndexURL] = `{"apiVersion":"5gpn.io/marketplace/v1","kind":"ExtensionMarketplace","metadata":{}}`
		},
		"partial index": func(served stubFetch) { served[catalogIndexURL] = partial },
	} {
		t.Run(name, func(t *testing.T) {
			served := stubFetch{catalogIndexURL: catalogIndexJSON(t, honestCapabilities, "")}
			stubImporter(t, served)
			e := catalogTestEngine(t)

			before, err := e.Catalog(context.Background(), false)
			if err != nil {
				t.Fatalf("initial catalog: %v", err)
			}
			if len(before.Sources) != 1 || len(before.Sources[0].Entries) != 1 || before.Sources[0].Error != "" {
				t.Fatalf("initial complete snapshot = %+v", before.Sources)
			}
			breakFetch(served)

			after, err := e.Catalog(context.Background(), true)
			if err != nil {
				t.Fatalf("failed refresh broke the complete listing: %v", err)
			}
			if len(after.Sources) != 1 || after.Sources[0].Error == "" {
				t.Fatalf("failed refresh did not report its source error: %+v", after.Sources)
			}
			got := after.Sources[0]
			want := before.Sources[0]
			if got.FetchedAt != want.FetchedAt || got.Metadata != want.Metadata || len(got.Entries) != 1 || got.Entries[0].ID != want.Entries[0].ID {
				t.Fatalf("failed refresh replaced prior snapshot:\n got %+v\nwant %+v plus error", got, want)
			}
		})
	}
}

func TestExpiredCatalogSurvivesARefreshFailure(t *testing.T) {
	served := stubFetch{catalogIndexURL: catalogIndexJSON(t, honestCapabilities, "")}
	stubImporter(t, served)
	e := catalogTestEngine(t)
	if _, err := e.Catalog(context.Background(), false); err != nil {
		t.Fatalf("initial catalog: %v", err)
	}

	e.catalogs.mu.Lock()
	retained := e.catalogs.entries[catalogIndexURL]
	retained.fetchedAt = time.Now().Add(-catalogCacheTTL - time.Minute)
	wantFetchedAt := retained.fetchedAt.UTC().Format(time.RFC3339)
	e.catalogs.entries[catalogIndexURL] = retained
	e.catalogs.mu.Unlock()
	delete(served, catalogIndexURL)

	view, err := e.Catalog(context.Background(), false)
	if err != nil {
		t.Fatalf("expired refresh failure broke the listing: %v", err)
	}
	if len(view.Sources) != 1 || view.Sources[0].Error == "" || len(view.Sources[0].Entries) != 1 || view.Sources[0].Entries[0].ID != "example.plugin" {
		t.Fatalf("expired snapshot was treated as deleted: %+v", view.Sources)
	}
	if view.Sources[0].FetchedAt != wantFetchedAt {
		t.Fatalf("expired snapshot fetched_at = %q, want retained %q", view.Sources[0].FetchedAt, wantFetchedAt)
	}
}

func TestSuccessfulCatalogRefreshAtomicallyReplacesTheSnapshot(t *testing.T) {
	served := stubFetch{catalogIndexURL: catalogIndexJSON(t, honestCapabilities, "")}
	stubImporter(t, served)
	e := catalogTestEngine(t)
	if _, err := e.Catalog(context.Background(), false); err != nil {
		t.Fatalf("initial catalog: %v", err)
	}
	served[catalogIndexURL] = strings.Replace(
		catalogIndexJSON(t, honestCapabilities, ""),
		`"id": "example.plugin"`, `"id": "next.plugin"`, 1,
	)

	refreshed, err := e.Catalog(context.Background(), true)
	if err != nil {
		t.Fatalf("successful refresh: %v", err)
	}
	if len(refreshed.Sources) != 1 || refreshed.Sources[0].Error != "" || len(refreshed.Sources[0].Entries) != 1 || refreshed.Sources[0].Entries[0].ID != "next.plugin" {
		t.Fatalf("successful refresh did not replace the complete snapshot: %+v", refreshed.Sources)
	}
	cached, err := e.Catalog(context.Background(), false)
	if err != nil {
		t.Fatalf("read refreshed cache: %v", err)
	}
	if len(cached.Sources[0].Entries) != 1 || cached.Sources[0].Entries[0].ID != "next.plugin" {
		t.Fatalf("cache retained the superseded snapshot: %+v", cached.Sources)
	}
}

func TestCatalogSourcesAreValidatedBeforeTheyAreStored(t *testing.T) {
	for name, sources := range map[string][]CatalogSource{
		"a plaintext URL":  {{ID: "a", URL: "http://example.com/i.json", Enabled: true}},
		"a duplicate id":   {{ID: "a", URL: "https://one.example/i.json"}, {ID: "a", URL: "https://two.example/i.json"}},
		"a duplicate URL":  {{ID: "a", URL: "https://one.example/i.json"}, {ID: "b", URL: "https://one.example/i.json"}},
		"an invalid id":    {{ID: "Not An Id", URL: "https://one.example/i.json"}},
		"a URL with a ref": {{ID: "a", URL: "https://one.example/i.json#frag"}},
	} {
		if _, err := normaliseCatalogSources(sources); err == nil {
			t.Errorf("%s was accepted", name)
		}
	}

	tooMany := make([]CatalogSource, 0, maxCatalogSources+1)
	for i := 0; i <= maxCatalogSources; i++ {
		tooMany = append(tooMany, CatalogSource{ID: fmt.Sprintf("source%d", i), URL: fmt.Sprintf("https://example.com/%d.json", i)})
	}
	if _, err := normaliseCatalogSources(tooMany); err == nil {
		t.Errorf("%d catalogs were accepted", len(tooMany))
	}
}

// A fresh gateway must not contact a marketplace the operator did not choose.
// The non-nil empty slice is also part of the wire contract: Console iterates
// it directly and must receive `[]`, not `null`.
func TestFreshDocumentHasNoCatalogSources(t *testing.T) {
	document := DefaultDocument()
	if document.Catalogs == nil || len(document.Catalogs) != 0 {
		t.Fatalf("fresh catalogs = %#v, want a non-nil empty list", document.Catalogs)
	}
	cloned := cloneConfig(document)
	if cloned.Catalogs == nil || len(cloned.Catalogs) != 0 {
		t.Fatalf("cloned fresh catalogs = %#v, want a non-nil empty list", cloned.Catalogs)
	}
	if err := validateCatalogs(document.Catalogs); err != nil {
		t.Fatalf("the empty catalog list does not validate: %v", err)
	}
	raw, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), `"catalogs":[]`) {
		t.Fatalf("fresh document did not publish an empty catalog list: %s", raw)
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
  "version": 6,
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
  "version": 6,
  "execution_order": [],
  "tls_cert": "/etc/5gpn/intercept/tls/fullchain.pem",
  "tls_key": "/etc/5gpn/intercept/tls/privkey.pem",
  "mitm": {"enabled": true, "http2": true, "quic_fallback_protection": true}
}`)
	if _, err := decodeConfig(body); err == nil {
		t.Fatal("retired quic_fallback_protection key was accepted")
	}
}

// A missing key authorizes no implicit publisher. It is normalized to a
// non-nil empty list so the next write persists the current contract.
func TestADocumentWithNoCatalogKeyStaysOffline(t *testing.T) {
	body := []byte(`{
  "version": 6,
  "execution_order": [],
  "tls_cert": "/etc/5gpn/intercept/tls/fullchain.pem",
  "tls_key": "/etc/5gpn/intercept/tls/privkey.pem",
  "mitm": {"enabled": false, "http2": true}
}`)
	cfg, err := decodeConfig(body)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Catalogs == nil || len(cfg.Catalogs) != 0 {
		t.Fatalf("an absent catalog key authorized a source: %#v", cfg.Catalogs)
	}
	raw, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), `"catalogs":[]`) {
		t.Fatalf("an absent catalog key did not normalize to an empty list: %s", raw)
	}
}

// An operator who removed every catalog decided something, and that decision
// has to survive a restart. The field is not omitempty because `[]` must remain
// the explicit current wire shape.
func TestAnExplicitlyEmptyCatalogListIsNotReseeded(t *testing.T) {
	body := []byte(`{
  "version": 6,
  "execution_order": [],
  "tls_cert": "/etc/5gpn/intercept/tls/fullchain.pem",
  "tls_key": "/etc/5gpn/intercept/tls/privkey.pem",
  "mitm": {"enabled": false, "http2": true},
  "catalogs": []
}`)
	cfg, err := decodeConfig(body)
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Catalogs) != 0 {
		t.Fatalf("an emptied catalog list was re-seeded: %+v", cfg.Catalogs)
	}
	raw, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), `"catalogs":[]`) {
		t.Errorf("an empty list did not survive the write: %s", raw)
	}
}

func TestAnEmptyCatalogListSurvivesAManagementWrite(t *testing.T) {
	e := newTestEngine(t, `{
  "version": 6,
  "execution_order": [],
  "tls_cert": "/etc/5gpn/intercept/tls/fullchain.pem",
  "tls_key": "/etc/5gpn/intercept/tls/privkey.pem",
  "mitm": {"enabled": false, "http2": true, "http3": false},
  "catalogs": []
}`)
	if _, _, err := e.SetCatalogSources(e.Revision(), []CatalogSource{}); err != nil {
		t.Fatalf("SetCatalogSources: %v", err)
	}
	document, _ := e.ReadDocument()
	if document.Catalogs == nil || len(document.Catalogs) != 0 {
		t.Fatalf("management write collapsed catalogs to %#v", document.Catalogs)
	}
	raw, err := os.ReadFile(e.config.path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(raw, []byte(`"catalogs": []`)) {
		t.Fatalf("management write persisted catalogs in a non-array shape: %s", raw)
	}
}

// installFromCatalog is the setup the update tests share: an extension already
// installed from some other URL, disabled, ready to be moved onto a catalog.
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
		catalogIndexURL:    catalogIndexJSON(t, honestCapabilities, ""),
		catalogManifestURL: validManifest,
		oldURL:             validManifest,
	})
	e := catalogTestEngine(t)
	revision := installFromCatalog(t, e, oldURL)

	before, _ := e.ReadDocument()
	if got := before.Modules[0].Source.URL; got != oldURL {
		t.Fatalf("setup installed from %q", got)
	}

	digest := SnapshotDigest(mustImport(t, catalogManifestURL))
	if _, _, err := e.ApplyCatalogUpdate(context.Background(), revision, "io.5gpn.official", "example.plugin", catalogManifestURL, digest); err != nil {
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
		catalogIndexURL:    catalogIndexJSON(t, honestCapabilities, ""),
		catalogManifestURL: validManifest,
		newURL:             validManifest,
		oldURL:             validManifest,
	}
	stubImporter(t, served)
	e := catalogTestEngine(t)
	revision := installFromCatalog(t, e, oldURL)
	candidate, reviewedURL, reviewRevision, err := e.ReviewCatalogEntryView(
		context.Background(), "io.5gpn.official", "example.plugin",
	)
	if err != nil {
		t.Fatalf("ReviewCatalogEntryView: %v", err)
	}
	if reviewRevision != revision || reviewedURL != catalogManifestURL {
		t.Fatalf("review returned revision %q URL %q, want %q %q", reviewRevision, reviewedURL, revision, catalogManifestURL)
	}

	served[catalogIndexURL] = strings.Replace(served[catalogIndexURL], catalogManifestURL, newURL, 1)
	if _, err := e.Catalog(context.Background(), true); err != nil {
		t.Fatalf("refresh changed catalog: %v", err)
	}
	_, _, err = e.ApplyCatalogUpdate(
		context.Background(), reviewRevision, "io.5gpn.official", "example.plugin", reviewedURL, candidate.Digest,
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
		catalogIndexURL: catalogIndexJSON(t, honestCapabilities, ""),
		finalURL:        validManifest,
		oldURL:          validManifest,
	}
	stubImporterTransport(t, catalogRedirectTransport{
		served: served,
		from:   catalogManifestURL,
		to:     finalURL,
	})
	e := catalogTestEngine(t)
	revision := installFromCatalog(t, e, oldURL)
	candidate, reviewedURL, reviewRevision, err := e.ReviewCatalogEntryView(
		context.Background(), "io.5gpn.official", "example.plugin",
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
		context.Background(), reviewRevision, "io.5gpn.official", "example.plugin",
		candidate.Detail.SourceURL, candidate.Digest,
	); !errors.Is(err, ErrReviewConflict) {
		t.Fatalf("redirect target apply error = %v, want review conflict", err)
	}
	if current := e.Revision(); current != revision {
		t.Fatalf("wrong reviewed URL changed revision to %q, want %q", current, revision)
	}
	if _, _, err := e.ApplyCatalogUpdate(
		context.Background(), reviewRevision, "io.5gpn.official", "example.plugin",
		reviewedURL, candidate.Digest,
	); err != nil {
		t.Fatalf("apply with reviewed entry URL: %v", err)
	}
}

func TestACatalogUpdateTreatsARemovedReviewedEntryAsConflict(t *testing.T) {
	const oldURL = "https://elsewhere.example.com/example.yaml"
	served := stubFetch{
		catalogIndexURL:    catalogIndexJSON(t, honestCapabilities, ""),
		catalogManifestURL: validManifest,
		oldURL:             validManifest,
	}
	stubImporter(t, served)
	e := catalogTestEngine(t)
	revision := installFromCatalog(t, e, oldURL)
	candidate, reviewedURL, reviewRevision, err := e.ReviewCatalogEntryView(
		context.Background(), "io.5gpn.official", "example.plugin",
	)
	if err != nil {
		t.Fatalf("ReviewCatalogEntryView: %v", err)
	}
	served[catalogIndexURL] = `{
  "apiVersion": "5gpn.io/marketplace/v1",
  "kind": "ExtensionMarketplace",
  "metadata": {"id": "io.5gpn.official", "name": "Official", "homepage": "https://example.com"},
  "entries": []
}`
	if _, err := e.Catalog(context.Background(), true); err != nil {
		t.Fatalf("refresh removed catalog entry: %v", err)
	}
	_, _, err = e.ApplyCatalogUpdate(
		context.Background(), reviewRevision, "io.5gpn.official", "example.plugin", reviewedURL, candidate.Digest,
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
		catalogIndexURL:    catalogIndexJSON(t, honestCapabilities, ""),
		catalogManifestURL: validManifest,
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
	_, _, err = e.ApplyCatalogUpdate(context.Background(), revision, "io.5gpn.official", "example.plugin", catalogManifestURL, digest)
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
		catalogIndexURL:    catalogIndexJSON(t, understated, ""),
		catalogManifestURL: validManifest,
	})
	e := catalogTestEngine(t)
	revision := installFromCatalog(t, e, catalogManifestURL)

	digest := SnapshotDigest(mustImport(t, catalogManifestURL))
	_, _, err := e.ApplyCatalogUpdate(context.Background(), revision, "io.5gpn.official", "example.plugin", catalogManifestURL, digest)
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
		catalogIndexURL:    catalogIndexJSON(t, honestCapabilities, ""),
		catalogManifestURL: validManifest,
	})
	e := catalogTestEngine(t)
	revision := installFromCatalog(t, e, catalogManifestURL)
	digest := SnapshotDigest(mustImport(t, catalogManifestURL))

	if _, _, err := e.ApplyCatalogUpdate(context.Background(), revision, "io.5gpn.official", "example.plugin", "", digest); !errors.Is(err, ErrInvalidRequest) {
		t.Errorf("an update without the reviewed URL returned %v, want invalid request", err)
	}
	if _, _, err := e.ApplyCatalogUpdate(context.Background(), revision, "io.5gpn.official", "example.plugin", catalogManifestURL, ""); err == nil {
		t.Error("an update with no digest was applied")
	}
	if _, _, err := e.ApplyCatalogUpdate(context.Background(), revision, "io.5gpn.official", "example.plugin", catalogManifestURL, strings.Repeat("b", 64)); err == nil {
		t.Error("an update quoting the wrong digest was applied")
	}
}

// CheckUpdate must keep re-reading only the installed source. A catalog that
// merely exists must not redirect anything.
func TestCheckUpdateStillReadsOnlyTheInstalledSource(t *testing.T) {
	const oldURL = "https://elsewhere.example.com/example.yaml"
	stubImporter(t, stubFetch{
		catalogIndexURL:    catalogIndexJSON(t, honestCapabilities, ""),
		catalogManifestURL: validManifest,
		oldURL:             validManifest,
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
