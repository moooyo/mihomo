package engine

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
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

func stubImporter(t *testing.T, served stubFetch) *Importer {
	t.Helper()
	imp := &Importer{client: &http.Client{Transport: served}, now: time.Now}
	previous := importerRef.Load()
	SetImporter(imp)
	t.Cleanup(func() { importerRef.Store(previous) })
	return imp
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
      "resources": [{"path": "a.js", "url": "https://catalog.example.com/a.js", "sha256": "00", "size": 1}],
      "policy": {"clientRules": 4, "policyRules": 0, "captureRules": 4, "digest": "beef"},
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

// The published index carries fields this build does not use -- a `policy`
// projection of the retired overlay compiler, and per-resource digests the
// importer computes for itself. Rejecting unknown fields is what made the
// previous implementation refuse whole catalogs whenever a publisher added
// something for a newer core, so the decode ignores them.
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

// One malformed listing must not hide every other extension a publisher offers,
// so a bad entry is dropped rather than failing the catalog.
func TestUnusableEntriesAreDroppedRatherThanFailingTheCatalog(t *testing.T) {
	index := `{
  "apiVersion": "5gpn.io/marketplace/v1",
  "kind": "ExtensionMarketplace",
  "metadata": {"id": "io.5gpn.official"},
  "entries": [
    {"id": "Bad Id", "manifest": {"url": "https://catalog.example.com/a.yaml", "sha256": "aa"}},
    {"id": "insecure.plugin", "manifest": {"url": "http://catalog.example.com/b.yaml", "sha256": "bb"}},
    {"id": "good.plugin", "manifest": {"url": "https://catalog.example.com/c.yaml", "sha256": "cc"}},
    {"id": "good.plugin", "manifest": {"url": "https://catalog.example.com/d.yaml", "sha256": "dd"}}
  ]
}`
	imp := stubImporter(t, stubFetch{catalogIndexURL: index})

	decoded, err := imp.catalog(context.Background(), catalogIndexURL)
	if err != nil {
		t.Fatalf("catalog: %v", err)
	}
	if len(decoded.Entries) != 1 || decoded.Entries[0].ID != "good.plugin" {
		t.Fatalf("kept %+v, want only good.plugin", decoded.Entries)
	}
	if decoded.Entries[0].Manifest.URL != "https://catalog.example.com/c.yaml" {
		t.Errorf("the duplicate replaced the first entry: %q", decoded.Entries[0].Manifest.URL)
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

// The seeded document has to survive its own decode, catalog included.
func TestTheSeededCatalogValidates(t *testing.T) {
	if err := validateCatalogs(DefaultDocument().Catalogs); err != nil {
		t.Fatalf("the seeded catalog does not validate: %v", err)
	}
}

// The fixture is the first-party index as published, fetched from the URL the
// seeded document names.
//
// Every other test here decodes a shape this file also wrote, which proves the
// decoder agrees with itself. This one proves it agrees with the catalog the
// gateway will actually fetch on its first day -- including the two fields the
// publisher emits and this build ignores, `resources` and the retired `policy`
// projection. Refresh it from officialCatalogURL when the published shape moves.
func TestTheFirstPartyIndexAsPublishedDecodes(t *testing.T) {
	published, err := os.ReadFile(filepath.Join("testdata", "marketplace-index.json"))
	if err != nil {
		t.Fatal(err)
	}
	imp := stubImporter(t, stubFetch{officialCatalogURL: string(published)})

	index, err := imp.catalog(context.Background(), officialCatalogURL)
	if err != nil {
		t.Fatalf("the published first-party index did not decode: %v", err)
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

// A document written by the build before HTTP/3 capture still opens.
//
// Renaming quic_fallback_protection to http3 made DisallowUnknownFields refuse
// every deployed gateway's intercept.json at once -- and refusing it is a
// warning, not a fatal, so the gateway came up resolving and forwarding with
// interception silently absent. That is the worst shape a failure can have.
//
// The strictness is not relaxed. A typo in a hand-edited document must still be
// refused; a key this program itself retired is not a typo.
func TestADocumentFromBeforeTheHTTP3RenameStillOpens(t *testing.T) {
	body := []byte(`{
  "version": 6,
  "execution_order": [],
  "tls_cert": "/etc/5gpn/intercept/tls/fullchain.pem",
  "tls_key": "/etc/5gpn/intercept/tls/privkey.pem",
  "mitm": {"enabled": true, "http2": true, "quic_fallback_protection": true}
}`)
	cfg, err := decodeConfig(body)
	if err != nil {
		t.Fatalf("a pre-rename document was refused: %v", err)
	}
	if !cfg.MITM.Enabled || !cfg.MITM.HTTP2 {
		t.Errorf("the operator's settings did not survive: %+v", cfg.MITM)
	}
	// Dropped, never mapped: an operator who had "fallback protection" on has
	// not thereby asked for QUIC to be terminated here.
	if cfg.MITM.HTTP3 {
		t.Error("the retired flag was mapped onto http3 instead of being dropped")
	}
	// And it does not come back on the next write.
	raw, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "quic_fallback_protection") {
		t.Errorf("the retired key was re-emitted: %s", raw)
	}
}

// The strictness that made the rename dangerous is what catches a typo, so it
// has to survive the fix.
func TestAnUnknownFieldThatIsNotRetiredIsStillRefused(t *testing.T) {
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

// A document with nothing retired in it must be passed through untouched, or
// every gateway's revision would move for no reason on first read.
func TestAnOrdinaryDocumentIsNotRewritten(t *testing.T) {
	body := []byte(`{"mitm": {"enabled": true}}`)
	out, err := dropRetiredFields(body)
	if err != nil {
		t.Fatal(err)
	}
	if string(out) != string(body) {
		t.Errorf("an ordinary document was rewritten:\n got %s\nwant %s", out, body)
	}
}
