package engine

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/metacubex/mihomo/5gpn/state"
)

// A document with two extensions, one enabled, both declaring overlapping
// hosts. Overlap is the interesting case: it is what execution order decides.
const twoExtensionDocument = `{
  "version": 6,
  "execution_order": ["first", "second"],
  "tls_cert": "/etc/5gpn/intercept/tls/fullchain.pem",
  "tls_key": "/etc/5gpn/intercept/tls/privkey.pem",
  "mitm": {"enabled": true, "http2": true, "http3": false},
  "modules": [
    {
      "id": "first",
      "extension_version": "1.0.0",
      "name": "First",
      "enabled": true,
      "imported_at": "2026-08-01T00:00:00Z",
      "source": {"digest": "44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a", "body": "{}"},
      "capture_hosts": ["*.first.example", "shared.example.com"],
      "capture_dns": "trust",
      "upstream_mappings": [{"host": "shared.example.com", "target": "origin-one.example.net"}],
      "persistent_storage": false,
      "egress_group_required": false,
      "egress_group": "DIRECT"
    },
    {
      "id": "second",
      "extension_version": "2.0.0",
      "name": "Second",
      "enabled": false,
      "imported_at": "2026-08-01T00:00:00Z",
      "source": {"digest": "44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a", "body": "{}"},
      "capture_hosts": ["*.second.example", "shared.example.com"],
      "capture_dns": "china",
      "upstream_mappings": [{"host": "api.second.example", "target": "origin-two.example.net"}],
      "persistent_storage": false,
      "egress_group_required": true,
      "egress_group": "DIRECT",
      "settings": [
        {"key": "region", "type": "select", "required": true, "options": ["cn", "hk"], "value": "cn"}
      ]
    }
  ]
}`

func newTestEngine(t *testing.T, document string) *Engine {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "intercept.json")
	if err := os.WriteFile(path, []byte(document), 0o600); err != nil {
		t.Fatal(err)
	}
	workers, err := newWorkerController()
	if err != nil {
		t.Fatalf("newWorkerController: %v", err)
	}
	t.Cleanup(func() { _ = workers.Close() })
	store, err := newConfigStore(path, workers)
	if err != nil {
		t.Fatalf("newConfigStore: %v", err)
	}
	// Only the store is under test here. Assembling the proxy buys nothing:
	// every method below reads and writes the document and nothing else.
	return &Engine{config: store, workers: workers}
}

func TestCaptureOwnershipFollowsExecutionOrder(t *testing.T) {
	e := newTestEngine(t, twoExtensionDocument)

	// Only "first" is enabled, so it owns the shared host even though both
	// declared it.
	binding, ok := e.CaptureFor("shared.example.com")
	if !ok || binding.ModuleID != "first" {
		t.Fatalf("CaptureFor(shared) = %+v, %v; want first", binding, ok)
	}
	if !binding.Ready {
		t.Error("the binding is not ready with the master on")
	}

	// Every installed extension has an explicit DIRECT default, so enabling the
	// second needs no separate binding step. Reordering then gives it ownership.
	if _, _, err := e.SetEnabled(e.Revision(), "second", true); err != nil {
		t.Fatal(err)
	}
	if _, _, err := e.Reorder(e.Revision(), []string{"second", "first"}); err != nil {
		t.Fatal(err)
	}

	binding, ok = e.CaptureFor("shared.example.com")
	if !ok || binding.ModuleID != "second" {
		t.Fatalf("after reorder CaptureFor(shared) = %+v, %v; want second", binding, ok)
	}
	// And the resolver binding travels with ownership, which is the reason
	// reordering is a reviewed change rather than a cosmetic one.
	if binding.CaptureDNS != "china" {
		t.Errorf("capture DNS %q, want china -- the new owner's binding", binding.CaptureDNS)
	}
}

func TestStartupRejectsMissingCurrentEgressBindings(t *testing.T) {
	invalid := strings.ReplaceAll(twoExtensionDocument, ",\n      \"egress_group\": \"DIRECT\"", "")
	path := filepath.Join(t.TempDir(), "intercept.json")
	if err := os.WriteFile(path, []byte(invalid), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := newConfigStore(path); err == nil || !strings.Contains(err.Error(), "egress_group") {
		t.Fatalf("startup with missing egress bindings returned %v", err)
	}
}

func TestCurrentConfigDecodeRejectsAnEmptyEgressBinding(t *testing.T) {
	currentWithEmpty := strings.Replace(twoExtensionDocument, `"egress_group": "DIRECT"`, `"egress_group": ""`, 1)
	if _, err := decodeConfig([]byte(currentWithEmpty)); err == nil || !strings.Contains(err.Error(), "egress_group") {
		t.Fatalf("current empty egress decode returned %v", err)
	}
}

// A wildcard covers subdomains and not the apex, and each extension only owns
// what it declared.
func TestCaptureMatchesWildcardsAndNotTheApex(t *testing.T) {
	e := newTestEngine(t, twoExtensionDocument)
	if _, ok := e.CaptureFor("a.first.example"); !ok {
		t.Error("the wildcard did not cover a subdomain")
	}
	if _, ok := e.CaptureFor("first.example"); ok {
		t.Error("the wildcard covered its own apex")
	}
	if _, ok := e.CaptureFor("unrelated.example"); ok {
		t.Error("an undeclared host matched")
	}
	// The disabled extension's own hosts are nobody's.
	if _, ok := e.CaptureFor("x.second.example"); ok {
		t.Error("a disabled extension captured a host")
	}
}

// With the master off nothing is captured, but the declaration is still
// reported: the extensions page shows the extension as enabled, so "why is this
// not captured" has to answer "the master switch".
func TestCaptureReportsDeclarationWithTheMasterOff(t *testing.T) {
	e := newTestEngine(t, twoExtensionDocument)
	if _, _, err := e.SetSettings(e.Revision(), MITMSettings{Enabled: false, HTTP2: true}); err != nil {
		t.Fatal(err)
	}
	binding, ok := e.CaptureFor("shared.example.com")
	if !ok {
		t.Fatal("the declaration disappeared with the master off")
	}
	if binding.Ready {
		t.Error("the binding reports ready with the master off")
	}

	snapshot, err := e.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	if len(snapshot.ActiveCaptureHosts) != 0 {
		t.Errorf("active capture hosts %v with the master off", snapshot.ActiveCaptureHosts)
	}
}

func TestPersistedDocumentKeepsHTTP3FalseAndRejectsTrueAtStartup(t *testing.T) {
	cfg, err := decodeConfig([]byte(twoExtensionDocument))
	if err != nil {
		t.Fatalf("document with http3 false did not load: %v", err)
	}
	if cfg.MITM.HTTP3 {
		t.Fatal("document with http3 false loaded as true")
	}

	document := strings.Replace(twoExtensionDocument, `"http3": false`, `"http3": true`, 1)
	path := filepath.Join(t.TempDir(), "intercept.json")
	if err := os.WriteFile(path, []byte(document), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err = newConfigStore(path)
	if err == nil {
		t.Fatal("startup accepted a persisted document enabling HTTP/3 interception")
	}
	if !strings.Contains(err.Error(), "HTTP/3") || !strings.Contains(err.Error(), "unsupported") || !strings.Contains(err.Error(), "blocked") {
		t.Fatalf("HTTP/3 rejection %q does not explain the unsupported blocked protocol", err)
	}
}

func TestSetSettingsRejectsHTTP3WithoutPublishing(t *testing.T) {
	e := newTestEngine(t, twoExtensionDocument)
	before, revision := e.ReadDocument()

	_, returnedRevision, err := e.SetSettings(revision, MITMSettings{
		Enabled: true,
		HTTP2:   true,
		HTTP3:   true,
	})
	if err == nil {
		t.Fatal("SetSettings accepted HTTP/3 interception")
	}
	if !strings.Contains(err.Error(), "HTTP/3") || !strings.Contains(err.Error(), "unsupported") {
		t.Fatalf("SetSettings returned an unclear error: %v", err)
	}
	if returnedRevision != revision {
		t.Errorf("rejected write returned revision %s, want unchanged %s", returnedRevision, revision)
	}

	after, stillRevision := e.ReadDocument()
	if stillRevision != revision {
		t.Errorf("revision moved from %s to %s after a rejected HTTP/3 write", revision, stillRevision)
	}
	if before.MITM != after.MITM || after.MITM.HTTP3 {
		t.Errorf("rejected HTTP/3 write changed settings from %+v to %+v", before.MITM, after.MITM)
	}
}

func TestWritesRequireTheCurrentRevision(t *testing.T) {
	e := newTestEngine(t, twoExtensionDocument)
	stale := e.Revision()

	if _, _, err := e.SetCaptureDNS(stale, "first", "china"); err != nil {
		t.Fatal(err)
	}
	// The same revision a second time is now stale.
	if _, _, err := e.SetCaptureDNS(stale, "first", "trust"); !errors.Is(err, state.ErrRevisionConflict) {
		t.Fatalf("a stale write returned %v, want a revision conflict", err)
	}
	// And the first write stands.
	cfg, _ := e.ReadDocument()
	for _, m := range cfg.Modules {
		if m.ID == "first" && m.CaptureDNS != "china" {
			t.Errorf("capture DNS is %q; the stale write was applied", m.CaptureDNS)
		}
	}
}

func TestMutationResponseUsesTheConfigCommittedAtItsReturnedRevision(t *testing.T) {
	e := newTestEngine(t, twoExtensionDocument)
	initial := e.Revision()
	var callbackRevision string
	var callbackErr error
	e.trafficChanged = func() {
		_, callbackRevision, callbackErr = e.config.Update(e.Revision(), func(current Config) (Config, error) {
			candidate := cloneConfig(current)
			module, err := findModule(&candidate, "first")
			if err != nil {
				return current, err
			}
			module.CaptureDNS = "trust"
			return candidate, nil
		})
	}

	snapshot, revision, err := e.SetCaptureDNS(initial, "first", "china")
	if err != nil {
		t.Fatalf("first mutation: %v", err)
	}
	if callbackErr != nil {
		t.Fatalf("interleaved mutation: %v", callbackErr)
	}
	if revision == initial || callbackRevision == revision || e.Revision() != callbackRevision {
		t.Fatalf("revisions initial=%q response=%q callback=%q current=%q", initial, revision, callbackRevision, e.Revision())
	}
	for _, module := range snapshot.Modules {
		if module.ID == "first" && module.CaptureDNS != "china" {
			t.Fatalf("response snapshot came from later revision: %+v", module)
		}
	}
	current, _ := e.ReadDocument()
	for _, module := range current.Modules {
		if module.ID == "first" && module.CaptureDNS != "trust" {
			t.Fatalf("interleaved current config = %+v", module)
		}
	}
}

func TestRejectedWriteLeavesTheDocumentRunning(t *testing.T) {
	e := newTestEngine(t, twoExtensionDocument)
	before, revision := e.ReadDocument()

	if _, _, err := e.SetCaptureDNS(revision, "first", "somewhere-else"); err == nil {
		t.Fatal("an invalid resolver binding was accepted")
	}
	if _, _, err := e.Reorder(revision, []string{"first", "first"}); err == nil {
		t.Fatal("a duplicate in the order was accepted")
	}
	if _, _, err := e.Reorder(revision, []string{"first"}); err == nil {
		t.Fatal("a short order was accepted")
	}
	if _, _, err := e.SetEnabled(revision, "nonexistent", true); !errors.Is(err, ErrModuleNotFound) {
		t.Fatal("enabling an unknown extension did not report it as missing")
	}

	after, stillRevision := e.ReadDocument()
	if stillRevision != revision {
		t.Errorf("the revision moved from %s to %s on writes that all failed", revision, stillRevision)
	}
	if len(after.Modules) != len(before.Modules) || after.Modules[0].CaptureDNS != before.Modules[0].CaptureDNS {
		t.Error("a rejected write changed the running document")
	}
}

// An import is a decision to have the code on the box. Enabling it is a
// separate decision about letting it see traffic.
func TestInstallAlwaysLandsDisabled(t *testing.T) {
	e := newTestEngine(t, twoExtensionDocument)
	_, revision, err := e.install(e.Revision(), Module{
		ID:           "third",
		Version:      "0.1.0",
		Name:         "Third",
		Enabled:      true, // ignored
		ImportedAt:   "2026-08-02T00:00:00Z",
		Source:       ModuleSource{Digest: "44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a", Body: "{}"},
		CaptureHosts: []string{"third.example.com"},
		HostMappings: []HostMapping{{Pattern: "third.example.com", Target: "origin-three.example.net"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	cfg, _ := e.ReadDocument()
	found := false
	for _, m := range cfg.Modules {
		if m.ID != "third" {
			continue
		}
		found = true
		if m.Enabled {
			t.Error("an install landed enabled")
		}
		if m.CaptureDNS != "trust" {
			t.Errorf("capture DNS defaulted to %q, want trust", m.CaptureDNS)
		}
	}
	if !found {
		t.Fatal("the extension was not installed")
	}
	if !strings.Contains(strings.Join(cfg.ExecutionOrder, ","), "third") {
		t.Error("the install did not take a place in the execution order")
	}
	if revision == "" {
		t.Error("the write returned no revision")
	}
}

func TestInstallRejectsAnExistingID(t *testing.T) {
	e := newTestEngine(t, twoExtensionDocument)
	revision := e.Revision()
	_, returned, err := e.install(revision, Module{ID: "first", Version: "9.9.9"})
	if !errors.Is(err, ErrInvalidRequest) || returned != revision || e.Revision() != revision {
		t.Fatalf("duplicate install returned revision=%q err=%v current=%q", returned, err, e.Revision())
	}
}

// Updating keeps what the operator entered. The publisher does not own the
// egress binding, the resolver binding, or the values typed into settings, and
// silently clearing them leaves a required setting empty with the extension
// refusing to enable and nothing saying why.
func TestUpdateCarriesOperatorStateForward(t *testing.T) {
	e := newTestEngine(t, twoExtensionDocument)
	if _, _, err := e.SetEgressGroup(e.Revision(), "second", "Proxies"); err != nil {
		t.Fatal(err)
	}

	if _, _, err := e.update(e.Revision(), Module{
		ID:           "second",
		Version:      "2.1.0",
		Name:         "Second",
		ImportedAt:   "2026-08-02T00:00:00Z",
		Source:       ModuleSource{Digest: "44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a", Body: "{}"},
		CaptureHosts: []string{"*.second.example", "shared.example.com"},
		HostMappings: []HostMapping{{Pattern: "api.second.example", Target: "origin-two.example.net"}},
		CaptureDNS:   "trust", // the publisher's default, which must not win
		Settings: []ModuleSetting{
			{Key: "region", Type: "select", Required: true, Options: []string{"cn", "hk"}},
		},
		EgressGroupRequired: true,
	}, nil); err != nil {
		t.Fatal(err)
	}

	cfg, _ := e.ReadDocument()
	for _, m := range cfg.Modules {
		if m.ID != "second" {
			continue
		}
		if m.Version != "2.1.0" {
			t.Errorf("version %q, want the new one", m.Version)
		}
		if m.EgressGroup != "Proxies" {
			t.Errorf("egress group %q, want the operator's binding preserved", m.EgressGroup)
		}
		if m.CaptureDNS != "china" {
			t.Errorf("capture DNS %q, want the operator's binding preserved", m.CaptureDNS)
		}
		if len(m.Settings) != 1 || string(m.Settings[0].Value) != `"cn"` {
			t.Errorf("settings %+v, want the entered value carried over", m.Settings)
		}
	}
}

// A type change means the stored value is no longer meaningful.
func TestReinstallDropsAValueWhoseTypeChanged(t *testing.T) {
	previous := []ModuleSetting{{Key: "region", Type: "select", Value: json.RawMessage(`"cn"`)}}
	incoming := []ModuleSetting{{Key: "region", Type: "number"}}
	got := carryOverSettingValues(previous, incoming)
	if len(got[0].Value) != 0 {
		t.Errorf("value %s survived a type change", got[0].Value)
	}
}

func TestCarryOverFallsBackToTheNewDefaultWhenConstraintsChanged(t *testing.T) {
	previous := []ModuleSetting{{
		Key: "region", Type: "select", Options: []string{"cn", "hk"}, Value: json.RawMessage(`"hk"`),
	}}
	incoming := []ModuleSetting{{
		Key: "region", Type: "select", Required: true, Options: []string{"cn"},
		Default: json.RawMessage(`"cn"`), Value: json.RawMessage(`"cn"`),
	}}
	got := carryOverSettingValues(previous, incoming)
	if value := string(got[0].Value); value != `"cn"` {
		t.Fatalf("carried invalid old option %s instead of new default", value)
	}
}

func TestSetSettingValuesIsACompleteAtomicTransaction(t *testing.T) {
	e := newTestEngine(t, twoExtensionDocument)
	revision := e.Revision()

	rejected := []SettingValues{
		nil,
		{},
		{"region": json.RawMessage(`"cn"`), "unknown": json.RawMessage(`true`)},
		{"region": json.RawMessage(`"outside-the-declared-options"`)},
	}
	for _, values := range rejected {
		_, returned, err := e.SetSettingValues(revision, "second", values)
		if !errors.Is(err, ErrInvalidRequest) || !errors.Is(err, ErrUnprocessable) {
			t.Fatalf("SetSettingValues(%v) returned %v, want an unprocessable invalid request", values, err)
		}
		if returned != revision || e.Revision() != revision {
			t.Fatalf("rejected settings write moved revision %q to returned=%q current=%q", revision, returned, e.Revision())
		}
		detail, detailErr := e.Detail("second")
		if detailErr != nil {
			t.Fatal(detailErr)
		}
		if got := string(detail.Settings[0].Value); got != `"cn"` {
			t.Fatalf("rejected settings write changed region to %s", got)
		}
	}

	_, next, err := e.SetSettingValues(revision, "second", SettingValues{
		"region": json.RawMessage(`"hk"`),
	})
	if err != nil {
		t.Fatalf("SetSettingValues(valid): %v", err)
	}
	if next == revision {
		t.Fatal("valid complete settings write did not move the revision")
	}
	detail, err := e.Detail("second")
	if err != nil {
		t.Fatal(err)
	}
	if got := string(detail.Settings[0].Value); got != `"hk"` {
		t.Fatalf("stored region = %s, want hk", got)
	}
}

func TestSetSettingValuesCanClearAnOptionalValue(t *testing.T) {
	e := newTestEngine(t, twoExtensionDocument)
	if _, _, err := e.install(e.Revision(), Module{
		ID:           "optional-setting",
		Version:      "1.0.0",
		Name:         "Optional setting",
		ImportedAt:   "2026-08-06T00:00:00Z",
		Source:       ModuleSource{Digest: digestText("{}"), Body: "{}"},
		CaptureHosts: []string{"optional.example.com"},
		HostMappings: []HostMapping{{Pattern: "optional.example.com", Target: "origin.optional.example.net"}},
		Settings: []ModuleSetting{{
			Key: "note", Type: "text", Value: json.RawMessage(`"present"`),
		}},
	}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := e.SetSettingValues(e.Revision(), "optional-setting", SettingValues{
		"note": json.RawMessage(`null`),
	}); err != nil {
		t.Fatalf("clear optional value: %v", err)
	}
	detail, err := e.Detail("optional-setting")
	if err != nil {
		t.Fatal(err)
	}
	if len(detail.Settings) != 1 || len(detail.Settings[0].Value) != 0 {
		t.Fatalf("optional value was not cleared: %+v", detail.Settings)
	}
}

func TestUninstallRemovesTheExtensionAndItsPlaceInTheOrder(t *testing.T) {
	e := newTestEngine(t, twoExtensionDocument)
	if _, _, err := e.Uninstall(e.Revision(), "second"); err != nil {
		t.Fatal(err)
	}
	cfg, _ := e.ReadDocument()
	for _, m := range cfg.Modules {
		if m.ID == "second" {
			t.Fatal("the extension survived uninstall")
		}
	}
	for _, id := range cfg.ExecutionOrder {
		if id == "second" {
			t.Fatal("the execution order still names the uninstalled extension")
		}
	}
	if _, _, err := e.Uninstall(e.Revision(), "second"); !errors.Is(err, ErrModuleNotFound) {
		t.Errorf("a second uninstall returned %v, want not-found", err)
	}
}

// The store publishes what it persisted, so a restart reads back exactly the
// configuration that was live.
func TestWritesRoundTripThroughDisk(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "intercept.json")
	if err := os.WriteFile(path, []byte(twoExtensionDocument), 0o600); err != nil {
		t.Fatal(err)
	}
	store, err := newConfigStore(path)
	if err != nil {
		t.Fatal(err)
	}
	e := &Engine{config: store}
	if _, _, err := e.SetCaptureDNS(e.Revision(), "first", "china"); err != nil {
		t.Fatal(err)
	}
	want := e.Revision()

	reopened, err := newConfigStore(path)
	if err != nil {
		t.Fatalf("the persisted document does not load: %v", err)
	}
	if got := reopened.Revision(); got != want {
		t.Errorf("reopened revision %s, live %s", got, want)
	}
	cfg, err := reopened.Current()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Modules[0].CaptureDNS != "china" {
		t.Error("the write did not reach disk")
	}
}

// An invalid document on disk must not take the running capture set with it.
func TestReloadKeepsTheLastValidSnapshot(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "intercept.json")
	if err := os.WriteFile(path, []byte(twoExtensionDocument), 0o600); err != nil {
		t.Fatal(err)
	}
	store, err := newConfigStore(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(`{"version": 6, "nonsense":`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := store.Reload(); err == nil {
		t.Fatal("an invalid document was accepted")
	}
	cfg, err := store.Current()
	if err != nil {
		t.Fatalf("the store lost its snapshot: %v", err)
	}
	if len(cfg.Modules) != 2 {
		t.Errorf("%d modules after a rejected reload, want the previous 2", len(cfg.Modules))
	}
}

// A gateway with no extensions installed is every gateway on its first day, and
// its very first write used to fail: append([]string(nil), empty...) is nil,
// nil marshals to null, and the decode that follows a write rejects a null
// execution order. Found on a live box, not here, which is why it is here now.
func TestFirstWriteOnAnEmptyGatewaySucceeds(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "intercept.json")
	if err := EnsureDocument(path); err != nil {
		t.Fatalf("EnsureDocument: %v", err)
	}
	store, err := newConfigStore(path)
	if err != nil {
		t.Fatalf("newConfigStore: %v", err)
	}
	e := &Engine{config: store}

	if _, _, err := e.SetSettings(e.Revision(), MITMSettings{Enabled: true, HTTP2: true}); err != nil {
		t.Fatalf("turning the master on for a gateway with no extensions: %v", err)
	}

	cfg, _ := e.ReadDocument()
	if !cfg.MITM.Enabled {
		t.Error("the master did not turn on")
	}
	// And it survives a reopen, which is what proves the persisted bytes are
	// something this program can read back.
	if _, err := newConfigStore(path); err != nil {
		t.Errorf("the persisted document does not reload: %v", err)
	}
}

// The seeded document is what a fresh install starts from, so it has to be
// valid on its own terms before anything writes to it.
func TestSeededDocumentIsValidAndInert(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "intercept.json")
	if err := EnsureDocument(path); err != nil {
		t.Fatalf("EnsureDocument: %v", err)
	}
	store, err := newConfigStore(path)
	if err != nil {
		t.Fatalf("the seeded document does not load: %v", err)
	}
	cfg, err := store.Current()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.MITM.Enabled {
		t.Error("a fresh gateway starts with the MITM master on")
	}
	if len(cfg.Modules) != 0 {
		t.Errorf("a fresh gateway starts with %d extensions", len(cfg.Modules))
	}

	// EnsureDocument must not touch a document that already exists -- doing so
	// would discard whatever the operator had installed.
	before, _ := os.ReadFile(path)
	if err := EnsureDocument(path); err != nil {
		t.Fatal(err)
	}
	after, _ := os.ReadFile(path)
	if string(before) != string(after) {
		t.Error("EnsureDocument rewrote an existing document")
	}
}

// The certificate request is what a root oneshot holding the CA signing key
// reads to decide what to mint. It must exist from the moment the document
// does, and it must follow every change to the enabled capture set.
func TestCertificateRequestIsPublishedAndFollowsTheDocument(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "intercept.json")
	if err := os.WriteFile(path, []byte(twoExtensionDocument), 0o600); err != nil {
		t.Fatal(err)
	}
	store, err := newConfigStore(path)
	if err != nil {
		t.Fatal(err)
	}
	e := &Engine{config: store}

	requestPath := filepath.Join(dir, "certificate-request")
	read := func() certificateRequest {
		t.Helper()
		request, err := readCertificateRequest(requestPath)
		if err != nil {
			t.Fatalf("the certificate request is not published: %v", err)
		}
		return request
	}

	initial := read()
	if initial.Version != certificateRequestVersion || len(initial.TargetDigest) != 64 || len(initial.Attempt) != certificateAttemptBytes*2 {
		t.Errorf("invalid certificate request identity: %+v", initial)
	}
	// Only "first" is enabled, so only its hosts are covered. A leaf naming a
	// disabled extension's hosts would let capture begin the moment it was
	// enabled, with no reissue and therefore no record of the widening.
	if !equalUnordered(initial.Hosts, []string{"*.first.example", "shared.example.com"}) {
		t.Errorf("hosts %v, want only the enabled extension's", initial.Hosts)
	}

	// Enabling the second widens the set, and the digest has to move with it --
	// the oneshot compares digests to decide whether to reissue.
	if _, _, err := e.SetEgressGroup(e.Revision(), "second", "Proxies"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := e.SetEnabled(e.Revision(), "second", true); err != nil {
		t.Fatal(err)
	}
	widened := read()
	if widened.TargetDigest == initial.TargetDigest || widened.Attempt == initial.Attempt {
		t.Error("the digest did not move when an extension was enabled")
	}
	if !equalUnordered(widened.Hosts, []string{"*.first.example", "*.second.example", "shared.example.com"}) {
		t.Errorf("hosts %v after enabling the second extension", widened.Hosts)
	}

	// An edit that does not change what must be covered must NOT move the
	// digest: reissuing on every unrelated change burns the CA and churns the
	// leaf under live sessions.
	if _, _, err := e.SetCaptureDNS(e.Revision(), "first", "china"); err != nil {
		t.Fatal(err)
	}
	again := read()
	if again.TargetDigest != widened.TargetDigest || again.Attempt != widened.Attempt || !equalStrings(again.Hosts, widened.Hosts) {
		t.Error("an unrelated edit moved the certificate request identity")
	}
}

func equalUnordered(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	seen := map[string]int{}
	for _, v := range a {
		seen[v]++
	}
	for _, v := range b {
		seen[v]--
	}
	for _, n := range seen {
		if n != 0 {
			return false
		}
	}
	return true
}
