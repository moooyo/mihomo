package engine

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/metacubex/mihomo/gpn/state"
)

// A document with two extensions, one enabled, both declaring overlapping
// hosts. Overlap is the interesting case: it is what execution order decides.
const twoExtensionDocument = `{
  "version": 6,
  "execution_order": ["first", "second"],
  "tls_cert": "/etc/5gpn/intercept/tls/fullchain.pem",
  "tls_key": "/etc/5gpn/intercept/tls/privkey.pem",
  "mitm": {"enabled": true, "http2": true, "quic_fallback_protection": false},
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
      "egress_group_required": false
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
	store, err := newConfigStore(path)
	if err != nil {
		t.Fatalf("newConfigStore: %v", err)
	}
	// Only the store is under test here. Assembling the certificate store and
	// the proxy would need a real leaf on disk and buys nothing: every method
	// below reads and writes the document and nothing else.
	return &Engine{config: store}
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

	// Enable the second and put it at the head of the order: it takes the host.
	if _, revision, err := e.SetEnabled(e.Revision(), "second", true); err == nil {
		t.Fatalf("enabling an extension that requires an egress group with none bound was accepted (revision %s)", revision)
	}
	if _, _, err := e.SetEgressGroup(e.Revision(), "second", "Proxies"); err != nil {
		t.Fatal(err)
	}
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

// Reinstalling keeps what the operator entered. The publisher does not own the
// egress binding, the resolver binding, or the values typed into settings, and
// silently clearing them leaves a required setting empty with the extension
// refusing to enable and nothing saying why.
func TestReinstallCarriesOperatorStateForward(t *testing.T) {
	e := newTestEngine(t, twoExtensionDocument)
	if _, _, err := e.SetEgressGroup(e.Revision(), "second", "Proxies"); err != nil {
		t.Fatal(err)
	}

	if _, _, err := e.install(e.Revision(), Module{
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
	}); err != nil {
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
