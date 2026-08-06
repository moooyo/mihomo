package engine

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"
)

func setTestImporter(t *testing.T, imp *Importer) {
	t.Helper()
	previous := importerRef.Load()
	SetImporter(imp)
	t.Cleanup(func() { importerRef.Store(previous) })
}

func assertConfigUnchanged(t *testing.T, e *Engine, revision string, body []byte) {
	t.Helper()
	if got := e.Revision(); got != revision {
		t.Errorf("review changed revision from %q to %q", revision, got)
	}
	after, err := os.ReadFile(e.config.path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(after, body) {
		t.Error("review changed the persisted config")
	}
}

func assertModuleNotInstalled(t *testing.T, e *Engine, id string) {
	t.Helper()
	if _, err := e.Detail(id); !errors.Is(err, ErrModuleNotFound) {
		t.Errorf("review installed the candidate: %v", err)
	}
}

func TestFetchDryRunsInstallWithoutMutation(t *testing.T) {
	setTestImporter(t, &Importer{})
	e := newTestEngine(t, twoExtensionDocument)
	revision := e.Revision()
	body, err := os.ReadFile(e.config.path)
	if err != nil {
		t.Fatal(err)
	}

	candidate, err := e.Fetch(context.Background(), ImportRequest{Content: validManifest})
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if candidate.Detail.ID != "example.plugin" || candidate.Digest == "" {
		t.Fatalf("candidate = %+v", candidate)
	}
	assertConfigUnchanged(t, e, revision, body)
	assertModuleNotInstalled(t, e, "example.plugin")
}

func TestFetchAndInstallUseTheSameCompleteValidation(t *testing.T) {
	imp := &Importer{}
	setTestImporter(t, imp)
	e := newTestEngine(t, twoExtensionDocument)
	revision := e.Revision()
	body, err := os.ReadFile(e.config.path)
	if err != nil {
		t.Fatal(err)
	}
	invalid := strings.Replace(validManifest,
		"function transform(context) { return {}; }",
		"function transform(", 1)

	_, reviewErr := e.Fetch(context.Background(), ImportRequest{Content: invalid})
	if reviewErr == nil || !strings.Contains(reviewErr.Error(), "does not compile") {
		t.Fatalf("Fetch returned %v, want the script compile failure", reviewErr)
	}
	assertConfigUnchanged(t, e, revision, body)
	assertModuleNotInstalled(t, e, "example.plugin")

	module, err := imp.Import(context.Background(), ImportRequest{Content: invalid})
	if err != nil {
		t.Fatalf("Import: %v", err)
	}
	_, _, installErr := e.Install(context.Background(), revision, InstallRequest{
		ImportRequest: ImportRequest{Content: invalid},
		Digest:        SnapshotDigest(module),
	})
	if installErr == nil {
		t.Fatal("Install accepted the invalid script")
	}
	if installErr.Error() != reviewErr.Error() {
		t.Fatalf("Fetch validation = %q, Install validation = %q", reviewErr, installErr)
	}
}

func TestFetchRejectsUnsafeMappingWithInstallValidation(t *testing.T) {
	imp := &Importer{}
	setTestImporter(t, imp)
	e := newTestEngine(t, twoExtensionDocument)
	revision := e.Revision()
	body, err := os.ReadFile(e.config.path)
	if err != nil {
		t.Fatal(err)
	}
	unsafe := strings.Replace(validManifest, "target: Origin.Example.NET.", "target: 10.0.0.1", 1)

	module, err := imp.Import(context.Background(), ImportRequest{Content: unsafe})
	if err != nil {
		t.Fatalf("Importer should parse the structural manifest: %v", err)
	}
	if got := module.HostMappings[0].Target; got != "10.0.0.1" {
		t.Fatalf("imported mapping target = %q", got)
	}

	_, reviewErr := e.Fetch(context.Background(), ImportRequest{Content: unsafe})
	if reviewErr == nil || !strings.Contains(reviewErr.Error(), "upstream mapping") {
		t.Fatalf("Fetch returned %v, want the unsafe mapping validation error", reviewErr)
	}
	assertConfigUnchanged(t, e, revision, body)
	assertModuleNotInstalled(t, e, "example.plugin")

	_, _, installErr := e.Install(context.Background(), revision, InstallRequest{
		ImportRequest: ImportRequest{Content: unsafe},
		Digest:        SnapshotDigest(module),
	})
	if installErr == nil || !strings.Contains(installErr.Error(), "upstream mapping") {
		t.Fatalf("Install returned %v, want the unsafe mapping validation error", installErr)
	}
	if installErr.Error() != reviewErr.Error() {
		t.Fatalf("Fetch validation = %q, Install validation = %q", reviewErr, installErr)
	}
	assertConfigUnchanged(t, e, revision, body)
	assertModuleNotInstalled(t, e, "example.plugin")
}

func TestCheckUpdateDryRunsAnExistingExtensionReplacement(t *testing.T) {
	const sourceURL = "https://updates.example.com/second.yaml"
	replacement := strings.Replace(validManifest, "id: example.plugin", "id: second", 1)
	stubImporter(t, stubFetch{sourceURL: replacement})

	cfg, err := decodeConfig([]byte(twoExtensionDocument))
	if err != nil {
		t.Fatal(err)
	}
	for i := range cfg.Modules {
		if cfg.Modules[i].ID == "second" {
			cfg.Modules[i].Source.URL = sourceURL
		}
	}
	raw, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	e := newTestEngine(t, string(raw))
	revision := e.Revision()
	body, err := os.ReadFile(e.config.path)
	if err != nil {
		t.Fatal(err)
	}

	candidate, err := e.CheckUpdate(context.Background(), "second")
	if err != nil {
		t.Fatalf("CheckUpdate: %v", err)
	}
	if candidate.Detail.ID != "second" || candidate.Detail.SourceURL != sourceURL {
		t.Fatalf("candidate = %+v", candidate)
	}
	if candidate.Installed == "" || candidate.InstalledVersion != "2.0.0" {
		t.Fatalf("installed identity = %q version %q", candidate.Installed, candidate.InstalledVersion)
	}
	assertConfigUnchanged(t, e, revision, body)
	installed, err := e.Detail("second")
	if err != nil {
		t.Fatal(err)
	}
	if installed.Version != "2.0.0" || installed.CaptureDNS != "china" {
		t.Fatalf("review changed installed operator state: %+v", installed)
	}
}

func installEnabledUpdateFixture(t *testing.T, sourceURL, manifest string, bindEgress bool) *Engine {
	t.Helper()
	module := parseFixture(t, manifest)
	module.Source.URL = sourceURL
	e := newTestEngine(t, twoExtensionDocument)
	if _, _, err := e.SetEnabled(e.Revision(), "first", false); err != nil {
		t.Fatalf("disable overlapping fixture: %v", err)
	}
	if _, _, err := e.install(e.Revision(), module); err != nil {
		t.Fatalf("install update fixture: %v", err)
	}
	if _, _, err := e.SetCaptureDNS(e.Revision(), module.ID, "china"); err != nil {
		t.Fatalf("bind capture DNS: %v", err)
	}
	if bindEgress {
		if _, _, err := e.SetEgressGroup(e.Revision(), module.ID, "Proxies"); err != nil {
			t.Fatalf("bind egress: %v", err)
		}
	}
	if _, _, err := e.SetSettingValues(e.Revision(), module.ID, SettingValues{
		"region": json.RawMessage(`"hk"`),
	}); err != nil {
		t.Fatalf("set fixture values: %v", err)
	}
	if _, _, err := e.SetEnabled(e.Revision(), module.ID, true); err != nil {
		t.Fatalf("enable update fixture: %v", err)
	}
	return e
}

func TestEnabledUpdateCarriesOperatorStateAndKeepsOldSnapshotImmutable(t *testing.T) {
	const sourceURL = "https://updates.example.com/example.yaml"
	e := installEnabledUpdateFixture(t, sourceURL, validManifest, true)
	replacement := strings.Replace(validManifest, "version: 1.2.0", "version: 1.3.0", 1)
	stubImporter(t, stubFetch{sourceURL: replacement})

	candidate, err := e.CheckUpdate(context.Background(), "example.plugin")
	if err != nil {
		t.Fatalf("CheckUpdate: %v", err)
	}
	if !candidate.Detail.Enabled || candidate.Detail.CaptureDNS != "china" || candidate.Detail.EgressGroup != "Proxies" {
		t.Fatalf("candidate did not project retained operator state: %+v", candidate.Detail.ModuleSummary)
	}
	if len(candidate.Detail.Settings) != 1 || string(candidate.Detail.Settings[0].Value) != `"hk"` {
		t.Fatalf("candidate proposed settings = %+v, want carried hk", candidate.Detail.Settings)
	}

	before, err := e.config.Current()
	if err != nil {
		t.Fatal(err)
	}
	beforeOrder := append([]string(nil), before.ExecutionOrder...)
	beforeRuntime := before.runtime
	_, _, err = e.ApplyUpdate(context.Background(), e.Revision(), "example.plugin", candidate.Digest)
	if err != nil {
		t.Fatalf("ApplyUpdate while enabled: %v", err)
	}
	after, err := e.config.Current()
	if err != nil {
		t.Fatal(err)
	}
	if beforeRuntime == after.runtime {
		t.Fatal("update reused the old compiled runtime pointer")
	}
	if strings.Join(after.ExecutionOrder, "\x00") != strings.Join(beforeOrder, "\x00") {
		t.Fatalf("execution order changed from %v to %v", beforeOrder, after.ExecutionOrder)
	}

	var oldModule, newModule Module
	for _, module := range before.Modules {
		if module.ID == "example.plugin" {
			oldModule = module
		}
	}
	for _, module := range after.Modules {
		if module.ID == "example.plugin" {
			newModule = module
		}
	}
	if oldModule.Version != "1.2.0" || !oldModule.Enabled || string(oldModule.Settings[0].Value) != `"hk"` {
		t.Fatalf("retained pre-update snapshot was mutated: %+v", oldModule)
	}
	if newModule.Version != "1.3.0" || !newModule.Enabled || newModule.CaptureDNS != "china" || newModule.EgressGroup != "Proxies" || string(newModule.Settings[0].Value) != `"hk"` {
		t.Fatalf("new module did not atomically retain operator state: %+v", newModule)
	}
}

func TestEnabledUpdateRequiresNewSettingInTheApplyTransaction(t *testing.T) {
	const sourceURL = "https://updates.example.com/example.yaml"
	e := installEnabledUpdateFixture(t, sourceURL, validManifest, true)
	replacement := strings.Replace(validManifest, "version: 1.2.0", "version: 1.3.0", 1)
	replacement = strings.Replace(replacement, "    default: cn\n", "    default: cn\n  - key: token\n    type: text\n    required: true\n", 1)
	stubImporter(t, stubFetch{sourceURL: replacement})

	candidate, err := e.CheckUpdate(context.Background(), "example.plugin")
	if err != nil {
		t.Fatalf("CheckUpdate: %v", err)
	}
	if len(candidate.Detail.Settings) != 2 || string(candidate.Detail.Settings[0].Value) != `"hk"` || len(candidate.Detail.Settings[1].Value) != 0 {
		t.Fatalf("candidate settings do not show carried and missing values: %+v", candidate.Detail.Settings)
	}
	revision := e.Revision()
	before, err := os.ReadFile(e.config.path)
	if err != nil {
		t.Fatal(err)
	}
	_, returned, err := e.ApplyUpdate(context.Background(), revision, "example.plugin", candidate.Digest)
	if !errors.Is(err, ErrInvalidRequest) || !errors.Is(err, ErrUnprocessable) {
		t.Fatalf("apply without new required value returned %v", err)
	}
	if returned != revision {
		t.Fatalf("rejected apply returned revision %q, want %q", returned, revision)
	}
	assertConfigUnchanged(t, e, revision, before)

	_, _, err = e.ApplyUpdateWithSettings(context.Background(), revision, "example.plugin", candidate.Digest, SettingValues{
		"region": json.RawMessage(`"hk"`),
		"token":  json.RawMessage(`"operator-value"`),
	})
	if err != nil {
		t.Fatalf("apply with complete candidate values: %v", err)
	}
	detail, err := e.Detail("example.plugin")
	if err != nil {
		t.Fatal(err)
	}
	if !detail.Enabled || detail.Version != "1.3.0" || len(detail.Settings) != 2 || string(detail.Settings[1].Value) != `"operator-value"` {
		t.Fatalf("updated detail = %+v", detail)
	}
}

func TestEnabledUpdateRejectsANewUnboundEgressRequirement(t *testing.T) {
	const sourceURL = "https://updates.example.com/example.yaml"
	withoutEgress := strings.Replace(validManifest, "requirements:\n  egressGroup:\n    required: true\n", "", 1)
	e := installEnabledUpdateFixture(t, sourceURL, withoutEgress, false)
	replacement := strings.Replace(validManifest, "version: 1.2.0", "version: 1.3.0", 1)
	stubImporter(t, stubFetch{sourceURL: replacement})
	candidate, err := e.CheckUpdate(context.Background(), "example.plugin")
	if err != nil {
		t.Fatal(err)
	}
	revision := e.Revision()
	_, returned, err := e.ApplyUpdate(context.Background(), revision, "example.plugin", candidate.Digest)
	if !errors.Is(err, ErrInvalidRequest) || !errors.Is(err, ErrUnprocessable) {
		t.Fatalf("unbound egress update returned %v", err)
	}
	if returned != revision || e.Revision() != revision {
		t.Fatalf("rejected egress update moved revision returned=%q current=%q want=%q", returned, e.Revision(), revision)
	}
}

type barrierFetch struct {
	body    string
	started chan struct{}
	release chan struct{}
}

func (b *barrierFetch) RoundTrip(request *http.Request) (*http.Response, error) {
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
	return &http.Response{
		StatusCode: http.StatusOK,
		Body:       io.NopCloser(strings.NewReader(b.body)),
		Header:     make(http.Header),
		Request:    request,
	}, nil
}

func TestUpdateFetchBarrierPublishesOnlyTheCompleteReplacement(t *testing.T) {
	const sourceURL = "https://updates.example.com/example.yaml"
	e := installEnabledUpdateFixture(t, sourceURL, validManifest, true)
	replacement := strings.Replace(validManifest, "version: 1.2.0", "version: 1.3.0", 1)
	parsed := parseFixture(t, replacement)
	digest := SnapshotDigest(parsed)
	barrier := &barrierFetch{body: replacement, started: make(chan struct{}), release: make(chan struct{})}
	setTestImporter(t, &Importer{client: &http.Client{Transport: barrier}, now: time.Now})

	before, err := e.config.Current()
	if err != nil {
		t.Fatal(err)
	}
	revision := e.Revision()
	done := make(chan error, 1)
	go func() {
		_, _, updateErr := e.ApplyUpdate(context.Background(), revision, "example.plugin", digest)
		done <- updateErr
	}()
	select {
	case <-barrier.started:
	case <-time.After(5 * time.Second):
		t.Fatal("update fetch did not reach the barrier")
	}

	during, err := e.config.Current()
	if err != nil {
		t.Fatal(err)
	}
	if e.Revision() != revision || during.runtime != before.runtime {
		t.Fatal("fetching candidate changed the live config before validation completed")
	}
	close(barrier.release)
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("ApplyUpdate: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("update did not complete after releasing the fetch")
	}

	after, err := e.config.Current()
	if err != nil {
		t.Fatal(err)
	}
	if after.runtime == before.runtime || e.Revision() == revision {
		t.Fatal("complete replacement was not published after validation")
	}
	for _, module := range before.Modules {
		if module.ID == "example.plugin" && module.Version != "1.2.0" {
			t.Fatalf("old snapshot changed to version %q", module.Version)
		}
	}
	for _, module := range after.Modules {
		if module.ID == "example.plugin" && module.Version != "1.3.0" {
			t.Fatalf("new snapshot has version %q", module.Version)
		}
	}
}

func TestCheckUpdateReturnsTheRevisionThatSuppliedProposedValues(t *testing.T) {
	const sourceURL = "https://updates.example.com/second.yaml"
	replacement := strings.Replace(validManifest, "id: example.plugin", "id: second", 1)
	cfg, err := decodeConfig([]byte(twoExtensionDocument))
	if err != nil {
		t.Fatal(err)
	}
	for i := range cfg.Modules {
		if cfg.Modules[i].ID == "second" {
			cfg.Modules[i].Source.URL = sourceURL
		}
	}
	raw, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	e := newTestEngine(t, string(raw))
	barrier := &barrierFetch{body: replacement, started: make(chan struct{}), release: make(chan struct{})}
	setTestImporter(t, &Importer{client: &http.Client{Transport: barrier}, now: time.Now})

	type result struct {
		candidate Candidate
		revision  string
		err       error
	}
	done := make(chan result, 1)
	go func() {
		candidate, revision, checkErr := e.CheckUpdateView(context.Background(), "second")
		done <- result{candidate: candidate, revision: revision, err: checkErr}
	}()
	select {
	case <-barrier.started:
	case <-time.After(5 * time.Second):
		t.Fatal("update check did not reach fetch barrier")
	}
	_, changedRevision, err := e.SetSettingValues(e.Revision(), "second", SettingValues{
		"region": json.RawMessage(`"hk"`),
	})
	if err != nil {
		t.Fatal(err)
	}
	close(barrier.release)
	select {
	case got := <-done:
		if got.err != nil {
			t.Fatalf("CheckUpdateView: %v", got.err)
		}
		if got.revision != changedRevision {
			t.Fatalf("candidate revision %q, want settings revision %q", got.revision, changedRevision)
		}
		if len(got.candidate.Detail.Settings) != 1 || string(got.candidate.Detail.Settings[0].Value) != `"hk"` {
			t.Fatalf("candidate did not use values from returned revision: %+v", got.candidate.Detail.Settings)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("update check did not complete")
	}
}
