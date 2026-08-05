package engine

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"
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
