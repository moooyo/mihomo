package nodes

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCLIListAndDryRunReturnOneJSONValue(t *testing.T) {
	store, path, original := newTestStore(t, testConfig)
	_ = store

	var listOutput bytes.Buffer
	if code := Run([]string{"list", "--config", path}, strings.NewReader(""), &listOutput); code != 0 {
		t.Fatalf("list failed: %s", listOutput.String())
	}
	var view View
	decodeSingleJSON(t, listOutput.Bytes(), &view)
	if view.Revision != revisionOf(original) || len(view.Nodes) != 1 {
		t.Fatalf("unexpected list output: %+v", view)
	}

	var previewOutput bytes.Buffer
	content := "name: Dry Run\ntype: http\nserver: dry.example\nport: 8080\n"
	if code := Run([]string{"import", "--dry-run", "--config", path, "--revision", view.Revision}, strings.NewReader(content), &previewOutput); code != 0 {
		t.Fatalf("dry-run failed: %s", previewOutput.String())
	}
	var preview ImportPreview
	decodeSingleJSON(t, previewOutput.Bytes(), &preview)
	if preview.Revision != view.Revision || preview.CandidateRevision == "" || len(preview.Added) != 1 {
		t.Fatalf("unexpected preview output: %+v", preview)
	}
	assertConfigUnchangedAndNoBackup(t, path, original)
}

func TestCLIErrorIsJSONAndDoesNotEchoCredentials(t *testing.T) {
	_, path, original := newTestStore(t, testConfig)
	secret := "super-secret-uuid"
	content := "vless://" + secret + "@#Bad\n"
	var output bytes.Buffer
	code := Run([]string{"import", "--config", path, "--revision", revisionOf(original)}, strings.NewReader(content), &output)
	if code == 0 {
		t.Fatalf("invalid import succeeded: %s", output.String())
	}
	var response errorOutput
	decodeSingleJSON(t, output.Bytes(), &response)
	if response.Code != "invalid_input" {
		t.Fatalf("unexpected error response: %+v", response)
	}
	if strings.Contains(output.String(), secret) {
		t.Fatalf("credential was echoed in CLI output: %s", output.String())
	}
}

func TestCLIMainDispatchContract(t *testing.T) {
	mainPath := filepath.Join("..", "..", "main.go")
	raw, err := os.ReadFile(mainPath)
	if err != nil {
		t.Fatal(err)
	}
	source := string(raw)
	for _, required := range []string{
		`os.Args[1] == "5gpn-nodes"`,
		`fivegpn.NodesMain(os.Args[2:])`,
	} {
		if !strings.Contains(source, required) {
			t.Fatalf("main dispatch is missing %q", required)
		}
	}
}

func decodeSingleJSON(t *testing.T, raw []byte, output any) {
	t.Helper()
	decoder := json.NewDecoder(bytes.NewReader(raw))
	if err := decoder.Decode(output); err != nil {
		t.Fatalf("decode JSON %q: %v", raw, err)
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		t.Fatalf("CLI wrote more than one JSON value: %q", raw)
	}
}
