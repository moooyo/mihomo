package configinspect

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCLIWritesOneVersionedJSONValue(t *testing.T) {
	var output bytes.Buffer
	code := run(
		[]string{"inspect-controller", "--config", filepath.Join(t.TempDir(), "config.yaml")},
		&output,
		func() error { return nil },
		func(string) ([]byte, error) { return []byte(validConfig), nil },
	)
	if code != 0 {
		t.Fatalf("inspection failed: %s", output.String())
	}
	var view View
	decodeSingleJSON(t, output.Bytes(), &view)
	want, err := Inspect([]byte(validConfig))
	if err != nil {
		t.Fatal(err)
	}
	if view != want {
		t.Fatalf("CLI output = %+v, want %+v", view, want)
	}
	var fields map[string]json.RawMessage
	decodeSingleJSON(t, output.Bytes(), &fields)
	wantFields := []string{"certificate", "external_controller_tls", "external_ui", "private_key", "raw_revision", "secret", "version"}
	if len(fields) != len(wantFields) {
		t.Fatalf("CLI field count = %d, want %d: %v", len(fields), len(wantFields), fields)
	}
	for _, field := range wantFields {
		if _, ok := fields[field]; !ok {
			t.Fatalf("CLI output is missing %q: %v", field, fields)
		}
	}
}

func TestCLIFailsClosedBeforeReadingWhenNotRoot(t *testing.T) {
	readCalled := false
	var output bytes.Buffer
	code := run(
		[]string{"inspect-controller", "--config", filepath.Join(t.TempDir(), "config.yaml")},
		&output,
		func() error { return errors.New("not root") },
		func(string) ([]byte, error) { readCalled = true; return nil, nil },
	)
	if code == 0 || readCalled {
		t.Fatalf("non-root inspection code=%d readCalled=%v", code, readCalled)
	}
	var response errorOutput
	decodeSingleJSON(t, output.Bytes(), &response)
	if response.Code != "permission_denied" {
		t.Fatalf("unexpected error: %+v", response)
	}
}

func TestCLIErrorDoesNotEchoInvalidConfigOrSecret(t *testing.T) {
	secret := "super-secret-value"
	invalid := strings.Replace(validConfig, `controller"secret`, secret, 1)
	invalid = strings.Replace(invalid, "127.0.0.1:443", "attacker.example:443", 1)
	var output bytes.Buffer
	code := run(
		[]string{"inspect-controller", "--config", filepath.Join(t.TempDir(), "config.yaml")},
		&output,
		func() error { return nil },
		func(string) ([]byte, error) { return []byte(invalid), nil },
	)
	if code == 0 {
		t.Fatal("invalid config inspection succeeded")
	}
	if strings.Contains(output.String(), secret) || strings.Contains(output.String(), "attacker.example") {
		t.Fatalf("CLI error leaked config contents: %s", output.String())
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
		`os.Args[1] == "5gpn-config"`,
		`fivegpn.ConfigInspectMain(os.Args[2:])`,
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
