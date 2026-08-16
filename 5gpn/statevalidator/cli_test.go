package statevalidator

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRunValidatesAbsoluteStateDirectory(t *testing.T) {
	dir := t.TempDir()
	var output bytes.Buffer
	if code := Run([]string{"validate", dir}, &output); code != 0 {
		t.Fatalf("Run() code = %d, output = %s", code, output.String())
	}
	var response cliSuccess
	decodeSingleJSON(t, output.Bytes(), &response)
	if response.Status != "ok" || len(response.Validated) != 0 || len(response.Missing) != 3 {
		t.Fatalf("unexpected response: %+v", response)
	}
}

func TestRunRejectsInvalidArguments(t *testing.T) {
	for _, args := range [][]string{
		nil,
		{"validate"},
		{"validate", "relative"},
		{"validate", "--owner-uid=-1", t.TempDir()},
		{"unknown", t.TempDir()},
	} {
		var output bytes.Buffer
		if code := Run(args, &output); code == 0 {
			t.Fatalf("Run(%v) succeeded: %s", args, output.String())
		}
		var response cliError
		decodeSingleJSON(t, output.Bytes(), &response)
		if response.Status != "error" || response.Code == "" || response.Error == "" {
			t.Fatalf("unexpected error response: %+v", response)
		}
	}
}

func TestMainDispatchesStateValidatorBeforeOrdinarySetup(t *testing.T) {
	mainPath := filepath.Join("..", "..", "main.go")
	raw, err := os.ReadFile(mainPath)
	if err != nil {
		t.Fatal(err)
	}
	source := string(raw)
	dispatch := strings.Index(source, `os.Args[1] == "5gpn-state"`)
	call := strings.Index(source, `fivegpn.StateMain(os.Args[2:])`)
	resolver := strings.Index(source, "net.DefaultResolver.PreferGo")
	if dispatch < 0 || call < 0 || resolver < 0 || dispatch > resolver || call > resolver {
		t.Fatal("5gpn-state dispatch does not precede ordinary resolver setup")
	}
}

func decodeSingleJSON(t *testing.T, raw []byte, destination any) {
	t.Helper()
	decoder := json.NewDecoder(bytes.NewReader(raw))
	if err := decoder.Decode(destination); err != nil {
		t.Fatalf("decode JSON %q: %v", raw, err)
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		t.Fatalf("CLI wrote more than one JSON value: %q", raw)
	}
}
