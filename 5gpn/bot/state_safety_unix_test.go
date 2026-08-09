//go:build !windows

package bot

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestOpenRefusesWorldReadableTokenState(t *testing.T) {
	document := DefaultDocument()
	document.Token = "secret-token"
	raw, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "bot.json")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(path, Facts{}, nil); err == nil {
		t.Fatal("Open accepted a world-readable bot token document")
	}
}
