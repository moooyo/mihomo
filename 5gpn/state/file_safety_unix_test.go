//go:build !windows

package state

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

func TestPrivateFileOwnerMustMatchServiceIdentity(t *testing.T) {
	uid := os.Geteuid()
	if !privateFileOwnerMatches(&syscall.Stat_t{Uid: uint32(uid)}, uid) {
		t.Fatal("the current service owner was rejected")
	}
	if privateFileOwnerMatches(&syscall.Stat_t{Uid: uint32(uid + 1)}, uid) {
		t.Fatal("a different file owner was accepted")
	}
}

func TestNewRequiresPrivateDocumentMode(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bot.json")
	if err := os.WriteFile(path, []byte(`{"hosts":[],"count":0}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o640); err != nil {
		t.Fatal(err)
	}
	if _, err := New(path, doc{}); err == nil {
		t.Fatal("New accepted a state document that was not mode 0600")
	}
}

func TestWritePublicFilePublishesFinalModeBeforeDirectorySync(t *testing.T) {
	path := filepath.Join(t.TempDir(), "certificate-request")
	checked := false
	err := writeFileMode(path, []byte(`{"version":1}`), 0o644, func(string) error {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatalf("stat published request: %v", err)
		}
		if got := info.Mode().Perm(); got != 0o644 {
			t.Fatalf("mode at directory sync = %04o, want 0644", got)
		}
		checked = true
		return nil
	})
	if err != nil {
		t.Fatalf("write public file: %v", err)
	}
	if !checked {
		t.Fatal("directory sync seam was not reached")
	}
}
