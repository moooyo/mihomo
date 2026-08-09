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
