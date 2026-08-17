//go:build !windows

package state

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

func TestPrivateFileOwnerPolicy(t *testing.T) {
	const ownerUID = 1234
	owner := &syscall.Stat_t{Uid: ownerUID}
	if !privateFileOwnerMatches(owner, ownerUID, nil) {
		t.Fatal("the current service owner was rejected")
	}
	if privateFileOwnerMatches(owner, ownerUID+1, nil) {
		t.Fatal("a different file owner was accepted")
	}
	if privateFileOwnerMatches(owner, 0, nil) {
		t.Fatal("root bypassed the default service-identity contract")
	}
	expected := ownerUID
	if !privateFileOwnerMatches(owner, 0, &expected) {
		t.Fatal("root could not read the explicitly named service owner")
	}
	if !privateFileOwnerMatches(owner, ownerUID, &expected) {
		t.Fatal("the explicitly named owner could not read its own file")
	}
	if privateFileOwnerMatches(owner, ownerUID+1, &expected) {
		t.Fatal("a non-root reader selected a different expected owner")
	}
	wrong := ownerUID + 1
	if privateFileOwnerMatches(owner, 0, &wrong) {
		t.Fatal("root accepted a file owned by a UID other than the expected owner")
	}
}

func TestValidatePrivateFileOwnerAccess(t *testing.T) {
	uid := os.Geteuid()
	if err := ValidatePrivateFileOwnerAccess(uid); err != nil {
		t.Fatalf("current owner UID was rejected: %v", err)
	}
	err := ValidatePrivateFileOwnerAccess(uid + 1)
	if uid == 0 && err != nil {
		t.Fatalf("root could not select an explicit service owner: %v", err)
	}
	if uid != 0 && err == nil {
		t.Fatal("non-root selected a different expected owner")
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
