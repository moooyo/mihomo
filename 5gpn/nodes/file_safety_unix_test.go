//go:build !windows

package nodes

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

func TestLockOwnerMatchRejectsAnotherUser(t *testing.T) {
	uid := os.Geteuid()
	gid := os.Getegid()
	if lockOwnerMatches(&syscall.Stat_t{Uid: uint32(uid + 1), Gid: uint32(gid)}, uid, gid) {
		t.Fatal("lock owned by another user was accepted")
	}
	if !lockOwnerMatches(&syscall.Stat_t{Uid: uint32(uid), Gid: uint32(gid)}, uid, gid) {
		t.Fatal("lock owned by the caller was rejected")
	}
}

func TestWritableNonStickyConfigDirectoryIsRejected(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "unsafe")
	if err := os.Mkdir(dir, 0o770); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o770); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte(testConfig), 0o640); err != nil {
		t.Fatal(err)
	}
	if _, err := New(path); err == nil {
		t.Fatal("group-writable non-sticky config directory was accepted")
	}
}
