package nodes

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestImportPreservesModeAndLeavesNoStagedFiles(t *testing.T) {
	store, path, original := newTestStore(t, testConfig)
	before, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	content := []byte("name: Mode Node\ntype: http\nserver: mode.example\nport: 8080\n")
	if _, err := store.Import(revisionOf(original), content); err != nil {
		t.Fatal(err)
	}
	for _, candidate := range []string{path, path + ".5gpn-nodes.bak"} {
		info, err := os.Stat(candidate)
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != before.Mode().Perm() {
			t.Fatalf("mode of %s = %v, want %v", candidate, info.Mode().Perm(), before.Mode().Perm())
		}
	}
	temps, err := filepath.Glob(filepath.Join(filepath.Dir(path), ".*.tmp"))
	if err != nil {
		t.Fatal(err)
	}
	if len(temps) != 0 {
		t.Fatalf("staged files remain after commit: %v", temps)
	}
}

func TestConfigHardlinkIsRejected(t *testing.T) {
	store, path, _ := newTestStore(t, testConfig)
	alias := filepath.Join(filepath.Dir(path), "alias.yaml")
	if err := os.Link(path, alias); err != nil {
		t.Skipf("hardlinks unavailable: %v", err)
	}
	if _, err := store.List(); err == nil {
		t.Fatal("hardlinked config was accepted")
	}
}

func TestBackupAndLockSymlinksAreRejected(t *testing.T) {
	tests := []struct {
		name   string
		suffix string
	}{
		{name: "backup", suffix: ".5gpn-nodes.bak"},
		{name: "lock", suffix: ".5gpn-nodes.lock"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			store, path, original := newTestStore(t, testConfig)
			target := filepath.Join(filepath.Dir(path), "target")
			if err := os.WriteFile(target, []byte("do not overwrite"), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(target, path+test.suffix); err != nil {
				t.Skipf("symlinks unavailable: %v", err)
			}
			content := []byte("name: Symlink Node\ntype: http\nserver: symlink.example\nport: 8080\n")
			if _, err := store.Import(revisionOf(original), content); err == nil {
				t.Fatal("unsafe transaction path was accepted")
			}
			written, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(written, original) {
				t.Fatal("config changed after rejecting an unsafe path")
			}
			targetBytes, err := os.ReadFile(target)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(targetBytes, []byte("do not overwrite")) {
				t.Fatal("symlink target was modified")
			}
		})
	}
}

func TestAliasedMutationTargetsAreRejected(t *testing.T) {
	tests := []struct {
		name   string
		config string
	}{
		{
			name: "aliased proxies",
			config: `mode: rule
node-list: &node-list
  - {name: Existing, type: http, server: 127.0.0.1, port: 8080}
proxies: *node-list
proxy-groups:
  - {name: Proxies, type: select, proxies: [DIRECT, Existing]}
rules: ["MATCH,Proxies"]
`,
		},
		{
			name: "aliased Proxies members",
			config: `mode: rule
members: &members [DIRECT, Existing]
proxies:
  - {name: Existing, type: http, server: 127.0.0.1, port: 8080}
proxy-groups:
  - name: Proxies
    type: select
    proxies: *members
rules: ["MATCH,Proxies"]
`,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			store, path, original := newTestStore(t, test.config)
			content := []byte("name: Alias Node\ntype: http\nserver: alias.example\nport: 8080\n")
			_, err := store.PreviewImport(revisionOf(original), content)
			if err == nil {
				t.Fatal("aliased mutation target was accepted")
			}
			written, readErr := os.ReadFile(path)
			if readErr != nil {
				t.Fatal(readErr)
			}
			if !bytes.Equal(written, original) {
				t.Fatal("dry-run changed an aliased config")
			}
			if _, statErr := os.Lstat(path + ".5gpn-nodes.lock"); !errors.Is(statErr, os.ErrNotExist) {
				t.Fatalf("dry-run created a lock: %v", statErr)
			}
		})
	}
}
