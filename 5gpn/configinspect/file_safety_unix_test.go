//go:build !windows

package configinspect

import (
	"os"
	"path/filepath"
	"testing"
)

func TestReadConfigFileRejectsLinks(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target.yaml")
	if err := os.WriteFile(target, []byte(validConfig), 0o600); err != nil {
		t.Fatal(err)
	}

	symlink := filepath.Join(dir, "symlink.yaml")
	if err := os.Symlink(target, symlink); err != nil {
		t.Fatal(err)
	}
	if _, err := readConfigFile(symlink); err == nil {
		t.Fatal("config symlink was accepted")
	}

	hardlink := filepath.Join(dir, "hardlink.yaml")
	if err := os.Link(target, hardlink); err != nil {
		t.Fatal(err)
	}
	if _, err := readConfigFile(target); err == nil {
		t.Fatal("multiply linked config was accepted")
	}
}

func TestReadConfigFileRejectsUnsafeOwnershipAndModes(t *testing.T) {
	if os.Geteuid() == 0 {
		path := filepath.Join(t.TempDir(), "secure.yaml")
		if err := os.WriteFile(path, []byte(validConfig), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := readConfigFile(path); err != nil {
			t.Fatalf("secure root-owned config was rejected: %v", err)
		}
	}

	tests := []struct {
		name string
		mode os.FileMode
	}{
		{name: "group writable", mode: 0o660},
		{name: "other writable", mode: 0o642},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "config.yaml")
			if err := os.WriteFile(path, []byte(validConfig), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(path, test.mode); err != nil {
				t.Fatal(err)
			}
			if _, err := readConfigFile(path); err == nil {
				t.Fatalf("mode %04o was accepted", test.mode)
			}
		})
	}

	if os.Geteuid() != 0 {
		t.Skip("changing a file to a non-root owner requires root")
	}
	path := filepath.Join(t.TempDir(), "non-root-owned.yaml")
	if err := os.WriteFile(path, []byte(validConfig), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(path, 65534, -1); err != nil {
		t.Fatal(err)
	}
	if _, err := readConfigFile(path); err == nil {
		t.Fatal("non-root-owned config was accepted")
	}
}
