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

func TestReadConfigFileForOwnerRequiresTheExpectedIdentity(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte(validConfig), 0o600); err != nil {
		t.Fatal(err)
	}
	ownerUID := os.Geteuid()
	if _, err := readConfigFileForOwner(path, ownerUID); err != nil {
		t.Fatalf("matching owner was rejected: %v", err)
	}
	if _, err := readConfigFileForOwner(path, ownerUID+1); err == nil {
		t.Fatal("mismatched expected owner was accepted")
	}
}

func TestConfigInspectionIdentityModesAreDisjoint(t *testing.T) {
	tests := []struct {
		name          string
		currentUID    int
		expectedOwner int
		containerMode bool
		wantError     bool
	}{
		{name: "host root", currentUID: 0, expectedOwner: 0},
		{name: "host non-root", currentUID: containerConfigOwnerUID, expectedOwner: 0, wantError: true},
		{name: "container owner", currentUID: containerConfigOwnerUID, expectedOwner: containerConfigOwnerUID, containerMode: true},
		{name: "container root", currentUID: 0, expectedOwner: containerConfigOwnerUID, containerMode: true, wantError: true},
		{name: "container arbitrary owner", currentUID: 20000, expectedOwner: 20000, containerMode: true, wantError: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := validateConfigInspectionIdentity(test.currentUID, test.expectedOwner, test.containerMode)
			if (err != nil) != test.wantError {
				t.Fatalf("identity validation error = %v, wantError=%v", err, test.wantError)
			}
		})
	}
}
