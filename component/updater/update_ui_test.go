package updater

import (
	"errors"
	"os"
	"testing"
)

func TestManagedDistributionDisablesEveryUIDownloadPath(t *testing.T) {
	previous := ManagedDistribution()
	SetManagedDistribution(true)
	t.Cleanup(func() { SetManagedDistribution(previous) })

	dir := t.TempDir()
	ui := NewUiUpdater(dir, "http://127.0.0.1:1/untrusted.zip", "")
	ui.AutoDownloadUI()

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("managed auto-download published %d entries", len(entries))
	}
	if err := ui.DownloadUI(); !errors.Is(err, ErrManagedDistribution) {
		t.Fatalf("managed explicit download error %v, want %v", err, ErrManagedDistribution)
	}
	if err := DefaultCoreUpdater.Update("not-a-real-executable", "release", false); !errors.Is(err, ErrManagedDistribution) {
		t.Fatalf("managed core update error %v, want %v", err, ErrManagedDistribution)
	}
}
