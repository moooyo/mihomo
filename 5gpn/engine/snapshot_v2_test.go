package engine

import (
	"bytes"
	"encoding/json"
	"testing"
)

func TestSnapshotV2ReportsDesiredAndRuntimeState(t *testing.T) {
	e := newTestEngine(t, twoExtensionDocument)
	snapshot, err := e.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	if len(snapshot.Modules) != 2 {
		t.Fatalf("module count = %d, want 2", len(snapshot.Modules))
	}

	first := snapshot.Modules[0]
	if !first.Enabled {
		t.Fatal("enabled no longer reports the persisted desired authorization")
	}
	if first.Runtime.Phase == "" {
		t.Fatal("enabled module has no derived runtime phase")
	}
	if first.SettingCount != 0 {
		t.Fatalf("first setting_count = %d, want 0", first.SettingCount)
	}

	second := snapshot.Modules[1]
	if second.Enabled {
		t.Fatal("disabled module reports desired enabled")
	}
	if second.Runtime.Ready || second.Runtime.Phase != "disabled" {
		t.Fatalf("disabled module runtime = %+v", second.Runtime)
	}
	if second.SettingCount != 1 {
		t.Fatalf("second setting_count = %d, want 1", second.SettingCount)
	}

	if snapshot.Certificate.Status == "" || snapshot.Certificate.TargetDigest == "" {
		t.Fatalf("certificate runtime identity is incomplete: %+v", snapshot.Certificate)
	}
	raw, err := json.Marshal(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	for _, field := range [][]byte{
		[]byte(`"setting_count":1`),
		[]byte(`"runtime":{"ready":false,"phase":"disabled"}`),
		[]byte(`"certificate":{"ready":true,"status":"ready"`),
		[]byte(`"target_digest":`),
	} {
		if !bytes.Contains(raw, field) {
			t.Errorf("snapshot JSON does not contain %s: %s", field, raw)
		}
	}
}

func TestSnapshotFromConfigDoesNotDriftToALaterCommit(t *testing.T) {
	e := newTestEngine(t, twoExtensionDocument)
	before, err := e.CommittedView()
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := e.config.Update(before.Revision, func(current Config) (Config, error) {
		current.MITM.HTTP2 = false
		return current, nil
	}); err != nil {
		t.Fatal(err)
	}

	oldSnapshot, err := e.SnapshotFromConfig(before.Config)
	if err != nil {
		t.Fatal(err)
	}
	currentSnapshot, err := e.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	if !oldSnapshot.HTTP2 {
		t.Fatal("SnapshotFromConfig read HTTP2 from the later committed config")
	}
	if currentSnapshot.HTTP2 {
		t.Fatal("current Snapshot did not observe the later committed config")
	}
}
