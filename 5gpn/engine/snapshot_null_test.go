package engine

import (
	"encoding/json"
	"strings"
	"testing"
)

// The document a gateway has before anything is installed: no extensions, no
// execution order, master off. This is the shape the console met in the wild.
const emptyInterceptDocument = `{
  "version": 7,
  "execution_order": [],
  "tls_cert": "/etc/5gpn/intercept/tls/fullchain.pem",
  "tls_key": "/etc/5gpn/intercept/tls/privkey.pem",
  "mitm": {"enabled": false, "http2": true, "http3": false},
  "modules": []
}`

// A list field must never reach the console as JSON null.
//
// Go marshals a nil slice as null, and the console reads .length off these
// fields directly. On a gateway with no extensions installed, or with the MITM
// master off, the snapshot carried "execution_order": null and
// "active_capture_hosts": null -- and the extensions page rendered into
// "Cannot read properties of null (reading 'length')" and a blank screen.
//
// The type says []string. Serving null is the type lying, and the failure lands
// three layers away in a browser where no Go test was looking. This one asserts
// on the bytes, because the bytes are the contract.
func TestSnapshotListsAreNeverNull(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name     string
		document string
		masterOn bool
	}{
		{"nothing installed, master off", emptyInterceptDocument, false},
		{"nothing installed, master on", emptyInterceptDocument, true},
		{"extensions installed, master off", twoExtensionDocument, false},
		{"extensions installed, master on", twoExtensionDocument, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := newTestEngine(t, tc.document)
			if _, _, err := e.SetSettings(e.Revision(), MITMSettings{
				Enabled: tc.masterOn,
				HTTP2:   true,
			}); err != nil {
				t.Fatalf("set settings: %v", err)
			}

			snap, err := e.Snapshot()
			if err != nil {
				t.Fatalf("snapshot: %v", err)
			}
			data, err := json.Marshal(snap)
			if err != nil {
				t.Fatalf("marshal: %v", err)
			}
			body := string(data)

			for _, field := range []string{"modules", "execution_order", "available_egress_groups", "active_capture_hosts"} {
				if strings.Contains(body, `"`+field+`":null`) {
					t.Errorf("%s is null; the console reads .length off it\n%s", field, body)
				}
			}
			if snap.Modules == nil {
				t.Error("Modules is a nil slice")
			}
			if snap.ExecutionOrder == nil {
				t.Error("ExecutionOrder is a nil slice")
			}
			if snap.ActiveCaptureHosts == nil {
				t.Error("ActiveCaptureHosts is a nil slice")
			}
			if snap.AvailableEgressGroups == nil {
				t.Error("AvailableEgressGroups is a nil slice")
			}
			for _, m := range snap.Modules {
				if m.CaptureHosts == nil {
					t.Errorf("module %s has nil capture_hosts", m.ID)
				}
			}
		})
	}
}
