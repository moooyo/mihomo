package nodes

import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const testConfig = `# top-level comment
mode: rule
log-level: silent
proxies:
  # existing node comment
  - name: Existing
    type: http
    server: 127.0.0.1
    port: 8080
proxy-groups:
  - name: Proxies
    type: select
    proxies:
      - DIRECT
      - Existing
rules:
  - MATCH,Proxies
`

func newTestStore(t *testing.T, config string) (*Store, string, []byte) {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	raw := []byte(config)
	if err := os.WriteFile(path, raw, 0o640); err != nil {
		t.Fatal(err)
	}
	store, err := New(path)
	if err != nil {
		t.Fatal(err)
	}
	return store, path, raw
}

func TestListProjectsStaticNodesAndFullRevision(t *testing.T) {
	store, _, raw := newTestStore(t, testConfig)
	view, err := store.List()
	if err != nil {
		t.Fatal(err)
	}
	if view.Revision != revisionOf(raw) || len(view.Revision) != 64 {
		t.Fatalf("unexpected revision %q", view.Revision)
	}
	if view.Group != "Proxies" || len(view.Nodes) != 1 {
		t.Fatalf("unexpected view: %+v", view)
	}
	node := view.Nodes[0]
	if node.Name != "Existing" || node.Type != "http" || node.Server != "127.0.0.1" || node.Port != 8080 || !node.InProxies {
		t.Fatalf("unexpected node: %+v", node)
	}
}

func TestImportAcceptsSupportedYAMLShapes(t *testing.T) {
	tests := []struct {
		name    string
		content string
		added   []string
	}{
		{
			name: "top-level proxies only",
			content: `proxies:
  - name: Clash Node
    type: http
    server: clash.example
    port: 8081
proxy-groups:
  - name: Must Not Be Adopted
    type: select
    proxies: [DIRECT]
rules:
  - MATCH,REJECT
listeners:
  - name: must-not-be-adopted
`,
			added: []string{"Clash Node"},
		},
		{
			name: "single proxy mapping",
			content: `name: Single Node
type: socks5
server: single.example
port: 1080
`,
			added: []string{"Single Node"},
		},
		{
			name: "proxy mapping array",
			content: `
- name: Array One
  type: http
  server: one.example
  port: 8001
- name: Array Two
  type: socks5
  server: two.example
  port: 1080
`,
			added: []string{"Array One", "Array Two"},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			store, path, original := newTestStore(t, testConfig)
			result, err := store.Import(revisionOf(original), []byte(test.content))
			if err != nil {
				t.Fatal(err)
			}
			if fmt.Sprint(result.Added) != fmt.Sprint(test.added) {
				t.Fatalf("added = %v, want %v", result.Added, test.added)
			}
			if len(result.Nodes) != 1+len(test.added) {
				t.Fatalf("unexpected nodes: %+v", result.Nodes)
			}
			for _, node := range result.Nodes[1:] {
				if !node.InProxies {
					t.Fatalf("imported node was not appended to Proxies: %+v", node)
				}
			}
			backup, err := os.ReadFile(path + ".5gpn-nodes.bak")
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(backup, original) {
				t.Fatal("backup does not contain the exact previous bytes")
			}
			written, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Contains(written, []byte("# top-level comment")) || !bytes.Contains(written, []byte("# existing node comment")) {
				t.Fatalf("comments were not preserved:\n%s", written)
			}
			if bytes.Contains(written, []byte("Must Not Be Adopted")) || bytes.Contains(written, []byte("must-not-be-adopted")) {
				t.Fatalf("untrusted top-level input was adopted:\n%s", written)
			}
		})
	}
}

func TestImportAcceptsPlainAndBase64URILists(t *testing.T) {
	first := "ss://YWVzLTEyOC1nY206cGFzcw@127.0.0.1:8388#URI%20One"
	second := "ss://YWVzLTEyOC1nY206cGFzczI@127.0.0.2:8389#URI%20Two"
	encoded := base64.StdEncoding.EncodeToString([]byte(first + "\n" + second + "\n"))
	wrapped := encoded[:len(encoded)/2] + "\n" + encoded[len(encoded)/2:]
	tests := []struct {
		name    string
		content []byte
	}{
		{name: "plain", content: []byte(first + "\n" + second + "\n")},
		{name: "standard base64", content: []byte(encoded)},
		{name: "line-wrapped standard base64", content: []byte(wrapped)},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			store, _, original := newTestStore(t, testConfig)
			result, err := store.Import(revisionOf(original), test.content)
			if err != nil {
				t.Fatal(err)
			}
			if fmt.Sprint(result.Added) != "[URI One URI Two]" {
				t.Fatalf("unexpected added nodes: %v", result.Added)
			}
		})
	}
}

func TestWholeSubscriptionRejectsURLSafeBase64(t *testing.T) {
	if _, err := decodeSubscriptionBase64("_w"); err == nil {
		t.Fatal("URL-safe Base64 was accepted for a whole subscription")
	}
}

func TestImportRejectsAnyUnknownURILineWithoutWriting(t *testing.T) {
	store, path, original := newTestStore(t, testConfig)
	content := []byte("ss://YWVzLTEyOC1nY206cGFzcw@127.0.0.1:8388#Good\nunknown://secret@example.invalid#Bad\n")
	_, err := store.Import(revisionOf(original), content)
	if !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("expected invalid input, got %v", err)
	}
	assertConfigUnchangedAndNoBackup(t, path, original)
}

func TestImportRejectsURIWithoutNameAndPartialMieru(t *testing.T) {
	tests := []struct {
		name    string
		content string
	}{
		{name: "missing name", content: "ss://YWVzLTEyOC1nY206cGFzcw@127.0.0.1:8388\n"},
		{name: "bad mieru port", content: "mierus://user:pass@127.0.0.1?port=6666&port=bad&protocol=TCP&protocol=TCP#Mieru\n"},
		{name: "duplicate mieru node", content: "mierus://user:pass@127.0.0.1?port=6666&port=6666&protocol=TCP&protocol=TCP#Mieru\n"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			store, path, original := newTestStore(t, testConfig)
			_, err := store.Import(revisionOf(original), []byte(test.content))
			if !errors.Is(err, ErrInvalidInput) {
				t.Fatalf("expected invalid input, got %v", err)
			}
			assertConfigUnchangedAndNoBackup(t, path, original)
		})
	}
}

func TestImportRejectsConflictsUnsafeNamesAndProhibitedTypes(t *testing.T) {
	tests := []struct {
		name    string
		content string
	}{
		{name: "existing node", content: "name: Existing\ntype: http\nserver: a.example\nport: 80\n"},
		{name: "existing group", content: "name: Proxies\ntype: http\nserver: a.example\nport: 80\n"},
		{name: "reserved", content: "name: DIRECT\ntype: http\nserver: a.example\nport: 80\n"},
		{name: "batch duplicate", content: "- {name: Duplicate, type: http, server: a.example, port: 80}\n- {name: Duplicate, type: http, server: b.example, port: 81}\n"},
		{name: "control character", content: "name: \"bad\\tname\"\ntype: http\nserver: a.example\nport: 80\n"},
		{name: "too long", content: "name: " + strings.Repeat("n", MaxNameBytes+1) + "\ntype: http\nserver: a.example\nport: 80\n"},
		{name: "wireguard", content: "name: Forbidden\ntype: wireguard\nserver: a.example\nport: 51820\nip: 10.0.0.2\nprivate-key: secret\npublic-key: secret\n"},
		{name: "tailscale", content: "name: Forbidden\ntype: tailscale\n"},
		{name: "openvpn", content: "name: Forbidden\ntype: openvpn\nserver: a.example\nport: 1194\n"},
		{name: "zerotier", content: "name: Forbidden\ntype: zerotier\nserver: a.example\nport: 9993\n"},
		{name: "YAML anchor", content: "name: &node-name Anchored\ntype: http\nserver: a.example\nport: 80\n"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			store, path, original := newTestStore(t, testConfig)
			_, err := store.Import(revisionOf(original), []byte(test.content))
			if !errors.Is(err, ErrInvalidInput) {
				t.Fatalf("expected invalid input, got %v", err)
			}
			assertConfigUnchangedAndNoBackup(t, path, original)
		})
	}
}

func TestImportRejectsCrashingMuxProtocol(t *testing.T) {
	// h2mux takes the process down on first dial rather than failing the
	// connection (x/net rewrote http2 and sing-mux never caught up), so it is
	// refused at the import boundary. The positive cases matter as much as the
	// negative ones: the guard must not quietly swallow the mux protocols that
	// do work, or it stops being a targeted fix and becomes a feature removal.
	rejected := []struct {
		name    string
		content string
	}{
		{name: "enabled", content: "name: Muxed\ntype: http\nserver: a.example\nport: 80\nsmux:\n  enabled: true\n  protocol: h2mux\n"},
		{name: "disabled is still rejected", content: "name: Muxed\ntype: http\nserver: a.example\nport: 80\nsmux:\n  enabled: false\n  protocol: h2mux\n"},
		{name: "case and padding", content: "name: Muxed\ntype: http\nserver: a.example\nport: 80\nsmux:\n  enabled: true\n  protocol: \"  H2Mux \"\n"},
	}
	for _, test := range rejected {
		t.Run("rejected/"+test.name, func(t *testing.T) {
			store, path, original := newTestStore(t, testConfig)
			_, err := store.Import(revisionOf(original), []byte(test.content))
			if !errors.Is(err, ErrInvalidInput) {
				t.Fatalf("expected invalid input, got %v", err)
			}
			assertConfigUnchangedAndNoBackup(t, path, original)
		})
	}

	for _, protocol := range []string{"smux", "yamux"} {
		t.Run("allowed/"+protocol, func(t *testing.T) {
			store, path, original := newTestStore(t, testConfig)
			content := "name: Muxed\ntype: http\nserver: a.example\nport: 80\nsmux:\n  enabled: true\n  protocol: " + protocol + "\n"
			if _, err := store.Import(revisionOf(original), []byte(content)); err != nil {
				t.Fatalf("%s must remain importable, got %v", protocol, err)
			}
			written, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Contains(written, []byte("Muxed")) {
				t.Fatalf("%s node was not written:\n%s", protocol, written)
			}
		})
	}
}

func TestImportRejectsMultipleDocumentsAndNodeLimit(t *testing.T) {
	tests := []struct {
		name    string
		content string
	}{
		{name: "multiple documents", content: "proxies:\n  - {name: One, type: http, server: one.example, port: 80}\n---\nproxies:\n  - {name: Two, type: http, server: two.example, port: 81}\n"},
		{name: "too many nodes", content: manyProxyMappings(MaxStaticNodes + 1)},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			store, path, original := newTestStore(t, testConfig)
			_, err := store.Import(revisionOf(original), []byte(test.content))
			if !errors.Is(err, ErrInvalidInput) {
				t.Fatalf("expected invalid input, got %v", err)
			}
			assertConfigUnchangedAndNoBackup(t, path, original)
		})
	}
}

func TestImportSizeLimit(t *testing.T) {
	store, path, original := newTestStore(t, testConfig)
	_, err := store.Import(revisionOf(original), bytes.Repeat([]byte("x"), MaxImportBytes+1))
	if !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("expected invalid input, got %v", err)
	}
	assertConfigUnchangedAndNoBackup(t, path, original)
}

func TestPreviewImportValidatesWithoutAnyFilesystemPublication(t *testing.T) {
	store, path, original := newTestStore(t, testConfig)
	content := []byte("name: Preview Node\ntype: http\nserver: preview.example\nport: 8080\n")
	preview, err := store.PreviewImport(revisionOf(original), content)
	if err != nil {
		t.Fatal(err)
	}
	if preview.Revision != revisionOf(original) || preview.CandidateRevision == preview.Revision || fmt.Sprint(preview.Added) != "[Preview Node]" {
		t.Fatalf("unexpected preview: %+v", preview)
	}
	assertConfigUnchangedAndNoBackup(t, path, original)
	if _, err := os.Lstat(path + ".5gpn-nodes.lock"); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("dry-run published a lock file: %v", err)
	}
}

func TestPreviewAndCommitProduceTheSameURIRevision(t *testing.T) {
	store, _, original := newTestStore(t, testConfig)
	content := []byte("vless://00000000-0000-0000-0000-000000000001@127.0.0.1:443?type=ws&security=tls&host=example.com&path=%2F#WebSocket\n")
	preview, err := store.PreviewImport(revisionOf(original), content)
	if err != nil {
		t.Fatal(err)
	}
	result, err := store.Import(revisionOf(original), content)
	if err != nil {
		t.Fatal(err)
	}
	if result.Revision != preview.CandidateRevision {
		t.Fatalf("preview revision %s differs from committed revision %s", preview.CandidateRevision, result.Revision)
	}
}

func TestRevisionConflictDoesNotChangeConfig(t *testing.T) {
	store, path, original := newTestStore(t, testConfig)
	wrong := strings.Repeat("0", 64)
	_, err := store.Import(wrong, []byte("name: Node\ntype: http\nserver: node.example\nport: 80\n"))
	var conflict *RevisionConflictError
	if !errors.As(err, &conflict) || conflict.Current != revisionOf(original) {
		t.Fatalf("expected current revision conflict, got %v", err)
	}
	assertConfigUnchangedAndNoBackup(t, path, original)
}

func TestDeleteRemovesNodeAndProxiesMembershipWithExactBackup(t *testing.T) {
	store, path, original := newTestStore(t, testConfig)
	result, err := store.Delete(revisionOf(original), " Existing ")
	if err != nil {
		t.Fatal(err)
	}
	if result.Removed != "Existing" || len(result.Nodes) != 0 {
		t.Fatalf("unexpected delete result: %+v", result)
	}
	backup, err := os.ReadFile(path + ".5gpn-nodes.bak")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(backup, original) {
		t.Fatal("backup is not the exact previous file")
	}
	written, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(written, []byte("name: Existing")) || bytes.Contains(written, []byte("- Existing")) {
		t.Fatalf("node or membership remains:\n%s", written)
	}
	if !bytes.Contains(written, []byte("# top-level comment")) {
		t.Fatalf("unrelated comment was lost:\n%s", written)
	}
}

func TestEachCommitReplacesTheFixedPreviousBackup(t *testing.T) {
	store, path, original := newTestStore(t, testConfig)
	first, err := store.Import(revisionOf(original), []byte("name: First\ntype: http\nserver: first.example\nport: 8080\n"))
	if err != nil {
		t.Fatal(err)
	}
	firstBytes, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Import(first.Revision, []byte("name: Second\ntype: http\nserver: second.example\nport: 8081\n")); err != nil {
		t.Fatal(err)
	}
	backup, err := os.ReadFile(path + ".5gpn-nodes.bak")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(backup, firstBytes) {
		t.Fatal("fixed backup was not replaced with the immediately previous config")
	}
}

func TestDeleteRejectsRemainingReferences(t *testing.T) {
	tests := []struct {
		name   string
		config string
	}{
		{
			name:   "other group",
			config: strings.Replace(testConfig, "rules:\n", "  - name: Other\n    type: select\n    proxies: [Existing]\nrules:\n", 1),
		},
		{
			name:   "rule",
			config: strings.Replace(testConfig, "  - MATCH,Proxies\n", "  - DOMAIN,example.com,Existing\n  - MATCH,Proxies\n", 1),
		},
		{
			name:   "dialer proxy",
			config: strings.Replace(testConfig, "proxy-groups:\n", "  - name: Dependent\n    type: socks5\n    server: 127.0.0.2\n    port: 1080\n    dialer-proxy: Existing\nproxy-groups:\n", 1),
		},
		{
			name:   "tunnel",
			config: testConfig + "tunnels:\n  - tcp,127.0.0.1:10000,127.0.0.1:10001,Existing\n",
		},
		{
			name:   "DNS proxy fragment after parameters",
			config: testConfig + "dns:\n  enable: false\n  nameserver:\n    - https://1.1.1.1/dns-query#h3=true&Existing\n",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			store, path, original := newTestStore(t, test.config)
			_, err := store.Delete(revisionOf(original), "Existing")
			if !errors.Is(err, ErrInvalidInput) {
				t.Fatalf("expected invalid input, got %v", err)
			}
			assertConfigUnchangedAndNoBackup(t, path, original)
		})
	}
}

func TestDNSFragmentReferenceUsesParsedBareSegments(t *testing.T) {
	tests := []struct {
		value string
		name  string
	}{
		{value: "https://1.1.1.1/dns-query#h3=true&Node+One", name: "Node+One"},
		{value: "https://1.1.1.1/dns-query#Node%2FOne", name: "Node/One"},
	}
	for _, test := range tests {
		if !dnsFragmentReferences(test.value, test.name) {
			t.Fatalf("did not find %q in %q", test.name, test.value)
		}
	}
}

func manyProxyMappings(count int) string {
	var output strings.Builder
	output.WriteString("proxies:\n")
	for index := range count {
		fmt.Fprintf(&output, "  - {name: Node %d, type: http, server: 127.0.0.1, port: %d}\n", index, 1000+index)
	}
	return output.String()
}

func assertConfigUnchangedAndNoBackup(t *testing.T, path string, original []byte) {
	t.Helper()
	written, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(written, original) {
		t.Fatalf("config changed after a failed operation:\n%s", written)
	}
	if _, err := os.Lstat(path + ".5gpn-nodes.bak"); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("backup was published after a failed operation: %v", err)
	}
}
