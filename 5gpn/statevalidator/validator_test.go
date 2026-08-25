package statevalidator

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/metacubex/mihomo/5gpn/bot"
	"github.com/metacubex/mihomo/5gpn/dns"
	"github.com/metacubex/mihomo/5gpn/engine"
)

func TestValidateAcceptsValidDocumentsWithoutWriting(t *testing.T) {
	dir := t.TempDir()
	writeDocument(t, dir, dnsDocumentName, installedDNSDocument())
	writeDocument(t, dir, interceptDocumentName, engine.DefaultDocument())
	writeDocument(t, dir, botDocumentName, bot.DefaultDocument())
	if err := os.WriteFile(filepath.Join(dir, "certificate-request"), []byte("existing request sentinel"), 0o644); err != nil {
		t.Fatal(err)
	}

	before := snapshotDirectory(t, dir)
	result, err := Validate(dir)
	if err != nil {
		t.Fatalf("Validate() error = %v", err)
	}
	if want := []string{dnsDocumentName, interceptDocumentName, botDocumentName}; !reflect.DeepEqual(result.Validated, want) {
		t.Fatalf("validated = %v, want %v", result.Validated, want)
	}
	if len(result.Missing) != 0 {
		t.Fatalf("missing = %v, want none", result.Missing)
	}
	after := snapshotDirectory(t, dir)
	if !reflect.DeepEqual(after, before) {
		t.Fatalf("state directory changed during validation\nbefore: %#v\nafter:  %#v", before, after)
	}
}

func TestValidateAllowsMissingDocuments(t *testing.T) {
	t.Run("all missing", func(t *testing.T) {
		dir := t.TempDir()
		before := snapshotDirectory(t, dir)
		result, err := Validate(dir)
		if err != nil {
			t.Fatalf("Validate() error = %v", err)
		}
		if len(result.Validated) != 0 {
			t.Fatalf("validated = %v, want none", result.Validated)
		}
		want := []string{dnsDocumentName, interceptDocumentName, botDocumentName}
		if !reflect.DeepEqual(result.Missing, want) {
			t.Fatalf("missing = %v, want %v", result.Missing, want)
		}
		if after := snapshotDirectory(t, dir); !reflect.DeepEqual(after, before) {
			t.Fatalf("empty state directory changed: %#v", after)
		}
	})

	t.Run("some missing", func(t *testing.T) {
		dir := t.TempDir()
		writeDocument(t, dir, dnsDocumentName, installedDNSDocument())
		result, err := Validate(dir)
		if err != nil {
			t.Fatalf("Validate() error = %v", err)
		}
		if want := []string{dnsDocumentName}; !reflect.DeepEqual(result.Validated, want) {
			t.Fatalf("validated = %v, want %v", result.Validated, want)
		}
		wantMissing := []string{interceptDocumentName, botDocumentName}
		if !reflect.DeepEqual(result.Missing, wantMissing) {
			t.Fatalf("missing = %v, want %v", result.Missing, wantMissing)
		}
	})
}

func TestValidateRejectsDuplicateAndUnknownJSONFields(t *testing.T) {
	tests := []struct {
		name     string
		filename string
		raw      []byte
		contains string
	}{
		{
			name:     "duplicate key",
			filename: dnsDocumentName,
			raw:      addTopLevelField(marshalDocument(t, dns.DefaultDocument()), `"gateway":""`),
			contains: "duplicate JSON key",
		},
		{
			name:     "unknown field",
			filename: interceptDocumentName,
			raw:      addTopLevelField(marshalDocument(t, engine.DefaultDocument()), `"unexpected":true`),
			contains: "unknown field",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			dir := t.TempDir()
			writeRawDocument(t, dir, test.filename, test.raw)
			_, err := Validate(dir)
			if err == nil || !strings.Contains(err.Error(), test.contains) {
				t.Fatalf("Validate() error = %v, want %q", err, test.contains)
			}
		})
	}
}

func TestValidateRejectsUnsupportedHTTP3AndNonFixedTLSPaths(t *testing.T) {
	tests := []struct {
		name     string
		mutate   func(*engine.Config)
		contains string
	}{
		{
			name: "HTTP3",
			mutate: func(document *engine.Config) {
				document.MITM.HTTP3 = true
			},
			contains: "HTTP/3 interception is unsupported",
		},
		{
			name: "TLS path",
			mutate: func(document *engine.Config) {
				document.TLSCert = "/tmp/unreviewed.pem"
			},
			contains: "TLS paths do not match",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			dir := t.TempDir()
			document := engine.DefaultDocument()
			test.mutate(&document)
			writeDocument(t, dir, interceptDocumentName, document)
			_, err := Validate(dir)
			if err == nil || !strings.Contains(err.Error(), test.contains) {
				t.Fatalf("Validate() error = %v, want %q", err, test.contains)
			}
		})
	}
}

func TestValidateRejectsInvalidInterceptionSemantics(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*engine.Config)
	}{
		{
			name: "module",
			mutate: func(document *engine.Config) {
				document.Modules[0].ID = "INVALID"
				document.ExecutionOrder[0] = "INVALID"
			},
		},
		{
			name: "action",
			mutate: func(document *engine.Config) {
				document.Modules[0].Scripts[0].BodyMode = "invalid"
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			dir := t.TempDir()
			document := validScriptDocument()
			test.mutate(&document)
			writeDocument(t, dir, interceptDocumentName, document)
			if _, err := Validate(dir); err == nil {
				t.Fatal("Validate() accepted invalid interception state")
			}
		})
	}
}

func TestValidateDoesNotCompileGuestCodeOrPublishCertificateRequest(t *testing.T) {
	dir := t.TempDir()
	document := validScriptDocument()
	rule := &document.Modules[0].Scripts[0]
	rule.Reject = false
	rule.ScriptBody = "function {"
	rule.ScriptDigest = digest(rule.ScriptBody)
	writeDocument(t, dir, interceptDocumentName, document)

	before := snapshotDirectory(t, dir)
	if _, err := Validate(dir); err != nil {
		t.Fatalf("read-only semantic validation compiled guest code: %v", err)
	}
	if after := snapshotDirectory(t, dir); !reflect.DeepEqual(after, before) {
		t.Fatalf("validation changed state\nbefore: %#v\nafter:  %#v", before, after)
	}
	if _, err := os.Lstat(filepath.Join(dir, "certificate-request")); !os.IsNotExist(err) {
		t.Fatalf("certificate request was created: %v", err)
	}
}

func TestValidateRejectsEnabledBotWithoutTokenOrAdmin(t *testing.T) {
	tests := []struct {
		name     string
		document bot.Document
		contains string
	}{
		{
			name: "token",
			document: bot.Document{
				Version: 1, Enabled: true, Admins: []int64{1234},
			},
			contains: "without a token",
		},
		{
			name: "admin",
			document: bot.Document{
				Version: 1, Enabled: true, Token: "123:token", Admins: []int64{},
			},
			contains: "without at least one admin",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			dir := t.TempDir()
			writeDocument(t, dir, botDocumentName, test.document)
			_, err := Validate(dir)
			if err == nil || !strings.Contains(err.Error(), test.contains) {
				t.Fatalf("Validate() error = %v, want %q", err, test.contains)
			}
		})
	}
}

func TestValidateRejectsInvalidDNSAndMissingCriticalListeners(t *testing.T) {
	tests := []struct {
		name     string
		mutate   func(*dns.Document)
		contains string
	}{
		{
			name: "invalid policy",
			mutate: func(document *dns.Document) {
				document.Policy.Rules = nil
			},
			contains: "policy rules must be an array",
		},
		{
			name: "missing DoT",
			mutate: func(document *dns.Document) {
				document.Listen.DoT = ""
			},
			contains: "both DoT and origin listeners are required",
		},
		{
			name: "missing origin",
			mutate: func(document *dns.Document) {
				document.Listen.Origin = ""
			},
			contains: "both DoT and origin listeners are required",
		},
		{
			name: "missing certificate",
			mutate: func(document *dns.Document) {
				document.Listen.Certificate = ""
			},
			contains: "DoT certificate paths must be",
		},
		{
			name: "missing private key",
			mutate: func(document *dns.Document) {
				document.Listen.PrivateKey = ""
			},
			contains: "DoT certificate paths must be",
		},
		{
			name: "non-loopback debug",
			mutate: func(document *dns.Document) {
				document.Listen.Debug = "0.0.0.0:5353"
			},
			contains: "listener coordinates must be",
		},
		{
			name: "non-loopback origin",
			mutate: func(document *dns.Document) {
				document.Listen.Origin = "0.0.0.0:5354"
			},
			contains: "listener coordinates must be",
		},
		{
			name: "wrong DoT port",
			mutate: func(document *dns.Document) {
				document.Listen.DoT = ":8853"
			},
			contains: "listener coordinates must be",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			dir := t.TempDir()
			document := installedDNSDocument()
			test.mutate(&document)
			writeDocument(t, dir, dnsDocumentName, document)
			_, err := Validate(dir)
			if err == nil || !strings.Contains(err.Error(), test.contains) {
				t.Fatalf("Validate() error = %v, want %q", err, test.contains)
			}
		})
	}
}

func TestValidateRequiresAbsoluteDirectoryAndAllowsMissingDirectory(t *testing.T) {
	if _, err := Validate("relative"); err == nil {
		t.Fatal("Validate() accepted a relative state directory")
	}
	missing := filepath.Join(t.TempDir(), "missing")
	result, err := Validate(missing)
	if err != nil {
		t.Fatalf("Validate() rejected a missing state directory: %v", err)
	}
	want := []string{dnsDocumentName, interceptDocumentName, botDocumentName}
	if !reflect.DeepEqual(result.Missing, want) {
		t.Fatalf("missing = %v, want %v", result.Missing, want)
	}
	if _, err := ValidateForOwner(missing, -1); err == nil {
		t.Fatal("ValidateForOwner() accepted an invalid owner UID")
	}
}

func validScriptDocument() engine.Config {
	document := engine.DefaultDocument()
	manifest := "apiVersion: 5gpn.io/v1\nkind: NativeExtension\n"
	document.Modules = []engine.Module{{
		ID:           "example.extension",
		Version:      "1.0.0",
		Name:         "Example",
		ImportedAt:   time.Unix(0, 0).UTC().Format(time.RFC3339),
		Source:       engine.ModuleSource{Body: manifest, Digest: digest(manifest)},
		CaptureHosts: []string{"example.com"},
		CaptureDNS:   "trust",
		Scripts: []engine.ScriptRule{{
			ID: "reject-action", Phase: "request",
			Match: engine.ActionMatch{
				Hosts: []string{"example.com"}, Schemes: []string{"https"}, PathRegex: ".*",
			},
			Reject: true, BodyMode: "none", TimeoutMS: 100, MaxBodyBytes: 1024,
		}},
		EgressGroup: "DIRECT",
	}}
	document.ExecutionOrder = []string{"example.extension"}
	return document
}

func installedDNSDocument() dns.Document {
	document := dns.DefaultDocument()
	document.Listen.Certificate = "/etc/5gpn/cert/dot/current/fullchain.pem"
	document.Listen.PrivateKey = "/etc/5gpn/cert/dot/current/privkey.pem"
	return document
}

func digest(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}

func marshalDocument(t *testing.T, value any) []byte {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func addTopLevelField(raw []byte, field string) []byte {
	trimmed := strings.TrimSpace(string(raw))
	return []byte(strings.TrimSuffix(trimmed, "}") + "," + field + "}")
}

func writeDocument(t *testing.T, dir, name string, value any) {
	t.Helper()
	writeRawDocument(t, dir, name, marshalDocument(t, value))
}

func writeRawDocument(t *testing.T, dir, name string, raw []byte) {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
}

type fileSnapshot struct {
	Mode    os.FileMode
	Size    int64
	ModTime time.Time
	Content string
}

func snapshotDirectory(t *testing.T, dir string) map[string]fileSnapshot {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	snapshot := make(map[string]fileSnapshot, len(entries))
	for _, entry := range entries {
		path := filepath.Join(dir, entry.Name())
		info, err := os.Lstat(path)
		if err != nil {
			t.Fatal(err)
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		snapshot[entry.Name()] = fileSnapshot{
			Mode: info.Mode(), Size: info.Size(), ModTime: info.ModTime(), Content: string(raw),
		}
	}
	return snapshot
}
