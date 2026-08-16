package fivegpn

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/metacubex/mihomo/5gpn/dns"
	"github.com/metacubex/mihomo/5gpn/engine"
	"github.com/metacubex/mihomo/5gpn/state"
)

func TestCapabilityKeyContract(t *testing.T) {
	got := []string{
		capabilityCoreKey,
		capabilityDNSKey,
		capabilityInterceptionKey,
		capabilityBotKey,
	}
	want := []string{
		"5gpn-core",
		"5gpn-dns",
		"5gpn-interception",
		"5gpn-bot",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("capability keys = %v, want %v", got, want)
	}
	if capabilityInterceptionVersion != engine.ReviewContractVersion || engine.ReviewContractVersion != 7 {
		t.Fatalf("interception capability version = %d, review contract = %d, want 7", capabilityInterceptionVersion, engine.ReviewContractVersion)
	}
}

func TestStartRejectsCorruptDNSDocument(t *testing.T) {
	home := t.TempDir()
	dir, err := state.Dir(home)
	if err != nil {
		t.Fatalf("state directory: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "dns.json"), []byte(`{"version":`), 0o600); err != nil {
		t.Fatalf("write corrupt DNS document: %v", err)
	}

	err = Start(home, func(error) {})
	if err == nil {
		t.Fatal("Start accepted a corrupt DNS document")
	}
	if !strings.Contains(err.Error(), "dns.json") {
		t.Fatalf("Start error = %q", err)
	}
}

func TestStartRejectsMissingCriticalDNSListeners(t *testing.T) {
	home := t.TempDir()
	dir, err := state.Dir(home)
	if err != nil {
		t.Fatalf("state directory: %v", err)
	}
	document := dns.DefaultDocument()
	document.Listen.DoT = ""
	document.Listen.Origin = ""
	document.Policy.Rules = []dns.Rule{}
	raw, err := json.Marshal(document)
	if err != nil {
		t.Fatalf("marshal DNS document: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "dns.json"), raw, 0o600); err != nil {
		t.Fatalf("write DNS document: %v", err)
	}

	unexpectedFatal := make(chan error, 1)
	err = Start(home, func(err error) {
		unexpectedFatal <- err
	})
	if err == nil {
		t.Fatal("Start accepted a document with no critical DNS listeners")
	}
	if !strings.Contains(err.Error(), "both DoT and origin listeners are required") {
		t.Fatalf("Start error = %q", err)
	}
	select {
	case failure := <-unexpectedFatal:
		t.Fatalf("a synchronous bind failure was reported as a runtime fatal: %v", failure)
	default:
	}
}

func TestStartReturnsDNSListenerFailure(t *testing.T) {
	home := t.TempDir()
	dir, err := state.Dir(home)
	if err != nil {
		t.Fatalf("state directory: %v", err)
	}
	document := dns.DefaultDocument()
	document.Listen.DoT = "127.0.0.1:18530"
	document.Listen.Origin = "127.0.0.1:18531"
	document.Listen.Certificate = filepath.Join(dir, "missing-cert.pem")
	document.Listen.PrivateKey = filepath.Join(dir, "missing-key.pem")
	document.Listen.Debug = ""
	document.Policy.Rules = []dns.Rule{}
	raw, err := json.Marshal(document)
	if err != nil {
		t.Fatalf("marshal DNS document: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "dns.json"), raw, 0o600); err != nil {
		t.Fatalf("write DNS document: %v", err)
	}

	err = Start(home, func(error) {})
	if err == nil {
		t.Fatal("Start accepted unusable critical DNS listeners")
	}
	if !strings.Contains(err.Error(), "start DNS listeners") || !strings.Contains(err.Error(), "missing-cert.pem") {
		t.Fatalf("Start error = %q", err)
	}
}

func TestStartBuildsInterceptionPlanBeforeOpeningDNS(t *testing.T) {
	home := t.TempDir()
	dir, err := state.Dir(home)
	if err != nil {
		t.Fatalf("state directory: %v", err)
	}
	document := dns.DefaultDocument()
	document.Listen.DoT = "127.0.0.1:18540"
	document.Listen.Origin = "127.0.0.1:18541"
	// These paths are deliberately unusable. If DNS Listen moves ahead of the
	// interception plan again, this error wins and the test names the ordering
	// regression rather than merely observing a callback sequence.
	document.Listen.Certificate = filepath.Join(dir, "missing-cert.pem")
	document.Listen.PrivateKey = filepath.Join(dir, "missing-key.pem")
	document.Listen.Debug = ""
	document.Policy.Rules = []dns.Rule{}
	raw, err := json.Marshal(document)
	if err != nil {
		t.Fatalf("marshal DNS document: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "dns.json"), raw, 0o600); err != nil {
		t.Fatalf("write DNS document: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "intercept.json"), []byte(`{"version":`), 0o600); err != nil {
		t.Fatalf("write corrupt interception document: %v", err)
	}

	err = Start(home, func(error) {})
	if err == nil {
		t.Fatal("Start opened DNS without a valid interception plan")
	}
	if !strings.Contains(err.Error(), "install interception plan") {
		t.Fatalf("Start error = %q, want interception-plan failure before DNS Listen", err)
	}
	if strings.Contains(err.Error(), "start DNS listeners") || strings.Contains(err.Error(), "missing-cert.pem") {
		t.Fatalf("DNS Listen ran before interception plan construction: %q", err)
	}
}
