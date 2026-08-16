package hub

import (
	"errors"
	"reflect"
	"testing"

	"github.com/metacubex/mihomo/component/ca"
	"github.com/metacubex/mihomo/component/updater"
	"github.com/metacubex/mihomo/config"
)

func TestManagedControllerOptionsCannotOverrideConfig(t *testing.T) {
	tests := []struct {
		name   string
		option Option
	}{
		{name: "secret", option: WithSecret("override-secret")},
		{name: "external UI", option: WithExternalUI("other-ui")},
		{name: "plaintext controller", option: WithExternalController("127.0.0.1:9090")},
		{name: "TLS controller", option: WithExternalControllerTLS("127.0.0.1:9443")},
		{name: "Unix controller", option: WithExternalControllerUnix("controller.sock")},
		{name: "pipe controller", option: WithExternalControllerPipe(`\\.\pipe\controller`)},
		{name: "routing mark", option: WithExternalControllerRoutingMark(1)},
		{name: "certificate", option: func(cfg *config.Config) { cfg.TLS.Certificate = "other-cert.pem" }},
		{name: "private key", option: func(cfg *config.Config) { cfg.TLS.PrivateKey = "other-key.pem" }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			cfg := managedCoreConfig(t)
			if err := applyManagedOptions(cfg, test.option); err == nil {
				t.Fatal("managed controller override was accepted")
			}
		})
	}

	cfg := managedCoreConfig(t)
	if err := applyManagedOptions(cfg, WithSecret(cfg.Controller.Secret), WithExternalUI(cfg.Controller.ExternalUI)); err != nil {
		t.Fatalf("same-value managed options were rejected: %v", err)
	}

	ordinary := &config.Config{Controller: &config.Controller{}, TLS: &config.TLS{}, General: &config.General{}}
	applyOptions(ordinary, WithSecret("upstream-secret"))
	if ordinary.Controller.Secret != "upstream-secret" {
		t.Fatal("ordinary mihomo secret override no longer applies")
	}
}

func TestParseManagedRejectsASecretOverrideWithoutPublishingManagedMode(t *testing.T) {
	previousManaged := updater.ManagedDistribution()
	updater.SetManagedDistribution(false)
	t.Cleanup(func() { updater.SetManagedDistribution(previousManaged) })

	raw := []byte("secret: from-file\nexternal-controller-tls: 127.0.0.1:443\nexternal-ui: ui\ntls:\n  certificate: cert.pem\n  private-key: key.pem\n")
	if err := ParseManaged(raw, WithSecret("override-secret")); err == nil {
		t.Fatal("ParseManaged accepted a secret override that changed config.yaml")
	}
	if updater.ManagedDistribution() {
		t.Fatal("rejected managed parse polluted the ordinary distribution mode")
	}
}

func TestManagedRuntimeFailureKeepsThePublishedFailureDomain(t *testing.T) {
	previousManaged := updater.ManagedDistribution()
	t.Cleanup(func() { updater.SetManagedDistribution(previousManaged) })

	tests := []struct {
		name  string
		start func() error
		apply func(*config.Config) error
	}{
		{name: "start", start: func() error { return errors.New("start failed") }, apply: func(*config.Config) error { return nil }},
		{name: "apply", start: func() error { return nil }, apply: func(*config.Config) error { return errors.New("apply failed") }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			updater.SetManagedDistribution(false)
			if err := applyManagedConfigWith(managedCoreConfig(t), test.start, test.apply); err == nil {
				t.Fatal("managed runtime failure was hidden")
			}
			if !updater.ManagedDistribution() {
				t.Fatal("managed mode rolled back after startup entered the shared failure domain")
			}
		})
	}
}

func TestManagedControllerIsValidatedBeforeFiveGPNStarts(t *testing.T) {
	previousManaged := updater.ManagedDistribution()
	updater.SetManagedDistribution(false)
	t.Cleanup(func() { updater.SetManagedDistribution(previousManaged) })

	cfg := managedCoreConfig(t)
	cfg.TLS.ClientAuthType = "require-and-verify-client-cert"

	var calls []string
	err := applyManagedConfigWith(cfg, func() error {
		calls = append(calls, "start")
		return nil
	}, func(*config.Config) error {
		calls = append(calls, "apply")
		return nil
	})
	if err == nil {
		t.Fatal("invalid managed controller config was accepted")
	}
	if len(calls) != 0 {
		t.Fatalf("managed runtime advanced before controller validation: %v", calls)
	}
	if updater.ManagedDistribution() {
		t.Fatal("failed controller preflight published managed distribution mode")
	}
}

func TestManagedControllerValidationPrecedesStartAndApply(t *testing.T) {
	previousManaged := updater.ManagedDistribution()
	updater.SetManagedDistribution(false)
	t.Cleanup(func() { updater.SetManagedDistribution(previousManaged) })

	cfg := managedCoreConfig(t)
	var calls []string
	err := applyManagedConfigWith(cfg, func() error {
		if !updater.ManagedDistribution() {
			t.Fatal("managed distribution mode was not published before subsystem startup")
		}
		calls = append(calls, "start")
		return nil
	}, func(candidate *config.Config) error {
		if !updater.ManagedDistribution() {
			t.Fatal("managed distribution mode was not published before controller apply")
		}
		if candidate != cfg {
			t.Fatal("apply received a different config")
		}
		calls = append(calls, "apply")
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"start", "apply"}; !reflect.DeepEqual(calls, want) {
		t.Fatalf("managed startup order = %v, want %v", calls, want)
	}
	if !updater.ManagedDistribution() {
		t.Fatal("successful managed startup did not publish managed distribution mode")
	}
}

func managedCoreConfig(t *testing.T) *config.Config {
	t.Helper()
	certificate, privateKey, _, err := ca.NewRandomTLSKeyPair(ca.KeyPairTypeP256)
	if err != nil {
		t.Fatal(err)
	}
	return &config.Config{
		General: &config.General{},
		Controller: &config.Controller{
			ExternalControllerTLS: "127.0.0.1:443",
			ExternalUI:            "ui",
			Secret:                "controller-secret",
		},
		TLS: &config.TLS{
			Certificate: certificate,
			PrivateKey:  privateKey,
		},
	}
}
