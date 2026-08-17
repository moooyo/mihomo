package configinspect

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
)

const validConfig = `
secret: 'controller"secret'
external-controller-tls: 127.0.0.1:443
external-ui: /opt/5gpn/ui
tls:
  certificate: /etc/5gpn/cert/console/fullchain.pem
  private-key: /etc/5gpn/cert/console/privkey.pem
`

func TestInspectReturnsTheExactManagedControllerProjection(t *testing.T) {
	raw := []byte(validConfig)
	view, err := Inspect(raw)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(raw)
	if OutputVersion != 2 || view.Version != 2 || view.RawRevision != hex.EncodeToString(sum[:]) {
		t.Fatalf("unexpected output envelope: %+v", view)
	}
	if view.Secret != `controller"secret` || view.ExternalControllerTLS != "127.0.0.1:443" {
		t.Fatalf("unexpected controller projection: %+v", view)
	}
	if view.Certificate != "/etc/5gpn/cert/console/fullchain.pem" {
		t.Fatalf("certificate = %q", view.Certificate)
	}
	if view.PrivateKey != "/etc/5gpn/cert/console/privkey.pem" {
		t.Fatalf("private key = %q", view.PrivateKey)
	}
	if view.ExternalUI != "/opt/5gpn/ui" {
		t.Fatalf("external UI = %q", view.ExternalUI)
	}
}

func TestInspectRejectsAnUnsafeControllerWithoutEchoingTheSecret(t *testing.T) {
	secret := "do-not-echo-this-secret"
	raw := strings.Replace(validConfig, `controller"secret`, secret, 1)
	raw = strings.Replace(raw, "127.0.0.1:443", "attacker.example:443", 1)
	_, err := Inspect([]byte(raw))
	if err == nil {
		t.Fatal("unsafe controller address was accepted")
	}
	if strings.Contains(err.Error(), secret) {
		t.Fatalf("inspection error echoed the controller secret: %v", err)
	}
}

func TestInspectRejectsManagedTLSClientAuthenticationAndECH(t *testing.T) {
	tests := []struct {
		name  string
		field string
	}{
		{name: "client auth type", field: "  client-auth-type: require-and-verify-client-cert\n"},
		{name: "whitespace client auth type", field: "  client-auth-type: ' '\n"},
		{name: "client auth certificate", field: "  client-auth-cert: /etc/5gpn/client-ca.pem\n"},
		{name: "whitespace client auth certificate", field: "  client-auth-cert: ' '\n"},
		{name: "ECH", field: "  ech-key: /etc/5gpn/ech.pem\n"},
		{name: "whitespace ECH", field: "  ech-key: ' '\n"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			raw := strings.Replace(validConfig, "  certificate:", test.field+"  certificate:", 1)
			if _, err := Inspect([]byte(raw)); err == nil {
				t.Fatal("unsupported managed TLS field was accepted")
			}
		})
	}
}

func TestInspectMatchesManagedSecretAndRoutingMarkContract(t *testing.T) {
	unicodeRaw := strings.Replace(validConfig, `controller"secret`, "控制器🔐", 1)
	view, err := Inspect([]byte(unicodeRaw))
	if err != nil {
		t.Fatalf("ordinary Unicode secret was rejected: %v", err)
	}
	if view.Secret != "控制器🔐" {
		t.Fatalf("Unicode secret projection = %q", view.Secret)
	}

	controlRaw := strings.Replace(validConfig, `secret: 'controller"secret'`, `secret: "before\u007fafter"`, 1)
	if _, err := Inspect([]byte(controlRaw)); err == nil {
		t.Fatal("controller secret containing DEL was accepted")
	}

	routingMarkRaw := strings.Replace(validConfig, "external-controller-tls:", "external-controller-routing-mark: 1\nexternal-controller-tls:", 1)
	if _, err := Inspect([]byte(routingMarkRaw)); err == nil {
		t.Fatal("managed external-controller-routing-mark was accepted")
	}
}

func TestInspectRejectsDuplicateControllerSecrets(t *testing.T) {
	raw := []byte("secret: one\nsecret: two\nexternal-controller-tls: 127.0.0.1:443\ntls:\n  certificate: cert.pem\n  private-key: key.pem\n")
	if _, err := Inspect(raw); err == nil {
		t.Fatal("duplicate secret keys were accepted")
	}
}
