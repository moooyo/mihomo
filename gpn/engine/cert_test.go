package engine

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// writeTestLeaf publishes a self-signed pair the store will accept: not a CA,
// currently valid, and with no SAN requirement to meet because the default
// document enables no extension and so names no capture host.
func writeTestLeaf(t *testing.T, certPath, keyPath string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "leaf.test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"leaf.test"},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	if err := os.WriteFile(certPath, certPEM, 0o644); err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		t.Fatal(err)
	}
}

// A gateway that has never enabled an extension has requested no capture hosts,
// so the root oneshot has minted no leaf and there is no pair on disk to load.
//
// That is an interception authority of zero extent, not a broken engine, and
// the difference is not academic: the engine has to exist for an operator to
// enable a first extension at all. While it does not, every /gpn/interception
// route answers 503 -- including the review that installing one begins with --
// and the gateway can never leave the state it shipped in.
//
// DefaultDocument's own comment already draws this line for the document: "the
// API answers 503 for an engine that failed to load and renders a panel for one
// that loaded and says it is off, and those must not be the same thing". The
// certificate is now held to the rule the document was already held to.
func TestNewSucceedsBeforeAnyLeafHasBeenMinted(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "intercept.json")

	cfg := DefaultDocument()
	// Paths under the temp dir, so the absence under test is the test's own and
	// not a property of whatever host happens to run it.
	cfg.TLSCert = filepath.Join(dir, "tls", "fullchain.pem")
	cfg.TLSKey = filepath.Join(dir, "tls", "privkey.pem")
	body, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatal(err)
	}

	e, err := New(path, dir)
	if err != nil {
		t.Fatalf("New refused to assemble an engine with no leaf minted yet: %v", err)
	}
	if e == nil {
		t.Fatal("New returned neither an engine nor an error")
	}

	// The authority really is zero, not merely unchecked: resolving a
	// certificate still fails, so a capture would lose its handshake rather
	// than proceed with nothing to present.
	if _, err := e.certs.currentCertificate(); err == nil {
		t.Fatal("a certificate resolved with no leaf on disk")
	}
}

// The complement: once the oneshot has published a pair, the same engine
// resolves it. Without this the test above would still pass if resolution were
// broken outright rather than merely empty.
func TestTheEngineResolvesALeafOnceOneIsPublished(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "intercept.json")
	tlsDir := filepath.Join(dir, "tls")
	if err := os.MkdirAll(tlsDir, 0o755); err != nil {
		t.Fatal(err)
	}
	certPath := filepath.Join(tlsDir, "fullchain.pem")
	keyPath := filepath.Join(tlsDir, "privkey.pem")
	writeTestLeaf(t, certPath, keyPath)

	cfg := DefaultDocument()
	cfg.TLSCert = certPath
	cfg.TLSKey = keyPath
	body, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatal(err)
	}

	e, err := New(path, dir)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if _, err := e.certs.currentCertificate(); err != nil {
		t.Fatalf("a published leaf did not resolve: %v", err)
	}
}
