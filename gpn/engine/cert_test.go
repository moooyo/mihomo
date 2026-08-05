package engine

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/metacubex/tls"
)

// writeTestLeaf publishes a self-signed pair the store will accept: not a CA,
// currently valid, and with no SAN requirement to meet because the default
// document enables no extension and so names no capture host.
func writeTestLeaf(t *testing.T, certPath, keyPath string) {
	t.Helper()
	now := time.Now()
	writeTestLeafFor(t, certPath, keyPath, 1, []string{"leaf.test"}, now.Add(-time.Hour), now.Add(24*time.Hour))
}

func writeTestLeafFor(
	t *testing.T,
	certPath string,
	keyPath string,
	serial int64,
	dnsNames []string,
	notBefore time.Time,
	notAfter time.Time,
) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(certPath), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(keyPath), 0o755); err != nil {
		t.Fatal(err)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(serial),
		Subject:      pkix.Name{CommonName: "leaf.test"},
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     dnsNames,
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

func newCertificateStateTestEngine(t *testing.T) (*Engine, string, string) {
	t.Helper()
	dir := t.TempDir()
	tlsDir := filepath.Join(dir, "tls")
	certPath := filepath.Join(tlsDir, "fullchain.pem")
	keyPath := filepath.Join(tlsDir, "privkey.pem")
	document := strings.ReplaceAll(
		twoExtensionDocument,
		"/etc/5gpn/intercept/tls/fullchain.pem",
		filepath.ToSlash(certPath),
	)
	document = strings.ReplaceAll(
		document,
		"/etc/5gpn/intercept/tls/privkey.pem",
		filepath.ToSlash(keyPath),
	)
	configPath := filepath.Join(dir, "intercept.json")
	if err := os.WriteFile(configPath, []byte(document), 0o600); err != nil {
		t.Fatal(err)
	}
	e, err := New(configPath, dir)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return e, certPath, keyPath
}

func setTestPairModTime(t *testing.T, certPath, keyPath string, modTime time.Time) {
	t.Helper()
	if err := os.Chtimes(certPath, modTime, modTime); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(keyPath, modTime, modTime); err != nil {
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

func TestCertificateStateReadsAColdLeafWithoutPrimingTheHandshakeCache(t *testing.T) {
	e, certPath, keyPath := newCertificateStateTestEngine(t)
	notAfter := time.Now().Add(48 * time.Hour).Truncate(time.Second)
	writeTestLeafFor(
		t,
		certPath,
		keyPath,
		11,
		[]string{"*.first.example", "shared.example.com", "unused.example.com"},
		time.Now().Add(-time.Hour),
		notAfter,
	)

	snapshot, err := e.Snapshot()
	if err != nil {
		t.Fatalf("Snapshot: %v", err)
	}
	if !snapshot.Certificate.Loaded {
		t.Fatal("a parseable pair on disk was reported as unloaded")
	}
	if snapshot.Certificate.NotAfter != notAfter.Unix() {
		t.Fatalf("NotAfter = %d, want %d", snapshot.Certificate.NotAfter, notAfter.Unix())
	}
	if !snapshot.Certificate.CoveredAll || len(snapshot.Certificate.Missing) != 0 {
		t.Fatalf("certificate coverage = %+v, want every requested SAN covered", snapshot.Certificate)
	}

	e.certs.mu.Lock()
	cached := e.certs.certificate
	e.certs.mu.Unlock()
	if cached != nil {
		t.Fatal("a read-only status snapshot populated the handshake cache")
	}
}

func TestCertificateStatusProjectionCacheTracksFileModTime(t *testing.T) {
	e, certPath, keyPath := newCertificateStateTestEngine(t)
	now := time.Now()
	initialNotAfter := now.Add(24 * time.Hour).Truncate(time.Second)
	writeTestLeafFor(
		t,
		certPath,
		keyPath,
		12,
		[]string{"*.first.example", "shared.example.com"},
		now.Add(-time.Hour),
		initialNotAfter,
	)
	initialModTime := now.Add(-10 * time.Minute).Truncate(time.Second)
	setTestPairModTime(t, certPath, keyPath, initialModTime)
	certInfo, err := os.Stat(certPath)
	if err != nil {
		t.Fatal(err)
	}
	keyInfo, err := os.Stat(keyPath)
	if err != nil {
		t.Fatal(err)
	}

	snapshot, err := e.Snapshot()
	if err != nil {
		t.Fatalf("initial Snapshot: %v", err)
	}
	if !snapshot.Certificate.Loaded || snapshot.Certificate.NotAfter != initialNotAfter.Unix() {
		t.Fatalf("initial certificate state = %+v", snapshot.Certificate)
	}

	// Change the bytes without changing the cache key. The second read must use
	// the immutable projection rather than parse the private pair again.
	if err := os.WriteFile(certPath, []byte("broken certificate"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(certPath, certInfo.ModTime(), certInfo.ModTime()); err != nil {
		t.Fatal(err)
	}
	snapshot, err = e.Snapshot()
	if err != nil {
		t.Fatalf("cached Snapshot: %v", err)
	}
	if !snapshot.Certificate.Loaded || snapshot.Certificate.NotAfter != initialNotAfter.Unix() {
		t.Fatalf("unchanged cache key did not reuse the status projection: %+v", snapshot.Certificate)
	}

	// Advancing the certificate mtime invalidates the positive projection. The
	// broken pair becomes a cached negative result.
	brokenModTime := certInfo.ModTime().Add(time.Second)
	if err := os.Chtimes(certPath, brokenModTime, brokenModTime); err != nil {
		t.Fatal(err)
	}
	snapshot, err = e.Snapshot()
	if err != nil {
		t.Fatalf("invalidated Snapshot: %v", err)
	}
	if snapshot.Certificate.Loaded {
		t.Fatalf("mtime change did not invalidate the positive projection: %+v", snapshot.Certificate)
	}

	// Publish a valid pair under the same path-and-mtime key. It stays unloaded
	// until the key changes, proving load failures are cached as projections too.
	renewedNotAfter := now.Add(72 * time.Hour).Truncate(time.Second)
	writeTestLeafFor(
		t,
		certPath,
		keyPath,
		13,
		[]string{"*.first.example", "shared.example.com"},
		now.Add(-time.Hour),
		renewedNotAfter,
	)
	if err := os.Chtimes(certPath, brokenModTime, brokenModTime); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(keyPath, keyInfo.ModTime(), keyInfo.ModTime()); err != nil {
		t.Fatal(err)
	}
	snapshot, err = e.Snapshot()
	if err != nil {
		t.Fatalf("negative cached Snapshot: %v", err)
	}
	if snapshot.Certificate.Loaded {
		t.Fatalf("unchanged negative cache key reparsed the pair: %+v", snapshot.Certificate)
	}

	renewedModTime := brokenModTime.Add(time.Second)
	setTestPairModTime(t, certPath, keyPath, renewedModTime)
	snapshot, err = e.Snapshot()
	if err != nil {
		t.Fatalf("renewed Snapshot: %v", err)
	}
	if !snapshot.Certificate.Loaded || snapshot.Certificate.NotAfter != renewedNotAfter.Unix() {
		t.Fatalf("mtime change did not invalidate the negative projection: %+v", snapshot.Certificate)
	}

	e.certs.mu.Lock()
	cached := e.certs.certificate
	e.certs.mu.Unlock()
	if cached != nil {
		t.Fatal("status projection caching populated the handshake cache")
	}
}

func TestCertificateStateReadsRenewalWithoutReplacingTheHandshakeCache(t *testing.T) {
	e, certPath, keyPath := newCertificateStateTestEngine(t)
	now := time.Now()
	oldNotAfter := now.Add(24 * time.Hour).Truncate(time.Second)
	writeTestLeafFor(
		t,
		certPath,
		keyPath,
		21,
		[]string{"*.first.example", "shared.example.com"},
		now.Add(-time.Hour),
		oldNotAfter,
	)
	cached, err := e.certs.currentCertificate()
	if err != nil {
		t.Fatalf("warm certificate cache: %v", err)
	}

	newNotAfter := now.Add(72 * time.Hour).Truncate(time.Second)
	writeTestLeafFor(
		t,
		certPath,
		keyPath,
		22,
		[]string{"*.first.example", "unused.example.com"},
		now.Add(-time.Hour),
		newNotAfter,
	)
	setTestPairModTime(t, certPath, keyPath, now.Add(2*time.Second))

	snapshot, err := e.Snapshot()
	if err != nil {
		t.Fatalf("Snapshot after renewal: %v", err)
	}
	if !snapshot.Certificate.Loaded || snapshot.Certificate.NotAfter != newNotAfter.Unix() {
		t.Fatalf("renewed certificate state = %+v", snapshot.Certificate)
	}
	if snapshot.Certificate.CoveredAll || len(snapshot.Certificate.Missing) != 1 || snapshot.Certificate.Missing[0] != "shared.example.com" {
		t.Fatalf("renewed certificate SAN gap = %+v, want only shared.example.com", snapshot.Certificate)
	}

	e.certs.mu.Lock()
	afterStatus := e.certs.certificate
	e.certs.mu.Unlock()
	if afterStatus != cached {
		t.Fatal("status replaced the handshake cache with an unadmitted renewal")
	}

	if err := os.WriteFile(certPath, []byte("broken certificate"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(certPath, now.Add(4*time.Second), now.Add(4*time.Second)); err != nil {
		t.Fatal(err)
	}
	snapshot, err = e.Snapshot()
	if err != nil {
		t.Fatalf("Snapshot during broken renewal: %v", err)
	}
	if snapshot.Certificate.Loaded || snapshot.Certificate.NotAfter != 0 || snapshot.Certificate.CoveredAll || len(snapshot.Certificate.Missing) != 0 {
		t.Fatalf("broken on-disk renewal was hidden by the hot cache: %+v", snapshot.Certificate)
	}

	e.certs.mu.Lock()
	afterBrokenStatus := e.certs.certificate
	e.certs.mu.Unlock()
	if afterBrokenStatus != cached {
		t.Fatal("reporting a broken on-disk renewal changed the handshake cache")
	}
}

func TestCertificateStateRejectsMissingAndBrokenColdPairs(t *testing.T) {
	tests := []struct {
		name  string
		setup func(*testing.T, string, string)
	}{
		{
			name:  "missing",
			setup: func(*testing.T, string, string) {},
		},
		{
			name: "malformed certificate",
			setup: func(t *testing.T, certPath, keyPath string) {
				if err := os.MkdirAll(filepath.Dir(certPath), 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(certPath, []byte("not a certificate"), 0o644); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(keyPath, []byte("not a key"), 0o600); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "mismatched private key",
			setup: func(t *testing.T, certPath, keyPath string) {
				now := time.Now()
				writeTestLeafFor(t, certPath, keyPath, 31, []string{"*.first.example", "shared.example.com"}, now.Add(-time.Hour), now.Add(time.Hour))
				otherCert := filepath.Join(filepath.Dir(certPath), "other.pem")
				otherKey := filepath.Join(filepath.Dir(keyPath), "other-key.pem")
				writeTestLeafFor(t, otherCert, otherKey, 32, []string{"other.example.com"}, now.Add(-time.Hour), now.Add(time.Hour))
				body, err := os.ReadFile(otherKey)
				if err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(keyPath, body, 0o600); err != nil {
					t.Fatal(err)
				}
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			e, certPath, keyPath := newCertificateStateTestEngine(t)
			tc.setup(t, certPath, keyPath)
			snapshot, err := e.Snapshot()
			if err != nil {
				t.Fatalf("Snapshot: %v", err)
			}
			if snapshot.Certificate.Loaded || snapshot.Certificate.NotAfter != 0 || snapshot.Certificate.CoveredAll || len(snapshot.Certificate.Missing) != 0 {
				t.Fatalf("broken cold pair state = %+v, want unloaded", snapshot.Certificate)
			}
		})
	}
}

func TestCertificateStateExposesExpiredLeafAndMissingSANs(t *testing.T) {
	e, certPath, keyPath := newCertificateStateTestEngine(t)
	now := time.Now()
	notAfter := now.Add(-time.Hour).Truncate(time.Second)
	writeTestLeafFor(
		t,
		certPath,
		keyPath,
		41,
		[]string{"*.first.example", "unused.example.com"},
		now.Add(-48*time.Hour),
		notAfter,
	)

	snapshot, err := e.Snapshot()
	if err != nil {
		t.Fatalf("Snapshot: %v", err)
	}
	if !snapshot.Certificate.Loaded {
		t.Fatal("a parseable expired leaf was hidden as unloaded")
	}
	if snapshot.Certificate.NotAfter != notAfter.Unix() {
		t.Fatalf("expired NotAfter = %d, want %d", snapshot.Certificate.NotAfter, notAfter.Unix())
	}
	if snapshot.Certificate.CoveredAll || len(snapshot.Certificate.Missing) != 1 || snapshot.Certificate.Missing[0] != "shared.example.com" {
		t.Fatalf("expired certificate SAN state = %+v", snapshot.Certificate)
	}
	if _, err := e.certs.currentCertificate(); err == nil {
		t.Fatal("status made an expired leaf admissible to the handshake path")
	}
}

func TestCertificateStateIsSafeAlongsideConcurrentHandshakes(t *testing.T) {
	e, certPath, keyPath := newCertificateStateTestEngine(t)
	now := time.Now()
	writeTestLeafFor(
		t,
		certPath,
		keyPath,
		51,
		[]string{"*.first.example", "shared.example.com"},
		now.Add(-time.Hour),
		now.Add(24*time.Hour),
	)
	hello := &tls.ClientHelloInfo{ServerName: "shared.example.com"}
	if _, err := e.certs.GetCertificate(hello); err != nil {
		t.Fatalf("warm certificate cache: %v", err)
	}

	errs := make(chan error, 1)
	report := func(err error) {
		select {
		case errs <- err:
		default:
		}
	}
	var wg sync.WaitGroup
	for worker := 0; worker < 12; worker++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for iteration := 0; iteration < 100; iteration++ {
				snapshot, err := e.Snapshot()
				if err != nil {
					report(fmt.Errorf("Snapshot: %w", err))
					return
				}
				if !snapshot.Certificate.Loaded || !snapshot.Certificate.CoveredAll {
					report(fmt.Errorf("unexpected certificate state: %+v", snapshot.Certificate))
					return
				}
				if _, err := e.certs.GetCertificate(hello); err != nil {
					report(fmt.Errorf("GetCertificate: %w", err))
					return
				}
			}
		}()
	}
	wg.Wait()
	select {
	case err := <-errs:
		t.Fatal(err)
	default:
	}
}
