package engine

import (
	"crypto/x509"
	"errors"
	"fmt"
	"github.com/metacubex/tls"
	"strings"
	"sync"
	"time"
)

type certificateStore struct {
	config *configStore

	mu          sync.Mutex
	certPath    string
	keyPath     string
	certHash    string
	keyHash     string
	certificate *tls.Certificate

	// Status loading is deliberately independent from the handshake cache.
	// Parsing a private key for a Console poll must never hold up a handshake.
	statusMu    sync.Mutex
	statusCache certificateStatusCache

	runtimeMu    sync.Mutex
	runtimeCache certificateRuntimeCache
	runtimeTTL   time.Duration
	runtimeNow   func() time.Time
}

// certificateStatus is the immutable part of a leaf that the control plane
// needs. Keeping tls.Certificate out of this projection matters: callers must
// not be able to mutate the certificate concurrently with a handshake.
type certificateStatus struct {
	notAfter time.Time
	dnsNames []string
}

type certificateStatusCache struct {
	set      bool
	certPath string
	keyPath  string
	certHash string
	keyHash  string
	loaded   bool
	status   certificateStatus
}

// newCertificateStore prepares the leaf source. It cannot fail, and that is the
// point: constructing a source of certificates is not the same act as resolving
// one, and only the second can be refused.
//
// This used to load the leaf eagerly and refuse to build without it. A gateway
// with no enabled extension has requested no capture hosts, so the root oneshot
// has minted no leaf, so there is no file to load -- an interception authority
// of zero extent, not a broken engine. Refusing to construct made the two
// indistinguishable, and the consequence was a deadlock: every
// /5gpn/interception route answered 503, including the review that installing a
// first extension has to begin with, so a fresh gateway could never enable one.
//
// Resolution stays where it always was, in currentCertificate, which every
// handshake already calls and which already reports a missing pair. A capture
// with no leaf to present fails that handshake. It no longer stops the engine
// from existing.
func newCertificateStore(config *configStore) *certificateStore {
	return &certificateStore{config: config}
}

func (s *certificateStore) GetCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	certificate, _, err := s.certificateForHello(hello)
	return certificate, err
}

// status returns the leaf currently represented by the store without going
// through GetCertificate. The handshake callback deliberately rejects a nil
// ClientHelloInfo before it resolves anything; inventing one here would bypass
// the SNI authorization boundary and make a status read look like a handshake.
//
// The projection has its own path-and-content cache and mutex. A Console poll can
// therefore parse a cold or renewed pair without holding the handshake mutex,
// while repeated polls of unchanged bytes pay only the bounded reads, hashes
// and a slice copy. Parse failures are cached too. Unlike
// currentCertificate, status does not retain the last-loaded leaf after a read
// failure: this status is explicitly about the current files, and a broken
// renewal must look the same whether or not a handshake happened before it.
// Expiry and SAN coverage are intentionally not admission checks here: they are
// the facts the caller needs in order to report an expired or under-covering
// leaf.
func (s *certificateStore) status(cfg Config) (certificateStatus, bool) {
	if s == nil {
		return certificateStatus{}, false
	}

	s.statusMu.Lock()
	defer s.statusMu.Unlock()

	certificateRaw, err := readBoundedMaterialFile(cfg.TLSCert)
	if err != nil {
		s.statusCache = certificateStatusCache{}
		return certificateStatus{}, false
	}
	keyRaw, err := readBoundedMaterialFile(cfg.TLSKey)
	if err != nil {
		s.statusCache = certificateStatusCache{}
		return certificateStatus{}, false
	}
	certHash := sha256Hex(certificateRaw)
	keyHash := sha256Hex(keyRaw)
	if s.statusCache.matches(cfg.TLSCert, cfg.TLSKey, certHash, keyHash) {
		return s.statusCache.result()
	}

	certificate, err := tls.X509KeyPair(certificateRaw, keyRaw)
	if err != nil {
		return s.cacheStatusLocked(cfg.TLSCert, cfg.TLSKey, certHash, keyHash, certificateStatus{}, false)
	}
	status, loaded := statusFromCertificate(&certificate)
	return s.cacheStatusLocked(cfg.TLSCert, cfg.TLSKey, certHash, keyHash, status, loaded)
}

func (c certificateStatusCache) matches(certPath, keyPath, certHash, keyHash string) bool {
	return c.set && c.certPath == certPath && c.keyPath == keyPath &&
		c.certHash == certHash && c.keyHash == keyHash
}

func (c certificateStatusCache) result() (certificateStatus, bool) {
	if !c.loaded {
		return certificateStatus{}, false
	}
	return c.status.clone(), true
}

func (s *certificateStore) cacheStatusLocked(
	certPath string,
	keyPath string,
	certHash string,
	keyHash string,
	status certificateStatus,
	loaded bool,
) (certificateStatus, bool) {
	s.statusCache = certificateStatusCache{
		set:      true,
		certPath: certPath,
		keyPath:  keyPath,
		certHash: certHash,
		keyHash:  keyHash,
		loaded:   loaded,
		status:   status.clone(),
	}
	return s.statusCache.result()
}

func (s certificateStatus) clone() certificateStatus {
	return certificateStatus{
		notAfter: s.notAfter,
		dnsNames: append([]string(nil), s.dnsNames...),
	}
}

func statusFromCertificate(certificate *tls.Certificate) (certificateStatus, bool) {
	if certificate == nil {
		return certificateStatus{}, false
	}
	leaf := certificate.Leaf
	if leaf == nil {
		if len(certificate.Certificate) == 0 {
			return certificateStatus{}, false
		}
		var err error
		leaf, err = x509.ParseCertificate(certificate.Certificate[0])
		if err != nil {
			return certificateStatus{}, false
		}
	}
	if leaf.IsCA {
		return certificateStatus{}, false
	}
	return certificateStatus{
		notAfter: leaf.NotAfter,
		dnsNames: append([]string(nil), leaf.DNSNames...),
	}, true
}

func (s *certificateStore) currentCertificate() (*tls.Certificate, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	cfg, err := s.config.Current()
	if err != nil {
		return nil, err
	}
	certificateRaw, err := readBoundedMaterialFile(cfg.TLSCert)
	if err != nil {
		s.certificate = nil
		return nil, fmt.Errorf("read TLS certificate: %w", err)
	}
	keyRaw, err := readBoundedMaterialFile(cfg.TLSKey)
	if err != nil {
		s.certificate = nil
		return nil, fmt.Errorf("read TLS private key: %w", err)
	}
	certHash := sha256Hex(certificateRaw)
	keyHash := sha256Hex(keyRaw)
	if s.certificate != nil && s.certPath == cfg.TLSCert && s.keyPath == cfg.TLSKey &&
		s.certHash == certHash && s.keyHash == keyHash {
		// The cache key covers file changes, not the passage of time. Revalidate
		// the cached leaf against the wall clock even when both hashes match, so an
		// unchanged certificate cannot remain on the fast path after it expires.
		if err := validateInterceptLeafValidity(s.certificate.Leaf, time.Now()); err == nil {
			return s.certificate, nil
		}
		s.certificate = nil
	}
	certificate, err := tls.X509KeyPair(certificateRaw, keyRaw)
	if err != nil {
		s.certificate = nil
		return nil, fmt.Errorf("load TLS keypair: %w", err)
	}
	if len(certificate.Certificate) == 0 {
		s.certificate = nil
		return nil, errors.New("TLS keypair contains no certificate")
	}
	leaf, err := x509.ParseCertificate(certificate.Certificate[0])
	if err != nil {
		s.certificate = nil
		return nil, fmt.Errorf("parse TLS leaf certificate: %w", err)
	}
	if err := validateInterceptLeaf(leaf, certificateHostPatterns(cfg), time.Now()); err != nil {
		s.certificate = nil
		return nil, err
	}
	certificate.Leaf = leaf
	s.certPath = cfg.TLSCert
	s.keyPath = cfg.TLSKey
	s.certHash = certHash
	s.keyHash = keyHash
	s.certificate = &certificate
	return s.certificate, nil
}

// validateInterceptLeafValidity is the one check in validateInterceptLeaf that
// depends on the clock rather than on the file, so it is the one a cache keyed
// on the file's content has to repeat.
func validateInterceptLeafValidity(leaf *x509.Certificate, now time.Time) error {
	if leaf == nil {
		return errors.New("missing TLS leaf certificate")
	}
	if now.Before(leaf.NotBefore) || !now.Before(leaf.NotAfter) {
		return errors.New("interception TLS leaf certificate is not currently valid")
	}
	return nil
}

func validateInterceptLeaf(leaf *x509.Certificate, requiredHosts []string, now time.Time) error {
	if leaf == nil {
		return errors.New("missing TLS leaf certificate")
	}
	if leaf.IsCA {
		return errors.New("interception runtime must not receive a CA certificate")
	}
	if err := validateInterceptLeafValidity(leaf, now); err != nil {
		return err
	}
	for _, host := range requiredHosts {
		probe := host
		if strings.HasPrefix(probe, "*.") {
			probe = "probe." + strings.TrimPrefix(probe, "*.")
		}
		if err := leaf.VerifyHostname(probe); err != nil {
			return fmt.Errorf("interception TLS certificate does not cover %s: %w", host, err)
		}
	}
	return nil
}
