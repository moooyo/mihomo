package engine

import (
	"crypto/x509"
	"errors"
	"fmt"
	"github.com/metacubex/tls"
	"log"
	"os"
	"strings"
	"sync"
	"time"
)

type certificateStore struct {
	config *configStore

	mu          sync.Mutex
	certPath    string
	keyPath     string
	certModTime time.Time
	keyModTime  time.Time
	certificate *tls.Certificate

	// Status loading is deliberately independent from the handshake cache.
	// Parsing a private key for a Console poll must never hold up a handshake.
	statusMu    sync.Mutex
	statusCache certificateStatusCache
}

// certificateStatus is the immutable part of a leaf that the control plane
// needs. Keeping tls.Certificate out of this projection matters: callers must
// not be able to mutate the certificate concurrently with a handshake.
type certificateStatus struct {
	notAfter time.Time
	dnsNames []string
}

type certificateStatusCache struct {
	set         bool
	certPath    string
	keyPath     string
	certModTime time.Time
	keyModTime  time.Time
	loaded      bool
	status      certificateStatus
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
// /gpn/interception route answered 503, including the review that installing a
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
	if hello == nil {
		return nil, errors.New("unrecognized interception SNI")
	}
	cfg, err := s.config.Current()
	if err != nil || !activeInterceptHost(cfg, hello.ServerName) {
		return nil, errors.New("unrecognized interception SNI")
	}
	return s.currentCertificate()
}

// status returns the leaf currently represented by the store without going
// through GetCertificate. The handshake callback deliberately rejects a nil
// ClientHelloInfo before it resolves anything; inventing one here would bypass
// the SNI authorization boundary and make a status read look like a handshake.
//
// The projection has its own path-and-mtime cache and mutex. A Console poll can
// therefore parse a cold or renewed pair without holding the handshake mutex,
// while repeated polls of unchanged files pay only the stat calls and a slice
// copy. Parse failures are cached too when both files could be statted. Unlike
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

	certInfo, err := os.Stat(cfg.TLSCert)
	if err != nil {
		s.statusCache = certificateStatusCache{}
		return certificateStatus{}, false
	}
	keyInfo, err := os.Stat(cfg.TLSKey)
	if err != nil {
		s.statusCache = certificateStatusCache{}
		return certificateStatus{}, false
	}
	if s.statusCache.matches(cfg.TLSCert, cfg.TLSKey, certInfo.ModTime(), keyInfo.ModTime()) {
		return s.statusCache.result()
	}

	certificate, err := tls.LoadX509KeyPair(cfg.TLSCert, cfg.TLSKey)
	if err != nil {
		return s.cacheStatusLocked(cfg.TLSCert, cfg.TLSKey, certInfo.ModTime(), keyInfo.ModTime(), certificateStatus{}, false)
	}
	status, loaded := statusFromCertificate(&certificate)
	return s.cacheStatusLocked(cfg.TLSCert, cfg.TLSKey, certInfo.ModTime(), keyInfo.ModTime(), status, loaded)
}

func (c certificateStatusCache) matches(certPath, keyPath string, certModTime, keyModTime time.Time) bool {
	return c.set && c.certPath == certPath && c.keyPath == keyPath &&
		c.certModTime.Equal(certModTime) && c.keyModTime.Equal(keyModTime)
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
	certModTime time.Time,
	keyModTime time.Time,
	status certificateStatus,
	loaded bool,
) (certificateStatus, bool) {
	s.statusCache = certificateStatusCache{
		set:         true,
		certPath:    certPath,
		keyPath:     keyPath,
		certModTime: certModTime,
		keyModTime:  keyModTime,
		loaded:      loaded,
		status:      status.clone(),
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
	certInfo, err := os.Stat(cfg.TLSCert)
	if err != nil {
		return s.staleOrError(fmt.Errorf("stat TLS certificate: %w", err))
	}
	keyInfo, err := os.Stat(cfg.TLSKey)
	if err != nil {
		return s.staleOrError(fmt.Errorf("stat TLS private key: %w", err))
	}
	if s.certificate != nil && s.certPath == cfg.TLSCert && s.keyPath == cfg.TLSKey &&
		certInfo.ModTime().Equal(s.certModTime) && keyInfo.ModTime().Equal(s.keyModTime) {
		// The cache key is the file's mtime, and one of the checks below is not a
		// property of the file: leaf validity is a property of the clock. Serving
		// the cached leaf without re-checking it meant that once renewal had
		// failed for long enough -- 397-day leaves, RENEW_BEFORE of 30 days and a
		// daily timer, so 30 consecutive failures -- this process would present an
		// expired certificate to every client indefinitely, and the SOCKS probe
		// checkInterceptHealth performs cannot see it.
		if err := validateInterceptLeafValidity(s.certificate.Leaf, time.Now()); err == nil {
			return s.certificate, nil
		}
		// Do not fall back to it either: staleOrError retains the last valid leaf
		// for a transient read failure, and an expired leaf is not that. Dropping
		// it makes the reload below authoritative, and if the file on disk is the
		// same expired one the error surfaces instead of the certificate.
		log.Print("intercept: the cached interception leaf is no longer within its validity window; reloading")
		s.certificate = nil
	}
	certificate, err := tls.LoadX509KeyPair(cfg.TLSCert, cfg.TLSKey)
	if err != nil {
		return s.staleOrError(fmt.Errorf("load TLS keypair: %w", err))
	}
	if len(certificate.Certificate) == 0 {
		return s.staleOrError(errors.New("TLS keypair contains no certificate"))
	}
	leaf, err := x509.ParseCertificate(certificate.Certificate[0])
	if err != nil {
		return s.staleOrError(fmt.Errorf("parse TLS leaf certificate: %w", err))
	}
	if err := validateInterceptLeaf(leaf, certificateHostPatterns(cfg), time.Now()); err != nil {
		return s.staleOrError(err)
	}
	certificate.Leaf = leaf
	s.certPath = cfg.TLSCert
	s.keyPath = cfg.TLSKey
	s.certModTime = certInfo.ModTime()
	s.keyModTime = keyInfo.ModTime()
	s.certificate = &certificate
	return s.certificate, nil
}

func (s *certificateStore) staleOrError(err error) (*tls.Certificate, error) {
	if s.certificate == nil {
		return nil, err
	}
	log.Printf("intercept: certificate reload failed; retaining the last valid leaf: %v", err)
	return s.certificate, nil
}

// validateInterceptLeafValidity is the one check in validateInterceptLeaf that
// depends on the clock rather than on the file, so it is the one a cache keyed
// on the file's mtime has to repeat.
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
