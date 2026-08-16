package ca

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"sync"
	"time"

	C "github.com/metacubex/mihomo/constant"

	"github.com/metacubex/tls"
)

const tlsKeyPairReloadInterval = time.Second

type tlsFileIdentity struct {
	resolvedPath string
	info         os.FileInfo
}

type tlsKeyPairIdentity struct {
	certificate tlsFileIdentity
	privateKey  tlsFileIdentity
}

type tlsKeyPairFileLoader struct {
	mutex           sync.Mutex
	certificatePath string
	privateKeyPath  string
	certificate     *tls.Certificate
	nextCheck       time.Time
	checkInterval   time.Duration
	now             func() time.Time
}

// NewTLSKeyPairLoader creates a loader function for TLS key pairs from the provided certificate and private key data or file paths.
// If both certificate and privateKey are empty, generates a random TLS RSA key pair.
func NewTLSKeyPairLoader(certificate, privateKey string) (func() (*tls.Certificate, error), error) {
	if certificate == "" && privateKey == "" {
		var err error
		certificate, privateKey, _, err = NewRandomTLSKeyPair(KeyPairTypeRSA)
		if err != nil {
			return nil, err
		}
	}
	cert, painTextErr := tls.X509KeyPair([]byte(certificate), []byte(privateKey))
	if painTextErr == nil {
		return func() (*tls.Certificate, error) {
			return &cert, nil
		}, nil
	}

	certificate = C.Path.Resolve(certificate)
	privateKey = C.Path.Resolve(privateKey)
	var loadErr error
	if !C.Path.IsSafePath(certificate) {
		loadErr = C.Path.ErrNotSafePath(certificate)
	} else if !C.Path.IsSafePath(privateKey) {
		loadErr = C.Path.ErrNotSafePath(privateKey)
	}
	if loadErr != nil {
		return nil, fmt.Errorf("parse certificate failed, maybe format error:%s, or path error: %s", painTextErr.Error(), loadErr.Error())
	}
	loader, loadErr := newTLSKeyPairFileLoader(certificate, privateKey, tlsKeyPairReloadInterval, time.Now)
	if loadErr != nil {
		return nil, fmt.Errorf("parse certificate failed, maybe format error:%s, or path error: %s", painTextErr.Error(), loadErr.Error())
	}
	return loader.load, nil
}

func newTLSKeyPairFileLoader(certificate, privateKey string, checkInterval time.Duration, now func() time.Time) (*tlsKeyPairFileLoader, error) {
	cert, _, err := loadStableTLSKeyPair(certificate, privateKey)
	if err != nil {
		return nil, err
	}
	return &tlsKeyPairFileLoader{
		certificatePath: certificate,
		privateKeyPath:  privateKey,
		certificate:     cert,
		nextCheck:       now().Add(checkInterval),
		checkInterval:   checkInterval,
		now:             now,
	}, nil
}

func (l *tlsKeyPairFileLoader) load() (*tls.Certificate, error) {
	l.mutex.Lock()
	defer l.mutex.Unlock()

	now := l.now()
	if now.Before(l.nextCheck) {
		return l.certificate, nil
	}
	// Advance the deadline even when inspection or loading fails. A broken pair
	// must not turn every incoming handshake into filesystem I/O.
	l.nextCheck = now.Add(l.checkInterval)

	// Always attempt one stable load after the bounded interval. Metadata alone
	// cannot identify an in-place rewrite whose inode, size, and mtime were
	// preserved, while the resolved-path checks below are still needed for an
	// atomic parent-symlink generation switch.
	certificate, _, err := loadStableTLSKeyPair(l.certificatePath, l.privateKeyPath)
	if err == nil {
		// Certificates are immutable after parsing. Swapping the pointer keeps a
		// certificate already returned to another handshake safe to use.
		l.certificate = certificate
	}
	return l.certificate, nil
}

func loadStableTLSKeyPair(certificate, privateKey string) (*tls.Certificate, tlsKeyPairIdentity, error) {
	return loadStableTLSKeyPairWithInspector(certificate, privateKey, inspectTLSKeyPair)
}

func loadStableTLSKeyPairWithInspector(
	certificate, privateKey string,
	inspect func(string, string) (tlsKeyPairIdentity, error),
) (*tls.Certificate, tlsKeyPairIdentity, error) {
	var lastErr error
	for range 2 {
		before, err := inspect(certificate, privateKey)
		if err != nil {
			lastErr = err
			continue
		}
		// Load the concrete targets captured above. In particular, an atomic
		// parent-symlink switch cannot make the certificate and key opens land in
		// different generations.
		cert, err := tls.LoadX509KeyPair(before.certificate.resolvedPath, before.privateKey.resolvedPath)
		if err != nil {
			lastErr = err
			continue
		}
		after, err := inspect(certificate, privateKey)
		if err != nil {
			lastErr = err
			continue
		}
		if before.equal(after) {
			return &cert, after, nil
		}
		lastErr = fmt.Errorf("TLS certificate or private key changed while loading")
	}
	return nil, tlsKeyPairIdentity{}, lastErr
}

func inspectTLSKeyPair(certificate, privateKey string) (tlsKeyPairIdentity, error) {
	certificateIdentity, err := inspectTLSFile(certificate)
	if err != nil {
		return tlsKeyPairIdentity{}, err
	}
	privateKeyIdentity, err := inspectTLSFile(privateKey)
	if err != nil {
		return tlsKeyPairIdentity{}, err
	}
	return tlsKeyPairIdentity{certificate: certificateIdentity, privateKey: privateKeyIdentity}, nil
}

func inspectTLSFile(path string) (tlsFileIdentity, error) {
	resolvedPath, err := filepath.EvalSymlinks(path)
	if err != nil {
		return tlsFileIdentity{}, err
	}
	info, err := os.Stat(resolvedPath)
	if err != nil {
		return tlsFileIdentity{}, err
	}
	return tlsFileIdentity{resolvedPath: resolvedPath, info: info}, nil
}

func (i tlsKeyPairIdentity) equal(other tlsKeyPairIdentity) bool {
	return i.certificate.equal(other.certificate) && i.privateKey.equal(other.privateKey)
}

func (i tlsFileIdentity) equal(other tlsFileIdentity) bool {
	return i.resolvedPath == other.resolvedPath &&
		os.SameFile(i.info, other.info) &&
		i.info.Size() == other.info.Size() &&
		i.info.ModTime().Equal(other.info.ModTime())
}

func LoadCertificates(certificate string) (*x509.CertPool, error) {
	pool := x509.NewCertPool()
	if pool.AppendCertsFromPEM([]byte(certificate)) {
		return pool, nil
	}
	painTextErr := fmt.Errorf("invalid certificate: %s", certificate)

	certificate = C.Path.Resolve(certificate)
	var loadErr error
	if !C.Path.IsSafePath(certificate) {
		loadErr = C.Path.ErrNotSafePath(certificate)
	} else {
		certPEMBlock, err := os.ReadFile(certificate)
		if pool.AppendCertsFromPEM(certPEMBlock) {
			return pool, nil
		}
		loadErr = err
	}
	if loadErr != nil {
		return nil, fmt.Errorf("parse certificate failed, maybe format error:%s, or path error: %s", painTextErr.Error(), loadErr.Error())
	}
	//TODO: support dynamic update pool too
	//      blocked by: https://github.com/golang/go/issues/64796
	//      maybe we can direct add `GetRootCAs` and `GetClientCAs` to ourselves tls fork
	return pool, nil
}

type KeyPairType string

const (
	KeyPairTypeRSA     KeyPairType = "rsa"
	KeyPairTypeP256    KeyPairType = "p256"
	KeyPairTypeP384    KeyPairType = "p384"
	KeyPairTypeEd25519 KeyPairType = "ed25519"
)

// NewRandomTLSKeyPair generates a random TLS key pair based on the specified KeyPairType and returns it with a SHA256 fingerprint.
// Note: Most browsers do not support KeyPairTypeEd25519 type of certificate, and utls.UConn will also reject this type of certificate.
func NewRandomTLSKeyPair(keyPairType KeyPairType) (certificate string, privateKey string, fingerprint string, err error) {
	var key crypto.Signer
	switch keyPairType {
	case KeyPairTypeRSA:
		key, err = rsa.GenerateKey(rand.Reader, 2048)
	case KeyPairTypeP256:
		key, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	case KeyPairTypeP384:
		key, err = ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	case KeyPairTypeEd25519:
		_, key, err = ed25519.GenerateKey(rand.Reader)
	default: // fallback to KeyPairTypeRSA
		key, err = rsa.GenerateKey(rand.Reader, 2048)
	}
	if err != nil {
		return
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		NotBefore:    time.Now().Add(-time.Hour * 24 * 365),
		NotAfter:     time.Now().Add(time.Hour * 24 * 365),
	}
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, key.Public(), key)
	if err != nil {
		return
	}
	privBytes, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return
	}
	fingerprint = CalculateFingerprint(certDER)
	privateKey = string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privBytes}))
	certificate = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER}))
	return
}
