package engine

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/metacubex/tls"
)

const (
	certificateStateName             = "cert-state"
	certificateStateVersion          = 1
	certificateRuntimeRefresh        = 250 * time.Millisecond
	maxCertificateMaterialFile int64 = 4 << 20
)

type certificateResult struct {
	Version           int    `json:"version"`
	TargetDigest      string `json:"target_digest"`
	Attempt           string `json:"attempt"`
	Status            string `json:"status"`
	CertificateSHA256 string `json:"certificate_sha256,omitempty"`
	PrivateKeySHA256  string `json:"private_key_sha256,omitempty"`
	Code              string `json:"code,omitempty"`
	Message           string `json:"message,omitempty"`
}

// CertificateRuntimeState is derived from the desired document, the current
// request, the root publisher's commit record and the exact keypair bytes. It
// is never persisted in the interception document.
type CertificateRuntimeState struct {
	Ready        bool   `json:"ready"`
	Status       string `json:"status"`
	TargetDigest string `json:"target_digest,omitempty"`
	Attempt      string `json:"attempt,omitempty"`
	ErrorCode    string `json:"error_code,omitempty"`
	ErrorMessage string `json:"error_message,omitempty"`
}

type certificateRuntimePlan struct {
	state       CertificateRuntimeState
	generation  string
	certificate *tls.Certificate
}

type certificateRuntimeCache struct {
	set              bool
	configGeneration uint64
	checkedAt        time.Time
	plan             certificateRuntimePlan
}

func certificateStatePath(cfg Config) string {
	return filepath.Join(filepath.Dir(filepath.Dir(cfg.TLSCert)), certificateStateName)
}

func (s *certificateStore) runtimeNowTime() time.Time {
	if s != nil && s.runtimeNow != nil {
		return s.runtimeNow()
	}
	return time.Now()
}

func (s *certificateStore) invalidateRuntimePlan() {
	if s == nil {
		return
	}
	s.runtimeMu.Lock()
	s.runtimeCache = certificateRuntimeCache{}
	s.runtimeMu.Unlock()
}

func (s *certificateStore) runtimePlan(cfg Config) certificateRuntimePlan {
	if s == nil {
		return certificateRuntimePlan{state: CertificateRuntimeState{
			Ready: true, Status: "ready", TargetDigest: certificateDigest(cfg),
		}}
	}
	// Unit-assembled engines do not have a control-file root. Production always
	// constructs its store from a non-empty config path before publication.
	if s.config == nil || s.config.path == "" {
		return certificateRuntimePlan{state: CertificateRuntimeState{
			Ready: true, Status: "ready", TargetDigest: certificateDigest(cfg),
		}}
	}

	now := s.runtimeNowTime()
	s.runtimeMu.Lock()
	defer s.runtimeMu.Unlock()
	ttl := s.runtimeTTL
	if ttl == 0 {
		ttl = certificateRuntimeRefresh
	}
	if s.runtimeCache.set && s.runtimeCache.configGeneration == cfg.generation &&
		ttl > 0 && !now.Before(s.runtimeCache.checkedAt) && now.Sub(s.runtimeCache.checkedAt) < ttl {
		plan := s.runtimeCache.plan
		if !plan.state.Ready || plan.certificate == nil ||
			validateInterceptLeafValidity(plan.certificate.Leaf, now) == nil {
			return plan
		}
	}
	plan := s.loadRuntimePlan(cfg, now)
	s.runtimeCache = certificateRuntimeCache{
		set: true, configGeneration: cfg.generation, checkedAt: now, plan: plan,
	}
	return plan
}

func (s *certificateStore) loadRuntimePlan(cfg Config, now time.Time) certificateRuntimePlan {
	targetDigest := certificateDigest(cfg)
	pending := func(attempt string) certificateRuntimePlan {
		return certificateRuntimePlan{state: CertificateRuntimeState{
			Status: "pending", TargetDigest: targetDigest, Attempt: attempt,
		}}
	}
	failure := func(attempt, code, message string) certificateRuntimePlan {
		return certificateRuntimePlan{state: CertificateRuntimeState{
			Status: "error", TargetDigest: targetDigest, Attempt: attempt,
			ErrorCode: code, ErrorMessage: message,
		}}
	}

	request, err := readCertificateRequest(certificateRequestPath(s.config.path))
	if err != nil || request.TargetDigest != targetDigest ||
		!equalStrings(request.Hosts, certificateHostPatterns(cfg)) {
		return pending("")
	}
	result, err := readCertificateResult(certificateStatePath(cfg))
	if errors.Is(err, os.ErrNotExist) {
		return pending(request.Attempt)
	}
	if err != nil {
		return failure(request.Attempt, "invalid_certificate_state", "The certificate publisher state is invalid.")
	}
	if result.TargetDigest != request.TargetDigest || result.Attempt != request.Attempt {
		return pending(request.Attempt)
	}
	if result.Status == "error" {
		return failure(request.Attempt, result.Code, result.Message)
	}
	if !result.readyShapeMatches(len(request.Hosts) == 0) {
		return failure(request.Attempt, "invalid_certificate_state", "The certificate publisher state does not match the requested host set.")
	}
	if len(request.Hosts) == 0 {
		return certificateRuntimePlan{state: CertificateRuntimeState{
			Ready: true, Status: "ready", TargetDigest: targetDigest, Attempt: request.Attempt,
		}, generation: runtimePlanGeneration(cfg, targetDigest, request.Attempt, "empty", "")}
	}

	certificateRaw, err := readBoundedMaterialFile(cfg.TLSCert)
	if err != nil {
		return failure(request.Attempt, "certificate_unavailable", "The interception certificate is unavailable.")
	}
	keyRaw, err := readBoundedMaterialFile(cfg.TLSKey)
	if err != nil {
		return failure(request.Attempt, "private_key_unavailable", "The interception private key is unavailable.")
	}
	certificateDigestValue := sha256Hex(certificateRaw)
	keyDigestValue := sha256Hex(keyRaw)
	if certificateDigestValue != result.CertificateSHA256 || keyDigestValue != result.PrivateKeySHA256 {
		return failure(request.Attempt, "certificate_pair_torn", "The interception certificate pair does not match its commit record.")
	}
	certificate, err := tls.X509KeyPair(certificateRaw, keyRaw)
	if err != nil || len(certificate.Certificate) == 0 {
		return failure(request.Attempt, "certificate_pair_invalid", "The interception certificate and private key do not form a valid pair.")
	}
	leaf, err := x509.ParseCertificate(certificate.Certificate[0])
	if err != nil {
		return failure(request.Attempt, "certificate_invalid", "The interception leaf certificate is invalid.")
	}
	if err := validateInterceptLeaf(leaf, request.Hosts, now); err != nil {
		return failure(request.Attempt, "certificate_not_ready", "The interception leaf is invalid, expired, or does not cover every requested host.")
	}
	certificate.Leaf = leaf
	generation := runtimePlanGeneration(cfg, targetDigest, request.Attempt, certificateDigestValue, keyDigestValue)
	return certificateRuntimePlan{
		state: CertificateRuntimeState{
			Ready: true, Status: "ready", TargetDigest: targetDigest, Attempt: request.Attempt,
		},
		generation: generation, certificate: &certificate,
	}
}

func runtimePlanGeneration(cfg Config, targetDigest, attempt, certificateDigestValue, keyDigestValue string) string {
	return digestText(strings.Join([]string{
		fmt.Sprintf("%d", cfg.generation), targetDigest, attempt, certificateDigestValue, keyDigestValue,
	}, "\n") + "\n")
}

func readCertificateResult(path string) (certificateResult, error) {
	raw, err := readBoundedControlFile(path)
	if err != nil {
		return certificateResult{}, err
	}
	var result certificateResult
	if err := decodeStrictCertificateJSON(raw, &result); err != nil {
		return certificateResult{}, err
	}
	if result.Version != certificateStateVersion || !validLowerHex(result.TargetDigest, 64) ||
		!validLowerHex(result.Attempt, certificateAttemptBytes*2) {
		return certificateResult{}, errors.New("invalid certificate state identity")
	}
	switch result.Status {
	case "ready":
		if result.Code != "" || result.Message != "" {
			return certificateResult{}, errors.New("ready certificate state contains an error")
		}
		certificateEmpty := result.CertificateSHA256 == ""
		keyEmpty := result.PrivateKeySHA256 == ""
		if certificateEmpty != keyEmpty {
			return certificateResult{}, errors.New("ready certificate state has only one material hash")
		}
		if !certificateEmpty && (!validLowerHex(result.CertificateSHA256, 64) || !validLowerHex(result.PrivateKeySHA256, 64)) {
			return certificateResult{}, errors.New("ready certificate state has invalid material hashes")
		}
	case "error":
		if result.CertificateSHA256 != "" || result.PrivateKeySHA256 != "" ||
			!validCertificateErrorCode(result.Code) || !validCertificateErrorMessage(result.Message) {
			return certificateResult{}, errors.New("invalid certificate error state")
		}
	default:
		return certificateResult{}, errors.New("invalid certificate state status")
	}
	return result, nil
}

func (r certificateResult) readyShapeMatches(emptyTarget bool) bool {
	if r.Status != "ready" {
		return true
	}
	hasMaterial := r.CertificateSHA256 != "" && r.PrivateKeySHA256 != ""
	return hasMaterial != emptyTarget
}

func validCertificateErrorCode(code string) bool {
	if len(code) == 0 || len(code) > 64 || code[0] < 'a' || code[0] > 'z' {
		return false
	}
	for _, char := range code[1:] {
		if char != '_' && (char < 'a' || char > 'z') && (char < '0' || char > '9') {
			return false
		}
	}
	return true
}

func validCertificateErrorMessage(message string) bool {
	if message == "" || len(message) > 512 || !utf8.ValidString(message) {
		return false
	}
	for _, char := range message {
		if char == '\r' || char == '\n' || char < 0x20 || char == 0x7f {
			return false
		}
	}
	return true
}

func readBoundedMaterialFile(path string) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	raw, err := io.ReadAll(io.LimitReader(file, maxCertificateMaterialFile+1))
	if err != nil {
		return nil, err
	}
	if int64(len(raw)) > maxCertificateMaterialFile {
		return nil, fmt.Errorf("certificate material exceeds %d bytes", maxCertificateMaterialFile)
	}
	return raw, nil
}

func sha256Hex(raw []byte) string {
	digest := sha256.Sum256(raw)
	return hex.EncodeToString(digest[:])
}

func (s *certificateStore) certificateForHello(hello *tls.ClientHelloInfo) (*tls.Certificate, string, error) {
	if s == nil || hello == nil {
		return nil, "", errors.New("unrecognized interception SNI")
	}
	cfg, err := s.config.Current()
	host := canonicalHost(hello.ServerName)
	if err != nil || host == "" || !activeInterceptHost(cfg, host) {
		return nil, "", errors.New("unrecognized interception SNI")
	}
	plan := s.runtimePlan(cfg)
	if !plan.state.Ready || plan.certificate == nil || plan.certificate.Leaf == nil {
		return nil, "", errors.New("interception certificate is not ready")
	}
	if err := validateInterceptLeafValidity(plan.certificate.Leaf, s.runtimeNowTime()); err != nil {
		s.invalidateRuntimePlan()
		return nil, "", err
	}
	if err := plan.certificate.Leaf.VerifyHostname(host); err != nil {
		return nil, "", fmt.Errorf("interception certificate does not cover SNI %s: %w", host, err)
	}
	return plan.certificate, plan.generation, nil
}

// CertificateRuntimeState reports the current derived certificate commit. A
// read may be up to certificateRuntimeRefresh old; handshakes repeat validity
// and per-SNI checks even while that bounded cache is hot.
func (e *Engine) CertificateRuntimeState() CertificateRuntimeState {
	if e == nil || e.config == nil {
		return CertificateRuntimeState{Status: "error", ErrorCode: "interception_unavailable", ErrorMessage: "The interception engine is unavailable."}
	}
	cfg, err := e.config.Current()
	if err != nil {
		return CertificateRuntimeState{Status: "error", ErrorCode: "configuration_unavailable", ErrorMessage: "The interception configuration is unavailable."}
	}
	return e.certificateRuntimeStateForConfig(cfg)
}

func (e *Engine) certificateRuntimeStateForConfig(cfg Config) CertificateRuntimeState {
	if e.certs == nil {
		return CertificateRuntimeState{Ready: true, Status: "ready", TargetDigest: certificateDigest(cfg)}
	}
	return e.certs.runtimePlan(cfg).state
}

func (e *Engine) certificateRuntimeReady(cfg Config) bool {
	return e == nil || e.certs == nil || e.certs.runtimePlan(cfg).state.Ready
}
