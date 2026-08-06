package engine

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/metacubex/mihomo/5gpn/state"
)

const (
	certificateRequestName    = "certificate-request"
	certificateRequestVersion = 1
	certificateAttemptBytes   = 16
	maxCertificateControlFile = 256 << 10
)

var (
	ErrCertificateRetryConflict = errors.New("certificate retry identity is stale")
	ErrCertificateAlreadyReady  = errors.New("certificate request is already ready")
)

// certificateRequest is the complete unprivileged-to-root certificate
// protocol. The random attempt token fences concurrent A -> B -> C updates and
// explicit retries without turning runtime readiness into persisted config.
type certificateRequest struct {
	Version      int      `json:"version"`
	TargetDigest string   `json:"target_digest"`
	Attempt      string   `json:"attempt"`
	Hosts        []string `json:"hosts"`
}

func certificateRequestPath(configPath string) string {
	return filepath.Join(filepath.Dir(configPath), certificateRequestName)
}

func desiredCertificateRequest(cfg Config, attempt string) certificateRequest {
	hosts := certificateHostPatterns(cfg)
	return certificateRequest{
		Version:      certificateRequestVersion,
		TargetDigest: certificateDigest(cfg),
		Attempt:      attempt,
		Hosts:        append(make([]string, 0, len(hosts)), hosts...),
	}
}

func publishCertificateRequest(configPath string, cfg Config) error {
	request, err := nextCertificateRequest(certificateRequestPath(configPath), cfg, false)
	if err != nil {
		return fmt.Errorf("5gpn/engine: prepare certificate request: %w", err)
	}
	if err := writeCertificateRequest(certificateRequestPath(configPath), request); err != nil {
		return fmt.Errorf("5gpn/engine: publish certificate request: %w", err)
	}
	return nil
}

func writeCertificateRequest(path string, request certificateRequest) error {
	raw, err := json.Marshal(request)
	if err != nil {
		return err
	}
	return state.WritePublicFile(path, raw)
}

func nextCertificateRequest(path string, cfg Config, forceNewAttempt bool) (certificateRequest, error) {
	desired := desiredCertificateRequest(cfg, "")
	if !forceNewAttempt && path != "" {
		if current, err := readCertificateRequest(path); err == nil &&
			current.TargetDigest == desired.TargetDigest && equalStrings(current.Hosts, desired.Hosts) {
			desired.Attempt = current.Attempt
			return desired, nil
		}
	}
	attempt, err := newCertificateAttempt()
	if err != nil {
		return certificateRequest{}, err
	}
	desired.Attempt = attempt
	return desired, nil
}

func newCertificateAttempt() (string, error) {
	var attempt [certificateAttemptBytes]byte
	if _, err := io.ReadFull(rand.Reader, attempt[:]); err != nil {
		return "", fmt.Errorf("generate certificate attempt: %w", err)
	}
	return hex.EncodeToString(attempt[:]), nil
}

func readCertificateRequest(path string) (certificateRequest, error) {
	raw, err := readBoundedControlFile(path)
	if err != nil {
		return certificateRequest{}, err
	}
	var request certificateRequest
	if err := decodeStrictCertificateJSON(raw, &request); err != nil {
		return certificateRequest{}, err
	}
	if request.Version != certificateRequestVersion {
		return certificateRequest{}, errors.New("unsupported certificate request version")
	}
	if !validLowerHex(request.TargetDigest, 64) {
		return certificateRequest{}, errors.New("invalid certificate request target digest")
	}
	if !validLowerHex(request.Attempt, certificateAttemptBytes*2) {
		return certificateRequest{}, errors.New("invalid certificate request attempt")
	}
	if request.Hosts == nil || len(request.Hosts) > maxCertificateHosts ||
		!equalStrings(request.Hosts, uniqueSorted(request.Hosts)) {
		return certificateRequest{}, errors.New("invalid certificate request hosts")
	}
	for _, host := range request.Hosts {
		if !validHostPattern(host) {
			return certificateRequest{}, errors.New("invalid certificate request host")
		}
	}
	return request, nil
}

func readBoundedControlFile(path string) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	raw, err := io.ReadAll(io.LimitReader(file, maxCertificateControlFile+1))
	if err != nil {
		return nil, err
	}
	if len(raw) > maxCertificateControlFile {
		return nil, errors.New("certificate control file is too large")
	}
	return raw, nil
}

func decodeStrictCertificateJSON(raw []byte, destination any) error {
	if err := rejectDuplicateJSONKeys(raw); err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return err
	}
	return requireJSONEOF(decoder)
}

func validLowerHex(value string, size int) bool {
	if len(value) != size {
		return false
	}
	for _, char := range value {
		if char < '0' || char > '9' {
			if char < 'a' || char > 'f' {
				return false
			}
		}
	}
	return true
}

func equalStrings(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

// RetryCertificateRequest republishes a publisher-reported error under a fresh
// attempt token. The caller must quote both current identities. A pending
// request is idempotent, a ready request is refused, and the config-store lock
// makes the identity check and publication one CAS with document updates.
func (e *Engine) RetryCertificateRequest(expectedRevision, expectedTargetDigest, expectedAttempt string) (Snapshot, string, error) {
	if e == nil || e.config == nil {
		return Snapshot{}, "", errors.New("5gpn/engine: interception is unavailable")
	}
	var snapshot Snapshot
	var currentRevision string
	err := e.config.WithCurrentLocked(func(cfg Config, revision string) error {
		currentRevision = revision
		var snapshotErr error
		snapshot, snapshotErr = e.SnapshotFromConfig(cfg)
		if snapshotErr != nil {
			return snapshotErr
		}
		if expectedRevision == "" || expectedRevision != revision {
			return state.ErrRevisionConflict
		}
		current, err := readCertificateRequest(certificateRequestPath(e.config.path))
		if err != nil || current.TargetDigest != certificateDigest(cfg) ||
			!equalStrings(current.Hosts, certificateHostPatterns(cfg)) ||
			expectedTargetDigest != current.TargetDigest || expectedAttempt != current.Attempt {
			return ErrCertificateRetryConflict
		}
		result, err := readCertificateResult(certificateStatePath(cfg))
		if err != nil || result.TargetDigest != current.TargetDigest || result.Attempt != current.Attempt {
			// Missing, malformed and stale results are all still pending. Preserve
			// the identity but atomically rewrite the request so a path-unit event
			// lost to lock contention is retriggered. systemd serializes the
			// oneshot; no second signing attempt can overlap the first.
			if err := writeCertificateRequest(certificateRequestPath(e.config.path), current); err != nil {
				return fmt.Errorf("5gpn/engine: retry pending certificate request: %w", err)
			}
			return nil
		}
		if result.Status == "ready" {
			if !result.readyShapeMatches(len(current.Hosts) == 0) {
				if err := writeCertificateRequest(certificateRequestPath(e.config.path), current); err != nil {
					return fmt.Errorf("5gpn/engine: retry mismatched certificate request: %w", err)
				}
				if e.certs != nil {
					e.certs.invalidateRuntimePlan()
				}
				snapshot, err = e.SnapshotFromConfig(cfg)
				return err
			}
			return ErrCertificateAlreadyReady
		}
		if result.Status != "error" {
			return nil
		}
		published, err := nextCertificateRequest(certificateRequestPath(e.config.path), cfg, true)
		if err != nil {
			return err
		}
		if err := writeCertificateRequest(certificateRequestPath(e.config.path), published); err != nil {
			return fmt.Errorf("5gpn/engine: retry certificate request: %w", err)
		}
		if e.certs != nil {
			e.certs.invalidateRuntimePlan()
		}
		snapshot, err = e.SnapshotFromConfig(cfg)
		if err != nil {
			return err
		}
		return nil
	})
	if err != nil {
		return snapshot, currentRevision, err
	}
	return snapshot, currentRevision, nil
}
