// Package statevalidator validates durable 5gpn state without creating,
// changing, or applying state and without compiling untrusted guest code.
package statevalidator

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/metacubex/mihomo/5gpn/bot"
	"github.com/metacubex/mihomo/5gpn/dns"
	"github.com/metacubex/mihomo/5gpn/engine"
	"github.com/metacubex/mihomo/5gpn/state"
)

const (
	dnsDocumentName       = "dns.json"
	interceptDocumentName = "intercept.json"
	botDocumentName       = "bot.json"
)

// Result reports which of the optional state documents were present.
type Result struct {
	Validated []string `json:"validated"`
	Missing   []string `json:"missing"`
}

type documentValidator struct {
	name     string
	validate func([]byte) error
}

// Validate validates every present durable document beneath an absolute dir.
// The directory and each document are optional.
func Validate(dir string) (Result, error) {
	return validate(dir, state.ReadPrivateFile)
}

// ValidateForOwner validates every present durable document while requiring
// the explicit Unix owner UID on all of them. This is the installer path: root
// can inspect fivegpn-owned state without weakening the ordinary service-owner
// contract, and mixed or unexpected ownership is rejected.
func ValidateForOwner(dir string, expectedUID int) (Result, error) {
	if err := state.ValidatePrivateFileOwnerAccess(expectedUID); err != nil {
		return Result{Validated: []string{}, Missing: []string{}}, err
	}
	return validate(dir, func(path string, maxBytes int64) ([]byte, error) {
		return state.ReadPrivateFileForOwner(path, maxBytes, expectedUID)
	})
}

func validate(dir string, readPrivate func(string, int64) ([]byte, error)) (Result, error) {
	result := Result{Validated: []string{}, Missing: []string{}}
	if dir == "" || !filepath.IsAbs(dir) {
		return result, errors.New("state directory must be an absolute path")
	}
	if readPrivate == nil {
		return result, errors.New("private state reader is required")
	}
	dir = filepath.Clean(dir)
	info, err := os.Lstat(dir)
	if errors.Is(err, os.ErrNotExist) {
		result.Missing = append(result.Missing, dnsDocumentName, interceptDocumentName, botDocumentName)
		return result, nil
	}
	if err != nil {
		return result, fmt.Errorf("inspect state directory: %w", err)
	}
	if !info.IsDir() {
		return result, errors.New("state directory is not a directory")
	}
	resolved, err := filepath.EvalSymlinks(dir)
	if err != nil {
		return result, fmt.Errorf("resolve state directory: %w", err)
	}
	if filepath.Clean(resolved) != dir {
		return result, errors.New("state directory contains a symlinked path component")
	}

	validators := []documentValidator{
		{name: dnsDocumentName, validate: validateDNS},
		{name: interceptDocumentName, validate: validateIntercept},
		{name: botDocumentName, validate: validateBot},
	}
	for _, validator := range validators {
		path := filepath.Join(dir, validator.name)
		raw, err := readPrivate(path, state.MaxDocumentBytes)
		switch {
		case err == nil:
		case errors.Is(err, os.ErrNotExist):
			result.Missing = append(result.Missing, validator.name)
			continue
		default:
			return result, fmt.Errorf("%s: %w", validator.name, err)
		}
		if err := validator.validate(raw); err != nil {
			return result, fmt.Errorf("%s: %w", validator.name, err)
		}
		result.Validated = append(result.Validated, validator.name)
	}
	return result, nil
}

func validateDNS(raw []byte) error {
	var document dns.Document
	if err := state.DecodeJSONBytes(raw, state.MaxDocumentBytes, &document); err != nil {
		return err
	}
	if err := document.Validate(); err != nil {
		return err
	}
	return dns.ValidateInstalledListeners(document.Listen)
}

func validateIntercept(raw []byte) error {
	var document engine.Config
	if err := state.DecodeJSONBytes(raw, state.MaxDocumentBytes, &document); err != nil {
		return err
	}
	// Validate covers modules, actions, routing, and HTTP/3. The
	// certificate-request validator pins the TLS paths but does not publish a
	// request; publication belongs to the live config store, which this package
	// deliberately never opens.
	if err := document.Validate(); err != nil {
		return err
	}
	return document.ValidateCertificateRequest()
}

func validateBot(raw []byte) error {
	var document bot.Document
	if err := state.DecodeJSONBytes(raw, state.MaxDocumentBytes, &document); err != nil {
		return err
	}
	return document.Validate()
}
