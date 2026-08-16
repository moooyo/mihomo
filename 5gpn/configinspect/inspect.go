// Package configinspect exposes the narrow controller projection needed by the
// root management tools without starting mihomo or fully constructing a config.
package configinspect

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"

	"github.com/metacubex/mihomo/config"
	"github.com/metacubex/mihomo/hub/route"
)

const (
	// OutputVersion is the JSON contract consumed by the pinned installer.
	OutputVersion  = 2
	maxConfigBytes = 16 << 20
)

// View is the exact managed-controller projection read from config.yaml.
type View struct {
	Version               int    `json:"version"`
	RawRevision           string `json:"raw_revision"`
	Secret                string `json:"secret"`
	ExternalControllerTLS string `json:"external_controller_tls"`
	ExternalUI            string `json:"external_ui"`
	Certificate           string `json:"certificate"`
	PrivateKey            string `json:"private_key"`
}

// Inspect parses only the raw YAML configuration and validates the managed
// controller boundary. It deliberately avoids config.Parse, whose complete
// rule/provider construction may load geodata or other runtime dependencies.
func Inspect(raw []byte) (View, error) {
	if len(raw) == 0 {
		return View{}, fmt.Errorf("operator config is empty")
	}
	rawConfig, err := config.UnmarshalRawConfig(raw)
	if err != nil {
		return View{}, fmt.Errorf("parse operator config: %w", err)
	}
	controller := &route.Config{
		Addr:           rawConfig.ExternalController,
		TLSAddr:        rawConfig.ExternalControllerTLS,
		UnixAddr:       rawConfig.ExternalControllerUnix,
		PipeAddr:       rawConfig.ExternalControllerPipe,
		RoutingMark:    rawConfig.ExternalControllerRoutingMark,
		Secret:         rawConfig.Secret,
		Certificate:    rawConfig.TLS.Certificate,
		PrivateKey:     rawConfig.TLS.PrivateKey,
		ClientAuthType: rawConfig.TLS.ClientAuthType,
		ClientAuthCert: rawConfig.TLS.ClientAuthCert,
		EchKey:         rawConfig.TLS.EchKey,
		DohServer:      rawConfig.ExternalDohServer,
	}
	if err := route.ValidateManagedConfig(controller); err != nil {
		return View{}, err
	}
	sum := sha256.Sum256(raw)
	return View{
		Version:               OutputVersion,
		RawRevision:           hex.EncodeToString(sum[:]),
		Secret:                rawConfig.Secret,
		ExternalControllerTLS: rawConfig.ExternalControllerTLS,
		ExternalUI:            rawConfig.ExternalUI,
		Certificate:           rawConfig.TLS.Certificate,
		PrivateKey:            rawConfig.TLS.PrivateKey,
	}, nil
}
