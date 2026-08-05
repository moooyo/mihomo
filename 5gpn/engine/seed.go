package engine

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"

	"github.com/metacubex/mihomo/5gpn/state"
)

// The fixed interception TLS paths. They are not configurable, and the
// certificate request validator pins these exact strings: the leaf is minted by
// a root oneshot that reads this document, so a document that could name its
// own certificate path could point the engine at a leaf nobody vouched for.
const (
	interceptCertPath = "/etc/5gpn/intercept/tls/fullchain.pem"
	interceptKeyPath  = "/etc/5gpn/intercept/tls/privkey.pem"
)

// DefaultDocument is an interception engine that is installed and doing
// nothing: the master off, no extensions, HTTP/2 on, and the retained HTTP/3
// field false because extension interception does not support QUIC.
//
// "Installed and doing nothing" is a state the system needs to be able to
// represent, and an absent file cannot represent it. The API answers 503 for an
// engine that failed to load and renders a panel for one that loaded and says
// it is off, and those must not be the same thing — one is a gateway to
// investigate and the other is a gateway working as configured.
//
// The first-party catalog is seeded because discovery has to work before an
// operator knows a URL to type; it is a default they can disable or remove, and
// it grants nothing on its own.
func DefaultDocument() Config {
	return Config{
		Version:        configVersion,
		ExecutionOrder: []string{},
		TLSCert:        interceptCertPath,
		TLSKey:         interceptKeyPath,
		MITM:           MITMSettings{Enabled: false, HTTP2: true, HTTP3: false},
		Catalogs:       defaultCatalogSources(),
	}
}

// EnsureDocument writes the default document if none exists.
//
// It does not repair one that exists and does not parse. That case is a
// deliberate refusal: an unreadable document is either a bug or a partial write
// nothing else explains, and replacing it with defaults would silently discard
// every extension the operator installed and every binding they chose.
func EnsureDocument(path string) error {
	switch _, err := os.Stat(path); {
	case err == nil:
		return nil
	case !errors.Is(err, os.ErrNotExist):
		return fmt.Errorf("5gpn/engine: stat %s: %w", path, err)
	}
	raw, err := json.MarshalIndent(DefaultDocument(), "", "  ")
	if err != nil {
		return fmt.Errorf("5gpn/engine: marshal the default document: %w", err)
	}
	// Round-trip before publishing, for the same reason a write does: what
	// lands on disk has to be something this program can read back.
	if _, err := decodeConfig(raw); err != nil {
		return fmt.Errorf("5gpn/engine: the default document does not validate: %w", err)
	}
	return state.WriteFile(path, raw)
}
