package engine

import (
	"fmt"
	"path/filepath"
	"strings"

	"github.com/metacubex/mihomo/5gpn/state"
)

// The certificate request is the engine's statement of what the interception
// leaf must cover: a digest on the first line, then one host pattern per line.
//
// It is published as a file rather than printed by a subcommand, and that is
// the whole point. The consumer is a root oneshot that holds the CA signing
// key, and the alternative had it execute the network-facing program's binary
// to find out what to sign. A root process asking an unprivileged program a
// question is fine; a root process holding the one key that can mint any
// identity and *running* that program to decide what to mint is a different
// shape entirely.
//
// It is also the only copy. Recomputing the digest in shell would put two
// implementations of the same hash on either side of a boundary neither can
// see across, and the failure when they drift is silent: the oneshot reissues
// on every run, or never reissues at all.
const certificateRequestName = "certificate-request"

// certificateRequestPath is the file beside the document.
func certificateRequestPath(configPath string) string {
	return filepath.Join(filepath.Dir(configPath), certificateRequestName)
}

// renderCertificateRequest is the exact bytes the oneshot parses.
//
// The digest covers the host list and nothing else. It deliberately does not
// cover the rest of the document: an operator changing a script, a setting or
// an egress binding has not changed what the certificate must name, and
// reissuing on those would burn the CA for no reason and churn the leaf under
// live sessions.
func renderCertificateRequest(cfg Config) string {
	hosts := certificateHostPatterns(cfg)
	var b strings.Builder
	b.WriteString(certificateDigest(cfg))
	b.WriteByte('\n')
	for _, host := range hosts {
		b.WriteString(host)
		b.WriteByte('\n')
	}
	return b.String()
}

// publishCertificateRequest writes the request beside the document.
//
// Called after every successful publish and once at startup, so a gateway that
// was edited while the oneshot was not running still converges: the path unit
// fires on the write, and a run that missed one still reads the current file.
func publishCertificateRequest(configPath string, cfg Config) error {
	path := certificateRequestPath(configPath)
	if err := state.WritePublicFile(path, []byte(renderCertificateRequest(cfg))); err != nil {
		return fmt.Errorf("5gpn/engine: publish certificate request: %w", err)
	}
	return nil
}
