package route

import (
	"fmt"

	"github.com/metacubex/mihomo/tunnel"
)

// overlayRejectsPatch reports why an incremental configuration change is
// refused while a runtime-overlay generation is bound to this process, or ""
// when it is allowed.
//
// The two fields it guards are the ones that make the anchors unenforceable
// rather than merely different:
//
//   - mode, because Direct and Global return from resolveMetadata before any
//     rule is evaluated, so neither anchor is ever reached;
//   - sniffing, because the client stage matches on the recovered hostname and
//     turning sniffing off silently shrinks the capture set to whatever the
//     destination address alone can express.
//
// Both are refused rather than accepted-and-compensated. The escape hatch is
// explicit: disable the interception generation first, through the control
// socket, and the operator regains the usual switches.
func overlayRejectsPatch(schema *configSchema) string {
	snapshot := tunnel.OverlaySnapshot()
	if !snapshot.RequiresAnchors() {
		return ""
	}

	if schema.Mode != nil && *schema.Mode != tunnel.Rule {
		return fmt.Sprintf(
			"cannot switch to %s mode while runtime-overlay generation %s is active: "+
				"Direct and Global bypass rule matching entirely. Disable the generation first.",
			schema.Mode.String(), snapshot.ActiveID())
	}

	if schema.Sniffing != nil && !*schema.Sniffing {
		return fmt.Sprintf(
			"cannot disable sniffing while runtime-overlay generation %s is active: "+
				"the capture rules match on the sniffed hostname. Disable the generation first.",
			snapshot.ActiveID())
	}

	return ""
}
