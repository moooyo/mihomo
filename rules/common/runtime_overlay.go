package common

import (
	"errors"
	"strings"
	"sync/atomic"

	"github.com/metacubex/mihomo/component/overlay"
	C "github.com/metacubex/mihomo/constant"
)

// errInvalidOverlayParams rejects trailing tokens on an anchor line.
var errInvalidOverlayParams = errors.New("RUNTIME-OVERLAY takes exactly an owner and a stage")

// Binding is the late-bound access point to the live runtime overlay.
//
// The anchor rule resolves the overlay at match time rather than capturing it
// at parse time. Capturing would pin one generation for the lifetime of the
// rule list, which survives across commits; the whole point of the snapshot
// swap is that a rule already in the rule list starts observing the new
// generation the instant it is published.
type Binding struct {
	// Owner is the overlay owner this process serves. An anchor naming a
	// different owner never matches.
	Owner string
	// Holder publishes the live snapshot. Reads are lock-free, which matters:
	// Match runs inside tunnel's configMux read lock, so taking any lock the
	// commit path also takes would risk a deadlock.
	Holder *overlay.Holder
	// AdapterExists reports whether an adapter name resolves in the live
	// proxies map. It must not acquire tunnel's configMux.
	AdapterExists func(string) bool
}

var overlayBinding atomic.Pointer[Binding]

// SetOverlayBinding publishes the overlay access point. Passing nil disables
// every anchor, which is the correct behaviour on a build or deployment with no
// overlay configured: the anchors then never match and the operator's own rules
// decide everything.
func SetOverlayBinding(b *Binding) { overlayBinding.Store(b) }

// OverlayBinding returns the published access point, or nil.
func OverlayBinding() *Binding { return overlayBinding.Load() }

// RuntimeOverlay is one of the two overlay anchors.
//
// It carries no policy of its own. All it does is mark the position in the
// operator's rule list where the overlay's own, separately committed policy is
// evaluated — which is what lets ordinary plugin operations change routing
// without rewriting the operator-owned configuration file.
type RuntimeOverlay struct {
	Base
	owner string
	stage overlay.Stage
}

func (r *RuntimeOverlay) RuleType() C.RuleType {
	if r.stage == overlay.StageEgress {
		return C.RuntimeOverlayEgress
	}
	return C.RuntimeOverlayClient
}

// Owner reports the overlay owner this anchor belongs to.
func (r *RuntimeOverlay) Owner() string { return r.owner }

// Stage reports which of the two stages this anchor evaluates.
func (r *RuntimeOverlay) Stage() overlay.Stage { return r.stage }

// Adapter returns the stage name. It is only ever read by GET /rules; the
// per-connection target comes from Match's second return value.
func (r *RuntimeOverlay) Adapter() string { return string(r.stage) }

// Payload returns the owner, which is what the rule line carries.
func (r *RuntimeOverlay) Payload() string { return r.owner }

// Match evaluates the overlay stage.
//
// Two properties are load-bearing and easy to lose:
//
//   - the client stage returns (false, "") when nothing matched, so resolution
//     continues into the operator's rules — an overlay that selects nothing must
//     be invisible;
//   - it never returns an adapter name that is absent from the live proxies map.
//     tunnel silently skips a rule whose adapter does not resolve, so returning a
//     stale processor name would make the anchor fail open and fall through to
//     the operator's rules. When the target has vanished the answer is REJECT.
func (r *RuntimeOverlay) Match(metadata *C.Metadata, _ C.RuleMatchHelper) (bool, string) {
	b := overlayBinding.Load()
	if b == nil || b.Holder == nil || b.Owner != r.owner {
		return false, ""
	}
	snapshot := b.Holder.Load()
	in := overlay.MatchInput{
		Host:    strings.ToLower(metadata.RuleHost()),
		DstIP:   metadata.DstIP,
		DstPort: metadata.DstPort,
		Network: networkOf(metadata),
		InName:  metadata.InName,
		InUser:  metadata.InUser,
	}

	if r.stage == overlay.StageEgress {
		res, ok := snapshot.ResolveEgress(&in)
		if !ok {
			// Not an authorized processor request. It continues to the fixed
			// egress reject terminator that the structural validator requires
			// to sit immediately after this anchor.
			return false, ""
		}
		// The group comes off the resolved binding, never off the capability:
		// one credential spans every group the generation binds, and the
		// destination is what selects among them.
		if !r.resolves(b, res.Binding.Group) {
			return true, rejectAdapter
		}
		metadata.OverlayGeneration = res.GenerationID
		metadata.OverlayCapability = res.Capability.ID
		return true, res.Binding.Group
	}

	d := snapshot.MatchClient(&in)
	if !d.Matched {
		return false, ""
	}
	switch d.Action {
	case overlay.ActionDirect:
		return true, directAdapter
	case overlay.ActionReject:
		return true, rejectAdapter
	case overlay.ActionCapture:
		if !r.resolves(b, d.Target) {
			return true, rejectAdapter
		}
		metadata.OverlayGeneration = snapshot.ActiveID()
		return true, d.Target
	}
	return true, rejectAdapter
}

func (r *RuntimeOverlay) resolves(b *Binding, name string) bool {
	if name == "" {
		return false
	}
	if b.AdapterExists == nil {
		return true
	}
	return b.AdapterExists(name)
}

const (
	directAdapter = "DIRECT"
	rejectAdapter = "REJECT"
)

func networkOf(metadata *C.Metadata) overlay.Network {
	if metadata.NetWork == C.UDP {
		return overlay.NetworkUDP
	}
	return overlay.NetworkTCP
}

// NewRuntimeOverlay builds an anchor from a `RUNTIME-OVERLAY,<owner>,<stage>`
// line.
//
// The stage arrives in the target slot because ParseRulePayload's default
// branch puts the third comma field there. Trailing params are rejected rather
// than ignored: ParseParams silently drops anything it does not recognise, so
// without this a typo in an anchor line would be a silent no-op.
func NewRuntimeOverlay(owner, stage string, params []string) (*RuntimeOverlay, error) {
	if len(params) > 0 {
		return nil, errInvalidOverlayParams
	}
	s, err := overlay.ParseStage(stage)
	if err != nil {
		return nil, err
	}
	owner = strings.TrimSpace(owner)
	if err := overlay.ValidateOwner(owner); err != nil {
		return nil, err
	}
	return &RuntimeOverlay{owner: owner, stage: s}, nil
}

var _ C.Rule = (*RuntimeOverlay)(nil)
