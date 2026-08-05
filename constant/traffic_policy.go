package constant

// ClientRouteAction is the only decision an extension manifest can make for
// ordinary gateway traffic. Keeping this typed prevents a manifest-derived
// value from ever being interpreted as an arbitrary proxy name.
type ClientRouteAction uint8

const (
	ClientRouteNone ClientRouteAction = iota
	ClientRouteDirect
	ClientRouteReject
)

// TrafficPolicy is the in-memory authorization boundary shared by the client
// routing hook and transformed engine egress.
//
// RouteClient is consulted before capture and ordinary rule evaluation.
// SelectEgress resolves only operator-owned bindings; owner identifies the
// extension whose authorized transformation produced the upstream flow.
type TrafficPolicy interface {
	ClientPolicyActive() bool
	RouteClient(metadata *Metadata) ClientRouteAction
	SelectEgress(metadata *Metadata, owner string, ownerOnly bool) (string, error)
}
