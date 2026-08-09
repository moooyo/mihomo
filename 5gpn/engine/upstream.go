package engine

import (
	"context"
	"errors"
	"net"

	C "github.com/metacubex/mihomo/constant"
)

// netTarget is a destination the engine wants reached.
//
// It was socksTarget, and the rename is the point: nothing about a host and a
// port was ever SOCKS-specific. The name described the one transport that
// happened to carry it to mihomo, and that transport is gone -- the engine and
// the thing that dials for it are now the same process.
type netTarget struct {
	Host      string
	Port      int
	Owner     string
	OwnerOnly bool
}

// errUpstreamUnwired is what every engine egress attempt gets until the host
// installs a dialer.
//
// This is a seam, not a stub. The engine has never been allowed to reach the
// network on its own -- every upstream connection, including one a script asks
// for, went back through mihomo so mihomo's rules chose the egress. Deleting
// the SOCKS hop did not relax that; it only removed the socket in the middle.
// So the engine still cannot dial, and the failure is loud rather than a
// silent fallback to a direct connection that would bypass every rule.
var errUpstreamUnwired = errors.New("engine: no upstream dialer installed")

var errUpstreamAuthorizerUnwired = errors.New("engine: no upstream authorizer installed")

var authorizeUpstream = func(C.NetWork, netTarget) (string, error) {
	return "", errUpstreamAuthorizerUnwired
}

// SetUpstreamAuthorizer installs the live preflight used before every request,
// including requests that could reuse an existing HTTP connection.
func SetUpstreamAuthorizer(authorize func(network C.NetWork, host string, port int, owner string, ownerOnly bool) (string, error)) {
	authorizeUpstream = func(network C.NetWork, target netTarget) (string, error) {
		return authorize(network, target.Host, target.Port, target.Owner, target.OwnerOnly)
	}
}

// dialUpstream is the single point where the engine leaves the process.
//
// The host sets it once at startup to a function that resolves the target
// through mihomo's own rule evaluation and dials the winning outbound, which is
// what the two authenticated SOCKS5 hops were an expensive way of arranging.
// One package-level var rather than a field on every requester because there is
// exactly one egress policy per process and threading it through the script
// runtime bought nothing but parameters.
var dialUpstream = func(ctx context.Context, t netTarget) (net.Conn, error) {
	return nil, errUpstreamUnwired
}

// SetUpstreamDialer installs the process-wide egress used by every engine
// connection. It is called once, before any listener accepts.
func SetUpstreamDialer(dial func(ctx context.Context, host string, port int, owner string, ownerOnly bool) (net.Conn, error)) {
	dialUpstream = func(ctx context.Context, t netTarget) (net.Conn, error) {
		return dial(ctx, t.Host, t.Port, t.Owner, t.OwnerOnly)
	}
}
