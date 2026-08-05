package engine

import (
	"context"
	"errors"
	"net"
	"strconv"

	C "github.com/metacubex/mihomo/constant"
)

// netTarget is a destination the engine wants reached.
//
// It was socksTarget, and the rename is the point: nothing about a host and a
// port was ever SOCKS-specific. The name described the one transport that
// happened to carry it to mihomo, and that transport is gone -- the engine and
// the thing that dials for it are now the same process.
//
// Network reports "udp" because the QUIC/H3 path is the only caller that asks;
// the TCP path names its own network at the dial.
type netTarget struct {
	Host      string
	Port      int
	Owner     string
	OwnerOnly bool
}

func (t netTarget) Network() string { return "udp" }

func (t netTarget) String() string { return net.JoinHostPort(t.Host, strconv.Itoa(t.Port)) }

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

// errPacketUpstreamUnwired mirrors errUpstreamUnwired for the QUIC/H3 path.
var errPacketUpstreamUnwired = errors.New("engine: no upstream packet dialer installed")

// listenPacketUpstream is the datagram half of the egress seam.
//
// The H3 client needs a net.PacketConn it can hand to quic.Transport, which the
// SOCKS design produced by holding a UDP ASSOCIATE open and wrapping the relay
// socket. In-process the host supplies one bound to whatever outbound mihomo's
// rules chose for this target -- same policy, one socket instead of three.
var listenPacketUpstream = func(ctx context.Context, t netTarget) (net.PacketConn, error) {
	return nil, errPacketUpstreamUnwired
}

// SetUpstreamPacketDialer installs the process-wide datagram egress. Called
// once, alongside SetUpstreamDialer, before any listener accepts.
func SetUpstreamPacketDialer(listen func(ctx context.Context, host string, port int, owner string, ownerOnly bool) (net.PacketConn, error)) {
	listenPacketUpstream = func(ctx context.Context, t netTarget) (net.PacketConn, error) {
		return listen(ctx, t.Host, t.Port, t.Owner, t.OwnerOnly)
	}
}
