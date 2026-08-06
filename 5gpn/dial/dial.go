// Package dial is the interception engine's only route to the network.
//
// The engine has never been allowed to open a socket of its own. Every upstream
// connection it makes -- including one a plugin script asks for -- goes back
// through mihomo so mihomo's rules choose the egress, which is what stops a
// captured connection from quietly escaping the operator's routing. That used
// to be arranged with an authenticated loopback SOCKS5 listener; here it is a
// function call, and the property is the same one.
package dial

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"
	"sync/atomic"

	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/listener/inner"
)

// ErrNoTunnel is returned before the core has finished starting.
var ErrNoTunnel = errors.New("5gpn/dial: tunnel not initialised")

// ErrNoTrafficPolicy is returned until an interception engine has installed
// the reviewed runtime authorization boundary.
var ErrNoTrafficPolicy = errors.New("5gpn/dial: traffic policy not initialised")

type trafficAuthorization struct {
	policy      C.TrafficPolicy
	proxyExists func(string) bool
}

var authorization atomic.Pointer[trafficAuthorization]

// SetTrafficPolicy installs the policy used only by transformed engine flows.
// Passing nil withdraws egress immediately; callers then fail closed.
func SetTrafficPolicy(policy C.TrafficPolicy, proxyExists func(string) bool) {
	if policy == nil {
		authorization.Store(nil)
		return
	}
	authorization.Store(&trafficAuthorization{policy: policy, proxyExists: proxyExists})
}

// Authorize revalidates a transformed target against the current document and
// live mihomo group set without opening a connection. HTTP callers use it
// before each request so a pooled connection cannot outlive its authorization.
func Authorize(network C.NetWork, host string, port int, owner string, ownerOnly bool) (string, error) {
	state := authorization.Load()
	if state == nil {
		return "", ErrNoTrafficPolicy
	}
	metadata, err := transformedMetadata(network, host, port)
	if err != nil {
		return "", err
	}
	return authorizeEgress(state, metadata, owner, ownerOnly)
}

// TCP opens a connection to host:port through mihomo's own rule evaluation.
//
// inner.HandleTcp is mihomo's existing answer to "the core itself needs to dial
// something and wants its own routing applied". Reusing it rather than
// reimplementing rule resolution means the engine's upstream and an ordinary
// client connection cannot diverge: same rules, same outbound selection, same
// entry in the connection table. The connection arrives at handleTCPConn with
// Type == INNER, which is exactly what the capture guard refuses, so this
// cannot feed the engine its own output.
//
// The cost is one in-memory pipe hop, because inner dialing hands back one end
// of a pipe rather than the outbound socket. That is mihomo's idiom and it buys
// rule evaluation and connection tracking; it is not free, and it is the
// obvious thing to revisit if intercepted throughput ever matters more than
// intercepted correctness.
func TCP(ctx context.Context, host string, port int, owner string, ownerOnly bool) (net.Conn, error) {
	t := inner.GetTunnel()
	if t == nil {
		return nil, ErrNoTunnel
	}
	state := authorization.Load()
	if state == nil {
		return nil, ErrNoTrafficPolicy
	}
	return tcpWithAuthorization(ctx, t, state, inner.HandleTcp, host, port, owner, ownerOnly)
}

// SystemTCP opens trusted core control traffic through ordinary mihomo rules.
// It is not an extension-transformed flow and therefore has no egress binding.
func SystemTCP(ctx context.Context, host string, port int) (net.Conn, error) {
	t := inner.GetTunnel()
	if t == nil {
		return nil, ErrNoTunnel
	}
	conn, err := inner.HandleTcp(t, net.JoinHostPort(host, strconv.Itoa(port)), "")
	if err != nil {
		return nil, err
	}
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}
	return conn, nil
}

// UDP opens a packet association to host:port through mihomo's rule evaluation.
//
// The QUIC/H3 client needs a net.PacketConn to hand to quic.Transport. The
// SOCKS design produced one by holding a UDP ASSOCIATE open and wrapping the
// relay socket; inner.HandleUdp produces the same shape with the same routing
// and without the association.
func UDP(ctx context.Context, host string, port int, owner string, ownerOnly bool) (net.PacketConn, error) {
	t := inner.GetTunnel()
	if t == nil {
		return nil, ErrNoTunnel
	}
	state := authorization.Load()
	if state == nil {
		return nil, ErrNoTrafficPolicy
	}
	return udpWithAuthorization(ctx, t, state, inner.HandleUdp, host, port, owner, ownerOnly)
}

type tcpHandler func(C.Tunnel, string, string) (net.Conn, error)
type udpHandler func(C.Tunnel, string, string, string) (net.PacketConn, net.Addr, error)

func tcpWithAuthorization(
	ctx context.Context,
	t C.Tunnel,
	state *trafficAuthorization,
	handle tcpHandler,
	host string,
	port int,
	owner string,
	ownerOnly bool,
) (net.Conn, error) {
	metadata, err := transformedMetadata(C.TCP, host, port)
	if err != nil {
		return nil, err
	}
	proxy, err := authorizeEgress(state, metadata, owner, ownerOnly)
	if err != nil {
		return nil, err
	}
	conn, err := handle(t, metadata.RemoteAddress(), proxy)
	if err != nil {
		return nil, err
	}
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}
	return conn, nil
}

func udpWithAuthorization(
	ctx context.Context,
	t C.Tunnel,
	state *trafficAuthorization,
	handle udpHandler,
	host string,
	port int,
	owner string,
	ownerOnly bool,
) (net.PacketConn, error) {
	metadata, err := transformedMetadata(C.UDP, host, port)
	if err != nil {
		return nil, err
	}
	proxy, err := authorizeEgress(state, metadata, owner, ownerOnly)
	if err != nil {
		return nil, err
	}
	pc, _, err := handle(t, "udp", metadata.RemoteAddress(), proxy)
	if err != nil {
		return nil, err
	}
	if deadline, ok := ctx.Deadline(); ok {
		_ = pc.SetDeadline(deadline)
	}
	return pc, nil
}

func transformedMetadata(network C.NetWork, host string, port int) (*C.Metadata, error) {
	if port < 1 || port > 65535 {
		return nil, fmt.Errorf("5gpn/dial: invalid destination port %d", port)
	}
	metadata := &C.Metadata{
		NetWork: network,
		Type:    C.INNER,
		DNSMode: C.DNSNormal,
		Process: C.MihomoName,
	}
	if err := metadata.SetRemoteAddress(net.JoinHostPort(host, strconv.Itoa(port))); err != nil {
		return nil, fmt.Errorf("5gpn/dial: invalid transformed target: %w", err)
	}
	return metadata, nil
}

func authorizeEgress(state *trafficAuthorization, metadata *C.Metadata, owner string, ownerOnly bool) (string, error) {
	if state == nil || state.policy == nil {
		return "", ErrNoTrafficPolicy
	}
	proxy, err := state.policy.SelectEgress(metadata, owner, ownerOnly)
	if err != nil {
		return "", fmt.Errorf("5gpn/dial: transformed egress denied: %w", err)
	}
	if proxy == "" {
		return "", errors.New("5gpn/dial: transformed egress policy returned no explicit binding")
	}
	if state.proxyExists == nil || !state.proxyExists(proxy) {
		return "", fmt.Errorf("5gpn/dial: transformed egress proxy %q is unavailable", proxy)
	}
	return proxy, nil
}
