// Package dial is the interception engine's only route to the network.
//
// The engine has never been allowed to open a socket of its own. Every upstream
// connection it makes -- including one a plugin script asks for -- goes back
// through mihomo. The protected operator rule prefix runs first, then the
// extension's reviewed binding is the terminal egress choice. That used to be
// arranged with an authenticated loopback SOCKS5 listener; here it is a
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
	t := inner.GetTunnel()
	if t == nil {
		return "", ErrNoTunnel
	}
	state := authorization.Load()
	if state == nil {
		return "", ErrNoTrafficPolicy
	}
	return authorizeWithTunnel(t, state, network, host, port, owner, ownerOnly)
}

type extensionEgressAuthorizer interface {
	AuthorizeExtensionEgress(metadata *C.Metadata, egressProxy string) error
}

type extensionEgressDialer interface {
	DialExtensionEgress(address string, egressProxy string) (net.Conn, error)
}

type managedSystemEgressDialer interface {
	DialManagedSystemEgress(address string) (net.Conn, error)
}

func authorizeWithTunnel(
	t C.Tunnel,
	state *trafficAuthorization,
	network C.NetWork,
	host string,
	port int,
	owner string,
	ownerOnly bool,
) (string, error) {
	metadata, err := transformedMetadata(network, host, port)
	if err != nil {
		return "", err
	}
	proxy, err := authorizeEgress(state, metadata, owner, ownerOnly)
	if err != nil {
		return "", err
	}
	authorizer, ok := t.(extensionEgressAuthorizer)
	if !ok {
		return "", errors.New("5gpn/dial: tunnel has no extension egress safety authorizer")
	}
	if err := authorizer.AuthorizeExtensionEgress(metadata, proxy); err != nil {
		return "", fmt.Errorf("5gpn/dial: transformed egress safety denied: %w", err)
	}
	return proxy, nil
}

// TCP opens a connection to host:port through mihomo's protected rule prefix
// and the extension's reviewed terminal egress binding.
//
// The tunnel's narrow DialExtensionEgress entry creates the same in-memory
// INNER connection used by core dialing without adding 5gpn fields or methods
// to upstream-owned listener and metadata packages. Console, private-network,
// and operator REJECT rules therefore stay in the tunnel's one implementation.
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
	dialer, ok := t.(extensionEgressDialer)
	if !ok {
		return nil, errors.New("5gpn/dial: tunnel has no extension egress dialer")
	}
	return tcpWithAuthorization(ctx, dialer, state, host, port, owner, ownerOnly)
}

// SystemTCP opens trusted core control traffic through ordinary mihomo rules.
// It is not an extension-transformed flow and therefore has no egress binding.
func SystemTCP(ctx context.Context, host string, port int) (net.Conn, error) {
	t := inner.GetTunnel()
	if t == nil {
		return nil, ErrNoTunnel
	}
	return systemTCPWithTunnel(ctx, t, host, port)
}

func systemTCPWithTunnel(ctx context.Context, t C.Tunnel, host string, port int) (net.Conn, error) {
	if t == nil {
		return nil, ErrNoTunnel
	}
	dialer, ok := t.(managedSystemEgressDialer)
	if !ok {
		return nil, errors.New("5gpn/dial: tunnel has no managed system egress dialer")
	}
	conn, err := dialer.DialManagedSystemEgress(net.JoinHostPort(host, strconv.Itoa(port)))
	if err != nil {
		return nil, err
	}
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}
	return conn, nil
}

func tcpWithAuthorization(
	ctx context.Context,
	dialer extensionEgressDialer,
	state *trafficAuthorization,
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
	conn, err := dialer.DialExtensionEgress(metadata.RemoteAddress(), proxy)
	if err != nil {
		return nil, err
	}
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}
	return conn, nil
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
