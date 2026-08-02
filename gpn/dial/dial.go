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
	"net"
	"strconv"

	"github.com/metacubex/mihomo/listener/inner"
)

// ErrNoTunnel is returned before the core has finished starting.
var ErrNoTunnel = errors.New("gpn/dial: tunnel not initialised")

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
func TCP(ctx context.Context, host string, port int) (net.Conn, error) {
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
func UDP(ctx context.Context, host string, port int) (net.PacketConn, error) {
	t := inner.GetTunnel()
	if t == nil {
		return nil, ErrNoTunnel
	}
	pc, _, err := inner.HandleUdp(t, "udp", net.JoinHostPort(host, strconv.Itoa(port)), "")
	if err != nil {
		return nil, err
	}
	if deadline, ok := ctx.Deadline(); ok {
		_ = pc.SetDeadline(deadline)
	}
	return pc, nil
}
