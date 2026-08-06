package dial

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	C "github.com/metacubex/mihomo/constant"
)

type dialTestPolicy struct {
	group     string
	err       error
	metadata  []*C.Metadata
	owner     string
	ownerOnly bool
}

func (*dialTestPolicy) ClientPolicyActive() bool { return true }

func (*dialTestPolicy) RouteClient(*C.Metadata) C.ClientRouteAction {
	return C.ClientRouteNone
}

func (p *dialTestPolicy) SelectEgress(metadata *C.Metadata, owner string, ownerOnly bool) (string, error) {
	p.metadata = append(p.metadata, metadata.Clone())
	p.owner = owner
	p.ownerOnly = ownerOnly
	return p.group, p.err
}

type dialTestPacketConn struct{}

func (*dialTestPacketConn) ReadFrom([]byte) (int, net.Addr, error) { return 0, nil, net.ErrClosed }
func (*dialTestPacketConn) WriteTo(p []byte, _ net.Addr) (int, error) {
	return len(p), nil
}
func (*dialTestPacketConn) Close() error                     { return nil }
func (*dialTestPacketConn) LocalAddr() net.Addr              { return &net.UDPAddr{} }
func (*dialTestPacketConn) SetDeadline(time.Time) error      { return nil }
func (*dialTestPacketConn) SetReadDeadline(time.Time) error  { return nil }
func (*dialTestPacketConn) SetWriteDeadline(time.Time) error { return nil }

func TestTransformedTCPPassesSelectedSpecialProxy(t *testing.T) {
	policy := &dialTestPolicy{group: "GroupA"}
	state := &trafficAuthorization{policy: policy, proxyExists: func(name string) bool { return name == "GroupA" }}
	handled := 0
	var address, proxy string
	conn, err := tcpWithAuthorization(
		context.Background(), nil, state,
		func(_ C.Tunnel, gotAddress, gotProxy string) (net.Conn, error) {
			handled++
			address, proxy = gotAddress, gotProxy
			client, server := net.Pipe()
			_ = server.Close()
			return client, nil
		},
		"origin.example.com", 443, "extension.a", true,
	)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if handled != 1 || address != "origin.example.com:443" || proxy != "GroupA" {
		t.Fatalf("TCP handler calls=%d address=%q proxy=%q", handled, address, proxy)
	}
	if len(policy.metadata) != 1 || policy.metadata[0].Type != C.INNER || policy.metadata[0].NetWork != C.TCP {
		t.Fatalf("TCP authorization metadata = %+v", policy.metadata)
	}
	if policy.owner != "extension.a" || !policy.ownerOnly {
		t.Fatalf("TCP owner = %q, ownerOnly=%v", policy.owner, policy.ownerOnly)
	}
}

func TestTransformedUDPPassesSelectedSpecialProxy(t *testing.T) {
	policy := &dialTestPolicy{group: "GroupA"}
	state := &trafficAuthorization{policy: policy, proxyExists: func(name string) bool { return name == "GroupA" }}
	handled := 0
	var network, address, proxy string
	packetConn, err := udpWithAuthorization(
		context.Background(), nil, state,
		func(_ C.Tunnel, gotNetwork, gotAddress, gotProxy string) (net.PacketConn, net.Addr, error) {
			handled++
			network, address, proxy = gotNetwork, gotAddress, gotProxy
			return &dialTestPacketConn{}, &net.UDPAddr{}, nil
		},
		"origin.example.com", 443, "extension.a", true,
	)
	if err != nil {
		t.Fatal(err)
	}
	defer packetConn.Close()
	if handled != 1 || network != "udp" || address != "origin.example.com:443" || proxy != "GroupA" {
		t.Fatalf("UDP handler calls=%d network=%q address=%q proxy=%q", handled, network, address, proxy)
	}
	if len(policy.metadata) != 1 || policy.metadata[0].Type != C.INNER || policy.metadata[0].NetWork != C.UDP {
		t.Fatalf("UDP authorization metadata = %+v", policy.metadata)
	}
}

func TestTransformedDialFailsBeforeHandlerWhenGroupIsMissing(t *testing.T) {
	policy := &dialTestPolicy{group: "RemovedGroup"}
	state := &trafficAuthorization{policy: policy, proxyExists: func(string) bool { return false }}
	tcpCalls := 0
	_, err := tcpWithAuthorization(
		context.Background(), nil, state,
		func(C.Tunnel, string, string) (net.Conn, error) {
			tcpCalls++
			return nil, nil
		},
		"origin.example.com", 443, "extension.a", false,
	)
	if err == nil || tcpCalls != 0 {
		t.Fatalf("missing group TCP err=%v handler calls=%d", err, tcpCalls)
	}

	udpCalls := 0
	_, err = udpWithAuthorization(
		context.Background(), nil, state,
		func(C.Tunnel, string, string, string) (net.PacketConn, net.Addr, error) {
			udpCalls++
			return nil, nil, nil
		},
		"origin.example.com", 443, "extension.a", false,
	)
	if err == nil || udpCalls != 0 {
		t.Fatalf("missing group UDP err=%v handler calls=%d", err, udpCalls)
	}
}

func TestTransformedDialRejectsAnEmptyPolicyBinding(t *testing.T) {
	policy := &dialTestPolicy{group: ""}
	state := &trafficAuthorization{policy: policy, proxyExists: func(string) bool { return true }}
	handled := 0
	_, err := tcpWithAuthorization(
		context.Background(), nil, state,
		func(C.Tunnel, string, string) (net.Conn, error) {
			handled++
			return nil, nil
		},
		"origin.example.com", 443, "extension.a", false,
	)
	if err == nil || handled != 0 {
		t.Fatalf("empty binding err=%v handler calls=%d, want fail before handler", err, handled)
	}
}

func TestTransformedDialFailsBeforeHandlerWhenBindingIsUnauthorized(t *testing.T) {
	policy := &dialTestPolicy{err: errors.New("required binding missing")}
	state := &trafficAuthorization{policy: policy, proxyExists: func(string) bool { return true }}
	calls := 0
	_, err := tcpWithAuthorization(
		context.Background(), nil, state,
		func(C.Tunnel, string, string) (net.Conn, error) {
			calls++
			return nil, nil
		},
		"origin.example.com", 443, "extension.a", true,
	)
	if err == nil || calls != 0 {
		t.Fatalf("unauthorized binding err=%v handler calls=%d", err, calls)
	}
}
