package dial

import (
	"context"
	"errors"
	"net"
	"testing"

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

type dialTestTunnel struct {
	metadata      *C.Metadata
	binding       string
	authorizeErr  error
	dialAddress   string
	dialBinding   string
	dialCalls     int
	dialErr       error
	systemAddress string
	systemCalls   int
	systemErr     error
}

func (*dialTestTunnel) HandleTCPConn(net.Conn, *C.Metadata)      {}
func (*dialTestTunnel) HandleUDPPacket(C.UDPPacket, *C.Metadata) {}
func (*dialTestTunnel) NatTable() C.NatTable                     { return nil }

func (t *dialTestTunnel) AuthorizeExtensionEgress(metadata *C.Metadata, binding string) error {
	t.metadata = metadata.Clone()
	t.binding = binding
	return t.authorizeErr
}

func (t *dialTestTunnel) DialExtensionEgress(address string, binding string) (net.Conn, error) {
	t.dialCalls++
	t.dialAddress = address
	t.dialBinding = binding
	if t.dialErr != nil {
		return nil, t.dialErr
	}
	client, server := net.Pipe()
	_ = server.Close()
	return client, nil
}

func (t *dialTestTunnel) DialManagedSystemEgress(address string) (net.Conn, error) {
	t.systemCalls++
	t.systemAddress = address
	if t.systemErr != nil {
		return nil, t.systemErr
	}
	client, server := net.Pipe()
	_ = server.Close()
	return client, nil
}

func TestSystemTCPUsesManagedEgressCarrierPath(t *testing.T) {
	tunnel := &dialTestTunnel{}
	conn, err := systemTCPWithTunnel(context.Background(), tunnel, "control.example.com", 443)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if tunnel.systemCalls != 1 || tunnel.systemAddress != "control.example.com:443" || tunnel.dialCalls != 0 {
		t.Fatalf("system dial calls=%d address=%q extension-calls=%d", tunnel.systemCalls, tunnel.systemAddress, tunnel.dialCalls)
	}

	tunnel.systemErr = errors.New("managed gateway denied")
	if _, err := systemTCPWithTunnel(context.Background(), tunnel, "control.example.com", 443); err == nil {
		t.Fatal("managed system dial error was ignored")
	}
	if _, err := systemTCPWithTunnel(context.Background(), nil, "control.example.com", 443); !errors.Is(err, ErrNoTunnel) {
		t.Fatalf("nil tunnel error = %v, want ErrNoTunnel", err)
	}
}

func TestAuthorizeRunsFinalTunnelSafetyForPooledConnections(t *testing.T) {
	policy := &dialTestPolicy{group: "GroupA"}
	state := &trafficAuthorization{policy: policy, proxyExists: func(name string) bool { return name == "GroupA" }}
	tunnel := &dialTestTunnel{}
	proxy, err := authorizeWithTunnel(tunnel, state, C.TCP, "origin.example.com", 443, "extension.a", true)
	if err != nil || proxy != "GroupA" || tunnel.binding != "GroupA" || tunnel.metadata == nil || tunnel.metadata.Host != "origin.example.com" {
		t.Fatalf("authorize = proxy:%q binding:%q metadata:%+v err:%v", proxy, tunnel.binding, tunnel.metadata, err)
	}

	tunnel.authorizeErr = errors.New("operator REJECT")
	if proxy, err = authorizeWithTunnel(tunnel, state, C.TCP, "origin.example.com", 443, "extension.a", true); err == nil || proxy != "" {
		t.Fatalf("rejected pooled authorize = proxy:%q err:%v", proxy, err)
	}
}

func TestTransformedTCPPassesSelectedEgressBinding(t *testing.T) {
	policy := &dialTestPolicy{group: "GroupA"}
	state := &trafficAuthorization{policy: policy, proxyExists: func(name string) bool { return name == "GroupA" }}
	tunnel := &dialTestTunnel{}
	conn, err := tcpWithAuthorization(
		context.Background(), tunnel, state,
		"origin.example.com", 443, "extension.a", true,
	)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if tunnel.dialCalls != 1 || tunnel.dialAddress != "origin.example.com:443" || tunnel.dialBinding != "GroupA" {
		t.Fatalf("TCP dial calls=%d address=%q binding=%q", tunnel.dialCalls, tunnel.dialAddress, tunnel.dialBinding)
	}
	if len(policy.metadata) != 1 || policy.metadata[0].Type != C.INNER || policy.metadata[0].NetWork != C.TCP {
		t.Fatalf("TCP authorization metadata = %+v", policy.metadata)
	}
	if policy.owner != "extension.a" || !policy.ownerOnly {
		t.Fatalf("TCP owner = %q, ownerOnly=%v", policy.owner, policy.ownerOnly)
	}
}

func TestTransformedTCPFailsBeforeHandlerWhenGroupIsMissing(t *testing.T) {
	policy := &dialTestPolicy{group: "RemovedGroup"}
	state := &trafficAuthorization{policy: policy, proxyExists: func(string) bool { return false }}
	tunnel := &dialTestTunnel{}
	_, err := tcpWithAuthorization(
		context.Background(), tunnel, state,
		"origin.example.com", 443, "extension.a", false,
	)
	if err == nil || tunnel.dialCalls != 0 {
		t.Fatalf("missing group TCP err=%v dial calls=%d", err, tunnel.dialCalls)
	}
}

func TestTransformedDialRejectsAnEmptyPolicyBinding(t *testing.T) {
	policy := &dialTestPolicy{group: ""}
	state := &trafficAuthorization{policy: policy, proxyExists: func(string) bool { return true }}
	tunnel := &dialTestTunnel{}
	_, err := tcpWithAuthorization(
		context.Background(), tunnel, state,
		"origin.example.com", 443, "extension.a", false,
	)
	if err == nil || tunnel.dialCalls != 0 {
		t.Fatalf("empty binding err=%v dial calls=%d, want fail before dial", err, tunnel.dialCalls)
	}
}

func TestTransformedDialFailsBeforeHandlerWhenBindingIsUnauthorized(t *testing.T) {
	policy := &dialTestPolicy{err: errors.New("required binding missing")}
	state := &trafficAuthorization{policy: policy, proxyExists: func(string) bool { return true }}
	tunnel := &dialTestTunnel{}
	_, err := tcpWithAuthorization(
		context.Background(), tunnel, state,
		"origin.example.com", 443, "extension.a", true,
	)
	if err == nil || tunnel.dialCalls != 0 {
		t.Fatalf("unauthorized binding err=%v dial calls=%d", err, tunnel.dialCalls)
	}
}
