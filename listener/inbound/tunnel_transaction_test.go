package inbound

import (
	"context"
	"errors"
	"net"
	"testing"
)

type tunnelTestListenConfig struct {
	listener *tunnelTestListener
	err      error
	calls    int
}

func (c *tunnelTestListenConfig) Listen(context.Context, string, string) (net.Listener, error) {
	c.calls++
	if c.calls == 1 {
		return c.listener, nil
	}
	return nil, c.err
}

func (c *tunnelTestListenConfig) ListenPacket(context.Context, string, string) (net.PacketConn, error) {
	return nil, errors.New("unexpected packet listener")
}

type tunnelTestListener struct {
	closed chan struct{}
}

func (l *tunnelTestListener) Accept() (net.Conn, error) {
	<-l.closed
	return nil, net.ErrClosed
}

func (l *tunnelTestListener) Close() error {
	select {
	case <-l.closed:
	default:
		close(l.closed)
	}
	return nil
}

func (l *tunnelTestListener) Addr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 10000}
}

func TestTunnelListenClosesEarlierAddressesAfterLaterBindFailure(t *testing.T) {
	bindErr := errors.New("second bind failed")
	first := &tunnelTestListener{closed: make(chan struct{})}
	listenConfig := &tunnelTestListenConfig{listener: first, err: bindErr}
	listener, err := NewTunnel(&TunnelOption{
		BaseOption: BaseOption{
			NameStr:            "transactional",
			Listen:             "127.0.0.1",
			Port:               "10000,10001",
			ListenConfigForAPI: listenConfig,
		},
		Network: []string{"tcp"},
		Target:  "example.com:80",
	})
	if err != nil {
		t.Fatal(err)
	}

	err = listener.Listen(nil)
	if !errors.Is(err, bindErr) {
		t.Fatalf("Listen error = %v, want second bind failure", err)
	}
	select {
	case <-first.closed:
	default:
		t.Fatal("the first address remained live after the second bind failed")
	}
	if len(listener.ttl) != 0 || len(listener.tul) != 0 {
		t.Fatal("failed Listen retained closed listener handles")
	}
	if err := listener.Close(); err != nil {
		t.Fatalf("Close after failed Listen returned %v", err)
	}
}
