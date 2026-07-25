package socks

import (
	"context"
	"net"

	"github.com/metacubex/mihomo/adapter/inbound"
	N "github.com/metacubex/mihomo/common/net"
	"github.com/metacubex/mihomo/common/sockopt"
	"github.com/metacubex/mihomo/component/auth"
	C "github.com/metacubex/mihomo/constant"
	LC "github.com/metacubex/mihomo/listener/config"
	"github.com/metacubex/mihomo/log"
	"github.com/metacubex/mihomo/transport/socks5"
)

type UDPListener struct {
	packetConn net.PacketConn
	addr       string
	closed     bool
}

// RawAddress implements C.Listener
func (l *UDPListener) RawAddress() string {
	return l.addr
}

// Address implements C.Listener
func (l *UDPListener) Address() string {
	return l.packetConn.LocalAddr().String()
}

// Close implements C.Listener
func (l *UDPListener) Close() error {
	l.closed = true
	return l.packetConn.Close()
}

func NewUDP(addr string, tunnel C.Tunnel, additions ...inbound.Addition) (*UDPListener, error) {
	return NewUDPWithConfig(defaultConfig(addr), inbound.NewListenConfig(), tunnel, additions...)
}

func NewUDPWithConfig(config LC.AuthServer, lc C.InboundListenConfig, tunnel C.Tunnel, additions ...inbound.Addition) (*UDPListener, error) {
	if len(additions) == 0 {
		additions = []inbound.Addition{
			inbound.WithInName("DEFAULT-SOCKS"),
			inbound.WithSpecialRules(""),
		}
	}
	l, err := lc.ListenPacket(context.Background(), "udp", config.Listen)
	if err != nil {
		return nil, err
	}

	if err := sockopt.UDPReuseaddr(l); err != nil {
		log.Warnln("Failed to Reuse UDP Address: %s", err)
	}

	sl := &UDPListener{
		packetConn: l,
		addr:       config.Listen,
	}
	conn := N.NewEnhancePacketConn(l)
	go func() {
		for {
			data, put, remoteAddr, err := conn.WaitReadFrom()
			if err != nil {
				if put != nil {
					put()
				}
				if sl.closed {
					break
				}
				continue
			}
			handleSocksUDP(l, config.AuthStore, tunnel, data, put, remoteAddr, additions...)
		}
	}()

	return sl, nil
}

func handleSocksUDP(pc net.PacketConn, store auth.AuthStore, tunnel C.Tunnel, buf []byte, put func(), addr net.Addr, additions ...inbound.Addition) {
	// The TCP path has filtered the peer since forever; the UDP path never did.
	if inbound.IsRemoteAddrDisAllowed(addr) {
		if put != nil {
			put()
		}
		return
	}

	// When the listener authenticates, a datagram must belong to an
	// association an authenticated control connection opened. Without this a
	// credential-bearing SOCKS listener still accepts UDP from anyone, which
	// makes the credential meaningless for UDP.
	//
	// An unauthenticated listener keeps its historical behaviour: there is no
	// identity to bind an association to, and refusing would break every
	// open SOCKS deployment for no security gain.
	if store != nil && store.Authenticator() != nil {
		user, ok := lookupAssociation(pc.LocalAddr().String(), addr)
		if !ok {
			dropUnassociated(pc.LocalAddr().String(), addr)
			if put != nil {
				put()
			}
			return
		}
		additions = append(append([]inbound.Addition(nil), additions...), inbound.WithInUser(user))
	}

	target, payload, err := socks5.DecodeUDPPacket(buf)
	if err != nil {
		// Unresolved UDP packet, return buffer to the pool
		if put != nil {
			put()
		}
		return
	}
	packet := &packet{
		pc:      pc,
		rAddr:   addr,
		payload: payload,
		put:     put,
	}
	tunnel.HandleUDPPacket(inbound.NewPacket(target, packet, C.SOCKS5, additions...))
}
