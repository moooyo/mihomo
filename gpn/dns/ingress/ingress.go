// Package ingress owns the client-facing DNS listeners.
//
// mihomo has no DNS-over-TLS server. Its dns/server.go serves UDP and TCP from a
// package-level singleton, and dot.go/doh.go are upstream *client* transports.
// So this is not a wrapper over something that exists -- it is the listener 5gpn
// clients actually connect to, and it lives here because it must survive things
// that would take mihomo's own resolver down with them.
//
// Specifically: hub/executor.updateDNS reassigns six resolver globals and calls
// dns.ReCreateServer on every ApplyConfig. Nothing in this package touches those,
// so an operator editing an unrelated proxy does not rebind the port every phone
// on the network is pointed at.
package ingress

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"

	"github.com/metacubex/mihomo/log"
	"github.com/metacubex/tls"

	D "github.com/miekg/dns"
)

// CertificateSource supplies the DoT leaf, re-read on every handshake.
//
// A function rather than a tls.Certificate because the Let's Encrypt lineage is
// renewed underneath a running process by a root oneshot. Capturing the
// certificate at bind time means serving an expired one until someone restarts
// the gateway -- and nothing observes that until clients start failing.
type CertificateSource func(*tls.ClientHelloInfo) (*tls.Certificate, error)

// Config is what the ingress needs to bind. Empty addresses are not bound.
type Config struct {
	// DoT is the public client ingress, conventionally :853.
	DoT string
	// Debug is a plain-UDP listener for local troubleshooting. It must be
	// loopback: it answers the same policy as the public listener without TLS,
	// so a non-loopback bind is an open resolver.
	Debug string
	// Certificate supplies the DoT leaf. Required when DoT is set.
	Certificate CertificateSource
}

// Ingress holds the bound listeners.
type Ingress struct {
	mu      sync.Mutex
	servers []*D.Server
}

// Start binds every configured listener and begins serving.
//
// Binds are synchronous and a failure is returned, because the alternative has
// exactly one outcome worth naming: a process that reports healthy -- systemd
// active, watchdog fed -- while :853 is dead and every client on the network has
// silently lost name resolution. Serve errors after a successful bind are logged
// instead, since by then the socket is up and the caller has nothing useful to
// decide.
func (i *Ingress) Start(cfg Config, handler D.Handler) error {
	if handler == nil {
		return errors.New("gpn/dns/ingress: no handler")
	}

	i.mu.Lock()
	defer i.mu.Unlock()
	if len(i.servers) > 0 {
		return errors.New("gpn/dns/ingress: already started")
	}

	if cfg.DoT != "" {
		if cfg.Certificate == nil {
			return errors.New("gpn/dns/ingress: DoT requires a certificate source")
		}
		ln, err := tls.Listen("tcp", cfg.DoT, &tls.Config{
			MinVersion:     tls.VersionTLS12,
			GetCertificate: cfg.Certificate,
		})
		if err != nil {
			return fmt.Errorf("gpn/dns/ingress: DoT listen %s: %w", cfg.DoT, err)
		}
		i.serve(&D.Server{Listener: ln, Handler: handler}, "DoT "+cfg.DoT)
	}

	if cfg.Debug != "" {
		if err := requireLoopback(cfg.Debug); err != nil {
			i.shutdownLocked()
			return err
		}
		pc, err := net.ListenPacket("udp", cfg.Debug)
		if err != nil {
			i.shutdownLocked()
			return fmt.Errorf("gpn/dns/ingress: debug listen %s: %w", cfg.Debug, err)
		}
		i.serve(&D.Server{PacketConn: pc, Handler: handler}, "debug UDP "+cfg.Debug)
	}

	return nil
}

func (i *Ingress) serve(srv *D.Server, what string) {
	i.servers = append(i.servers, srv)
	go func() {
		if err := srv.ActivateAndServe(); err != nil {
			log.Errorln("[GPN/DNS] %s stopped: %v", what, err)
		}
	}()
}

// Shutdown stops every listener, bounded by ctx.
func (i *Ingress) Shutdown(ctx context.Context) {
	i.mu.Lock()
	defer i.mu.Unlock()
	var wg sync.WaitGroup
	for _, srv := range i.servers {
		wg.Add(1)
		go func(srv *D.Server) {
			defer wg.Done()
			_ = srv.ShutdownContext(ctx)
		}(srv)
	}
	wg.Wait()
	i.servers = nil
}

// shutdownLocked closes what is already bound when a later bind fails. Callers
// hold i.mu. Without it a partial Start leaves a listener serving behind an
// error the caller is about to treat as "nothing came up".
func (i *Ingress) shutdownLocked() {
	for _, srv := range i.servers {
		_ = srv.Shutdown()
	}
	i.servers = nil
}

// requireLoopback refuses a debug listener that would be an open resolver.
//
// The debug listener answers the same policy as the public one with no TLS and
// no client identity. On a public address that is an open resolver -- usable for
// amplification, and answering for a network it was never meant to serve.
func requireLoopback(addr string) error {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("gpn/dns/ingress: debug address %q must be host:port: %w", addr, err)
	}
	if port == "" || port == "0" {
		return fmt.Errorf("gpn/dns/ingress: debug address %q must name a port", addr)
	}
	ip := net.ParseIP(host)
	if ip == nil || !ip.IsLoopback() {
		return fmt.Errorf("gpn/dns/ingress: debug address %q must be a loopback IP", addr)
	}
	return nil
}
