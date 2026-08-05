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
	// Origin is the boundary mihomo's own resolver queries after the sniffer
	// recovers a hostname, conventionally 127.0.0.1:5354, bound on both UDP and
	// TCP. It must be loopback for the same reason Debug must: it answers
	// without policy, without TLS and without client identity.
	//
	// It exists as a socket rather than a function call because mihomo reaches
	// its resolver through package-level globals that hub/executor reassigns on
	// every ApplyConfig. A loopback nameserver named in the operator's own
	// config is the one seam that survives a reload without a single edit to an
	// upstream-owned file.
	Origin string
	// Certificate supplies the DoT leaf. Required when DoT is set.
	Certificate CertificateSource
	// Fatal receives an unexpected listener exit after a successful bind. The
	// process owner decides how to terminate; keeping that decision out of this
	// package makes the boundary deterministic to test without calling os.Exit.
	Fatal func(error)
}

// Ingress holds the bound listeners.
type Ingress struct {
	mu       sync.Mutex
	servers  []*D.Server
	fatal    func(error)
	stopping bool
	serveWG  sync.WaitGroup
}

// Start binds every configured listener and begins serving.
//
// Binds are synchronous and a failure is returned, because the alternative has
// exactly one outcome worth naming: a process that reports healthy -- systemd
// active, watchdog fed -- while :853 is dead and every client on the network has
// silently lost name resolution. An unexpected Serve return after a successful
// bind is reported through Fatal so the process owner can fail fast and let its
// supervisor restore the complete gateway.
func (i *Ingress) Start(cfg Config, client, originHandler D.Handler) error {
	if client == nil {
		return errors.New("5gpn/dns/ingress: no client handler")
	}

	i.mu.Lock()
	defer i.mu.Unlock()
	if len(i.servers) > 0 {
		return errors.New("5gpn/dns/ingress: already started")
	}
	i.fatal = cfg.Fatal
	i.stopping = false

	if cfg.DoT != "" {
		if cfg.Certificate == nil {
			return errors.New("5gpn/dns/ingress: DoT requires a certificate source")
		}
		ln, err := tls.Listen("tcp", cfg.DoT, &tls.Config{
			MinVersion:     tls.VersionTLS12,
			GetCertificate: cfg.Certificate,
		})
		if err != nil {
			return fmt.Errorf("5gpn/dns/ingress: DoT listen %s: %w", cfg.DoT, err)
		}
		if err := i.serve(&D.Server{Listener: ln, Handler: client}, "DoT "+cfg.DoT, true); err != nil {
			i.shutdownLocked()
			return err
		}
	}

	if cfg.Debug != "" {
		if err := requireLoopback("debug", cfg.Debug); err != nil {
			i.shutdownLocked()
			return err
		}
		pc, err := net.ListenPacket("udp", cfg.Debug)
		if err != nil {
			log.Warnln("[5GPN/DNS] optional debug UDP %s not bound: %v", cfg.Debug, err)
		} else if err := i.serve(&D.Server{PacketConn: pc, Handler: client}, "debug UDP "+cfg.Debug, false); err != nil {
			log.Warnln("[5GPN/DNS] optional debug UDP %s not started: %v", cfg.Debug, err)
		}
	}

	if cfg.Origin != "" {
		if originHandler == nil {
			i.shutdownLocked()
			return errors.New("5gpn/dns/ingress: origin address set with no handler")
		}
		if err := requireLoopback("origin", cfg.Origin); err != nil {
			i.shutdownLocked()
			return err
		}
		pc, err := net.ListenPacket("udp", cfg.Origin)
		if err != nil {
			i.shutdownLocked()
			return fmt.Errorf("5gpn/dns/ingress: origin listen %s: %w", cfg.Origin, err)
		}
		if err := i.serve(&D.Server{PacketConn: pc, Handler: originHandler}, "origin UDP "+cfg.Origin, true); err != nil {
			i.shutdownLocked()
			return err
		}
		// TCP as well: mihomo retries over TCP when a reply comes back
		// truncated, and a boundary that only speaks UDP turns a large answer
		// into a resolution failure at the exact moment egress needs it.
		ln, err := net.Listen("tcp", cfg.Origin)
		if err != nil {
			i.shutdownLocked()
			return fmt.Errorf("5gpn/dns/ingress: origin listen tcp %s: %w", cfg.Origin, err)
		}
		if err := i.serve(&D.Server{Listener: ln, Handler: originHandler}, "origin TCP "+cfg.Origin, true); err != nil {
			i.shutdownLocked()
			return err
		}
	}

	return nil
}

func (i *Ingress) serve(srv *D.Server, what string, critical bool) error {
	ready := make(chan struct{})
	earlyExit := make(chan error, 1)
	started := false
	srv.NotifyStartedFunc = func() {
		started = true
		close(ready)
	}
	i.servers = append(i.servers, srv)
	i.serveWG.Add(1)
	go func() {
		defer i.serveWG.Done()
		err := srv.ActivateAndServe()
		failure := ingressFailure(what, err)
		if !started {
			earlyExit <- failure
			return
		}

		i.mu.Lock()
		stopping, fatal := i.stopping, i.fatal
		i.mu.Unlock()
		if stopping {
			return
		}
		if critical && fatal != nil {
			fatal(failure)
			return
		}
		log.Errorln("[5GPN/DNS] %v", failure)
	}()

	select {
	case <-ready:
		return nil
	case err := <-earlyExit:
		return err
	}
}

func ingressFailure(what string, err error) error {
	if err == nil {
		err = errors.New("Serve returned without an error")
	}
	return fmt.Errorf("5gpn/dns/ingress: %s stopped: %w", what, err)
}

// Shutdown stops every listener, bounded by ctx.
func (i *Ingress) Shutdown(ctx context.Context) {
	i.PrepareShutdown()

	i.mu.Lock()
	servers := append([]*D.Server(nil), i.servers...)
	i.servers = nil
	i.mu.Unlock()

	var wg sync.WaitGroup
	for _, srv := range servers {
		wg.Add(1)
		go func(srv *D.Server) {
			defer wg.Done()
			_ = srv.ShutdownContext(ctx)
		}(srv)
	}
	wg.Wait()
}

// PrepareShutdown withdraws the fatal-error boundary before an intentional
// asynchronous drain begins. A relisten calls this synchronously after the new
// listeners are ready, closing the scheduling window in which an old listener
// could end normally and still be mistaken for a process-fatal failure.
func (i *Ingress) PrepareShutdown() {
	i.mu.Lock()
	i.stopping = true
	i.mu.Unlock()
}

// shutdownLocked closes what is already bound when a later bind fails. Callers
// hold i.mu. Without it a partial Start leaves a listener serving behind an
// error the caller is about to treat as "nothing came up".
func (i *Ingress) shutdownLocked() {
	i.stopping = true
	for _, srv := range i.servers {
		_ = srv.Shutdown()
	}
	i.servers = nil
}

// requireLoopback refuses a listener that would be an open resolver.
//
// The debug and origin listeners answer without TLS and without client
// identity. On a public address either is an open resolver -- usable for
// amplification, and answering for a network it was never meant to serve.
func requireLoopback(what, addr string) error {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("5gpn/dns/ingress: %s address %q must be host:port: %w", what, addr, err)
	}
	if port == "" || port == "0" {
		return fmt.Errorf("5gpn/dns/ingress: %s address %q must name a port", what, addr)
	}
	ip := net.ParseIP(host)
	if ip == nil || !ip.IsLoopback() {
		return fmt.Errorf("5gpn/dns/ingress: %s address %q must be a loopback IP", what, addr)
	}
	return nil
}
