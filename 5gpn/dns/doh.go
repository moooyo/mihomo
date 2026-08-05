package dns

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"time"

	D "github.com/miekg/dns"
)

// dohMediaType is the RFC 8484 wire-format type, used for both the request body
// and the expected response.
const dohMediaType = "application/dns-message"

// dohMaxResponse bounds how much of a response body is read. A DNS message
// cannot exceed this, and without the limit a hostile or broken resolver could
// stream unbounded data into the process that every client depends on.
const dohMaxResponse = D.MaxMsgSize

// dohClient is one DoH member: a pooled HTTP/2 client pinned to a dial address.
//
// HTTP/2 rather than a hand-rolled DoT connection pool for two reasons. A
// pooled DoT connection has to demultiplex replies itself, and the only
// correlator available is the client's own query ID -- which arrives from stub
// resolvers that commonly use small or sequential values, so two concurrent
// queries can collide and hand one client another's answer. HTTP/2 stream IDs
// do that demultiplexing at the transport.
//
// The decisive one is cancellation. Arbitration abandons the losing group on
// every china-CN win, which on domestic-heavy traffic is most cache misses.
// Cancelling an HTTP/2 request resets that stream and leaves the connection
// pooled; the equivalent on a shared DoT connection abandons a read mid-frame
// and desyncs every query behind it.
type dohClient struct {
	endpoint string
	http     *http.Client
	// transport is retained so idle connections can be closed when the group is
	// retired. Without the handle they stay reachable through the pool and are
	// never collected.
	transport *http.Transport
}

// newDoHClient builds a pooled client for one member.
//
// dialAddr pins the TCP destination: resolving the endpoint's hostname would
// have to come back through this resolver, so the operator supplies the address
// and the hostname is used only for certificate verification and the Host
// header.
func newDoHClient(endpoint, serverName, dialAddr string, sessions tls.ClientSessionCache) (*dohClient, error) {
	u, err := url.Parse(endpoint)
	if err != nil {
		return nil, fmt.Errorf("doh: parse %q: %w", endpoint, err)
	}
	if u.Scheme != "https" || u.Host == "" {
		return nil, fmt.Errorf("doh: %q must be an absolute https URL", endpoint)
	}
	if serverName == "" {
		serverName = u.Hostname()
	}

	transport := &http.Transport{
		// Without this net/http silently drops to HTTP/1.1 for any transport
		// carrying a dial override, and HTTP/1.1 serves one query per
		// connection at a time -- the multiplexing this type exists for.
		ForceAttemptHTTP2: true,
		TLSClientConfig: &tls.Config{
			ServerName:         serverName,
			ClientSessionCache: sessions,
			MinVersion:         tls.VersionTLS12,
		},
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return (&net.Dialer{Timeout: 5 * time.Second, KeepAlive: 30 * time.Second}).DialContext(ctx, network, dialAddr)
		},
		// One member is one origin, so per-host and total are the same bound. A
		// small pool is right: upstream concurrency is already bounded by the
		// cache, the single-flight collapse and admission control, so a larger
		// one would only hold idle sockets open.
		MaxIdleConns:        4,
		MaxIdleConnsPerHost: 4,
		// Comfortably under the idle timeout public resolvers apply, so this
		// side closes first rather than racing a server-side FIN.
		IdleConnTimeout:     25 * time.Second,
		TLSHandshakeTimeout: 5 * time.Second,
	}

	return &dohClient{
		endpoint:  u.String(),
		transport: transport,
		// No client timeout: the caller's context already carries the
		// per-attempt budget, and a second independent deadline would cut an
		// exchange the group still considers live.
		http: &http.Client{Transport: transport},
	}, nil
}

// exchange performs one RFC 8484 POST.
func (c *dohClient) exchange(ctx context.Context, q *D.Msg) (*D.Msg, error) {
	// RFC 8484 4.1: the ID SHOULD be 0, because HTTP already correlates request
	// and response. Sending the client's ID would leak it upstream for no
	// benefit. It is restored on the reply so matching downstream is unchanged.
	sent := q.Copy()
	originalID := q.Id
	sent.Id = 0

	wire, err := sent.Pack()
	if err != nil {
		return nil, fmt.Errorf("doh: pack: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.endpoint, bytes.NewReader(wire))
	if err != nil {
		return nil, fmt.Errorf("doh: build request: %w", err)
	}
	req.Header.Set("Content-Type", dohMediaType)
	req.Header.Set("Accept", dohMediaType)

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("doh: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		// Drain a bounded amount so the connection returns to the pool instead
		// of being abandoned mid-body.
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, dohMaxResponse))
		return nil, fmt.Errorf("doh: upstream returned HTTP %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, dohMaxResponse))
	if err != nil {
		return nil, fmt.Errorf("doh: read body: %w", err)
	}

	reply := new(D.Msg)
	if err := reply.Unpack(body); err != nil {
		return nil, fmt.Errorf("doh: unpack: %w", err)
	}
	reply.Id = originalID
	return reply, nil
}

func (c *dohClient) closeIdle() {
	if c != nil && c.transport != nil {
		c.transport.CloseIdleConnections()
	}
}
