package dns

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/metacubex/mihomo/log"

	D "github.com/miekg/dns"
)

// Exchanger sends a query and returns the reply. A single member or a whole
// group satisfies it, which is what lets an extension's resolver binding and
// the two operator groups be handled by the same code.
type Exchanger interface {
	Exchange(ctx context.Context, q *D.Msg) (*D.Msg, error)
}

// Transport is the wire protocol of one member. It is a per-MEMBER property,
// never per-group: a domestic resolver reachable only over plaintext UDP and
// one offering DoH can sit in the same pool, and the group dispatches on it.
type Transport uint8

const (
	// TransportUDP is a bare "IP[:port]" member: plain UDP to a resolver on a
	// path clean enough that demanding a certificate would only break
	// resolution.
	TransportUDP Transport = iota
	// TransportDoT is "serverName@IP[:port]": TLS verified against serverName,
	// dialed at the pinned address.
	TransportDoT
	// TransportDoH is "https://host/path@IP[:port]": RFC 8484 over a pooled
	// HTTP/2 connection. Preferred where a resolver offers it, because the
	// connection stays warm and a query costs one round trip instead of the
	// three a per-query TCP+TLS handshake costs.
	TransportDoH
)

// MemberSpec is one parsed upstream member.
type MemberSpec struct {
	Raw        string
	Transport  Transport
	ServerName string // TLS identity, for DoT and DoH
	DialAddr   string // the address actually dialed, with a port
	Endpoint   string // absolute https:// URL, DoH only
}

// ErrInvalidUpstream wraps every caller-caused spec failure, so the API can
// answer 400 for a bad spec and 500 for a disk failure while persisting a good
// one.
var ErrInvalidUpstream = errors.New("gpn/dns: invalid upstream")

// hostnameRE matches dot-separated LDH labels. Deliberately simple: it only has
// to reject obvious garbage before the value becomes a TLS server name, not to
// fully implement RFC 1035.
var hostnameRE = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?)*$`)

// ParseMember parses and validates one spec against the grammar both groups
// share:
//
//	IP[:port]                    plain UDP :53
//	serverName@IP[:port]         DoT :853, verified against serverName
//	https://host/path@IP[:port]  DoH :443 over pooled HTTP/2
//
// Validation and parsing are one function on purpose. They used to be two --
// a validator that rejected a spec and a parser that silently skipped it -- and
// two implementations of one grammar drift: whatever the parser skipped became
// a group quietly one member short of what the operator configured.
//
// The address after '@' is mandatory for DoT and DoH, and a bare hostname is
// refused outright, because resolving an upstream's own name would have to come
// back through this resolver.
func ParseMember(spec string) (MemberSpec, error) {
	spec = strings.TrimSpace(spec)
	if spec == "" {
		return MemberSpec{}, fmt.Errorf("%w: empty entry", ErrInvalidUpstream)
	}
	at := strings.LastIndex(spec, "@")

	switch {
	case strings.HasPrefix(spec, "https://"):
		if at <= 0 {
			return MemberSpec{}, fmt.Errorf("%w: %q needs a pinned address, e.g. https://dns.google/dns-query@8.8.8.8", ErrInvalidUpstream, spec)
		}
		endpoint, dial := spec[:at], spec[at+1:]
		u, err := url.Parse(endpoint)
		if err != nil || u.Scheme != "https" || u.Hostname() == "" {
			return MemberSpec{}, fmt.Errorf("%w: %q has a bad DoH endpoint %q", ErrInvalidUpstream, spec, endpoint)
		}
		if u.Path == "" || u.Path == "/" {
			return MemberSpec{}, fmt.Errorf("%w: %q needs an endpoint path, e.g. /dns-query", ErrInvalidUpstream, spec)
		}
		if !hostnameRE.MatchString(u.Hostname()) && !isIPLiteral(u.Hostname()) {
			return MemberSpec{}, fmt.Errorf("%w: %q has a bad DoH host %q", ErrInvalidUpstream, spec, u.Hostname())
		}
		addr, err := dialAddr(dial, "443")
		if err != nil {
			return MemberSpec{}, fmt.Errorf("%w: %q: %v", ErrInvalidUpstream, spec, err)
		}
		return MemberSpec{Raw: spec, Transport: TransportDoH, ServerName: u.Hostname(), DialAddr: addr, Endpoint: u.String()}, nil

	case at > 0:
		name, dial := spec[:at], spec[at+1:]
		if !hostnameRE.MatchString(name) && !isIPLiteral(name) {
			return MemberSpec{}, fmt.Errorf("%w: %q has a bad server name %q", ErrInvalidUpstream, spec, name)
		}
		addr, err := dialAddr(dial, "853")
		if err != nil {
			return MemberSpec{}, fmt.Errorf("%w: %q: %v", ErrInvalidUpstream, spec, err)
		}
		return MemberSpec{Raw: spec, Transport: TransportDoT, ServerName: name, DialAddr: addr}, nil

	default:
		addr, err := dialAddr(spec, "53")
		if err != nil {
			return MemberSpec{}, fmt.Errorf("%w: %q: want IP[:port] for plain UDP, serverName@IP for DoT, or https://host/path@IP for DoH", ErrInvalidUpstream, spec)
		}
		return MemberSpec{Raw: spec, Transport: TransportUDP, DialAddr: addr}, nil
	}
}

// ParseMembers parses a whole list and requires at least one member. A group
// with no members answers nothing, and the failure surfaces as every query
// timing out rather than as a configuration error, so it is refused here.
func ParseMembers(label string, specs []string) ([]MemberSpec, error) {
	out := make([]MemberSpec, 0, len(specs))
	for _, s := range specs {
		if strings.TrimSpace(s) == "" {
			continue
		}
		m, err := ParseMember(s)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", label, err)
		}
		out = append(out, m)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("%w: %s group is empty", ErrInvalidUpstream, label)
	}
	return out, nil
}

func isIPLiteral(s string) bool {
	_, err := netip.ParseAddr(s)
	return err == nil
}

// dialAddr normalises "IP" or "IP:port" to a dialable address, defaulting the
// port. Only IP literals are accepted, for the self-reference reason above.
func dialAddr(raw, defaultPort string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", errors.New("dial address is empty")
	}
	if addr, err := netip.ParseAddr(raw); err == nil {
		return net.JoinHostPort(addr.String(), defaultPort), nil
	}
	host, port, err := net.SplitHostPort(raw)
	if err != nil {
		return "", fmt.Errorf("dial part %q must be IP or IP:port", raw)
	}
	addr, err := netip.ParseAddr(host)
	if err != nil {
		return "", fmt.Errorf("dial part %q must be IP or IP:port", raw)
	}
	// SplitHostPort validates only the shape; parse the value so both 0 and
	// anything above 65535 are refused rather than handed to the dialer.
	p, err := strconv.ParseUint(port, 10, 16)
	if err != nil || p == 0 {
		return "", fmt.Errorf("dial part %q has an invalid port", raw)
	}
	return net.JoinHostPort(addr.String(), port), nil
}

// member is one built upstream: what to dial and how.
type member struct {
	spec   MemberSpec
	net    string      // "udp" or "tcp-tls"; empty for DoH
	tlsCfg *tls.Config // nil for plain UDP
	doh    *dohClient  // non-nil only for DoH
}

// group is one of the two operator upstream pools.
//
// Members are tried SEQUENTIALLY in configured order and the first success
// wins. That order is the operator's stated preference, so racing them would
// substitute "whichever is fastest right now" for a decision they made
// deliberately.
type group struct {
	members []member
	label   string
	breaker *breaker

	// ecs is the client subnet attached to every outgoing query, set only on
	// the china group. An atomic pointer because the console swaps it while
	// queries are reading it.
	ecs atomic.Pointer[netip.Prefix]
}

// newGroup builds a group from parsed specs.
func newGroup(label string, specs []MemberSpec) *group {
	sessions := tls.NewLRUClientSessionCache(0)
	members := make([]member, 0, len(specs))
	for _, s := range specs {
		switch s.Transport {
		case TransportDoH:
			client, err := newDoHClient(s.Endpoint, s.ServerName, s.DialAddr, sessions)
			if err != nil {
				// ParseMember rejects a malformed endpoint long before here, so
				// this is defensive. Degrade the member rather than the group:
				// with no doh client its attempt fails and the loop rolls to the
				// next member, which is strictly better than refusing to build a
				// resolver the gateway cannot start without.
				log.Warnln("[GPN/DNS] %s upstream %q: %v -- member disabled", label, s.Raw, err)
				members = append(members, member{spec: s})
				continue
			}
			members = append(members, member{spec: s, doh: client})
		case TransportDoT:
			members = append(members, member{
				spec:   s,
				net:    "tcp-tls",
				tlsCfg: &tls.Config{ServerName: s.ServerName, ClientSessionCache: sessions, MinVersion: tls.VersionTLS12},
			})
		default:
			members = append(members, member{spec: s, net: "udp"})
		}
	}
	return &group{members: members, label: label, breaker: newBreaker()}
}

// SetECS sets or, with an invalid prefix, clears the subnet attached to
// outgoing queries.
func (g *group) SetECS(p netip.Prefix) {
	if g == nil {
		return
	}
	if !p.IsValid() {
		g.ecs.Store(nil)
		return
	}
	g.ecs.Store(&p)
}

// ECS reports the attached subnet, or the zero prefix when disabled.
func (g *group) ECS() netip.Prefix {
	if g == nil {
		return netip.Prefix{}
	}
	if p := g.ecs.Load(); p != nil {
		return *p
	}
	return netip.Prefix{}
}

// Specs reports the raw member specs, for the API and diagnostics.
func (g *group) Specs() []string {
	if g == nil {
		return nil
	}
	out := make([]string, 0, len(g.members))
	for _, m := range g.members {
		out = append(out, m.spec.Raw)
	}
	return out
}

// Exchange tries members in order and returns the first success.
//
// Each attempt gets an even share of what remains of the caller's deadline
// (remaining / members-left), so a dead first member cannot swallow the whole
// query budget and starve the ones behind it, and whatever an early failure
// does not spend rolls forward to the next.
func (g *group) Exchange(ctx context.Context, q *D.Msg) (*D.Msg, error) {
	if !g.breaker.allow() {
		return nil, fmt.Errorf("gpn/dns: %s group circuit open", g.label)
	}

	// Always send a private copy with the client's subnet removed. Only the
	// operator's configured value may leave the gateway, trust must never
	// receive one at all, and a client-supplied value must never influence a
	// response another client will read out of the cache.
	send := q.Copy()
	stripECS(send)
	if p := g.ecs.Load(); p != nil {
		setECS(send, *p)
	}

	var lastErr error
	for i, m := range g.members {
		attemptCtx := ctx
		var cancel context.CancelFunc
		if dl, ok := ctx.Deadline(); ok {
			attemptCtx, cancel = context.WithTimeout(ctx, time.Until(dl)/time.Duration(len(g.members)-i))
		}
		msg, err := m.exchange(attemptCtx, send)
		if cancel != nil {
			cancel()
		}

		// Caller cancellation is not an upstream health signal -- see
		// breaker.recordCanceled. Checked on the PARENT context, because an
		// attempt-slice timeout is DeadlineExceeded on the child only and must
		// keep the loop going.
		if ctx.Err() == context.Canceled {
			g.breaker.recordCanceled()
			if err == nil {
				err = ctx.Err()
			}
			return nil, fmt.Errorf("gpn/dns: %s exchange abandoned by caller: %w", g.label, err)
		}

		if err == nil {
			// The subnet is an upstream implementation detail. Strip an echo, or
			// an option nobody asked for, whether or not we sent one.
			stripECS(msg)
			g.breaker.record(true)
			return msg, nil
		}
		lastErr = err
	}

	if lastErr == nil {
		lastErr = errors.New("no members configured")
	}
	g.breaker.record(false)
	return nil, fmt.Errorf("gpn/dns: all %s upstreams failed: %w", g.label, lastErr)
}

func (m member) exchange(ctx context.Context, q *D.Msg) (*D.Msg, error) {
	if m.doh != nil {
		// Pooled HTTP/2: no per-query handshake, and cancelling resets one
		// stream rather than tearing down the connection.
		return m.doh.exchange(ctx, q)
	}
	if m.net == "" {
		return nil, fmt.Errorf("gpn/dns: member %q is disabled", m.spec.Raw)
	}
	c := &D.Client{Net: m.net, TLSConfig: m.tlsCfg}
	msg, _, err := c.ExchangeContext(ctx, q, m.spec.DialAddr)
	// miekg deliberately does not retry a truncated UDP reply over TCP. Do it
	// inside this member's own slice, so a DoT client is never handed a TC
	// response it cannot act on over an already-stream transport.
	if err == nil && msg != nil && msg.Truncated && m.net == "udp" {
		tcp := &D.Client{Net: "tcp"}
		msg, _, err = tcp.ExchangeContext(ctx, q, m.spec.DialAddr)
	}
	return msg, err
}

// Close releases pooled connections.
//
// Only DoH members hold any: the UDP and DoT paths build a throwaway client per
// attempt whose socket miekg closes on return, while a DoH member's idle
// connections live in a transport the group keeps reachable. A group replaced
// without this leaks one descriptor per pooled connection on every upstream
// edit, and the console can issue those as fast as an operator can click.
func (g *group) Close() {
	if g == nil {
		return
	}
	for _, m := range g.members {
		m.doh.closeIdle()
	}
}

// retire closes a replaced group's connections after a grace window.
//
// Not immediately: a query that already loaded the old snapshot holds the old
// group for up to the query timeout and is entitled to finish against it.
// Close only reclaims idle connections anyway, so the grace costs nothing.
func retire(p pool, grace time.Duration) {
	if p == nil {
		return
	}
	time.AfterFunc(grace, p.Close)
}
