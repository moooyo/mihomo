package dns

import (
	"bytes"
	"context"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	D "github.com/miekg/dns"
)

// Everything else in this package tests the decision path with the transport
// removed. This file is the other half: the service opens a document, binds
// what the document names, and serves the two boundaries over real sockets.
//
// It is worth its own file because the seam it covers is the one that unit
// tests structurally cannot reach. resolve() returning the right message proves
// nothing about whether :853 is bound, whether the origin listener got the
// origin handler rather than the client one, or whether a document edit
// actually reaches the running resolver -- and each of those failures presents
// as "DNS is broken" with every unit test still green.

// freePort asks the kernel for a port and immediately gives it back.
//
// The listeners under test refuse port 0: a loopback debug or origin listener
// that binds an arbitrary port would be one nothing can find. So the port has
// to be concrete, and this is the standard way to get one that is probably
// free. The window between close and re-bind is real but small, and the
// alternative -- a fixed port -- fails whenever two runs overlap, which on this
// project is routine.
func freePort(t *testing.T) string {
	t.Helper()
	for attempt := 0; attempt < 20; attempt++ {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("reserve TCP port: %v", err)
		}
		addr := ln.Addr().String()
		pc, err := net.ListenPacket("udp", addr)
		if err == nil {
			_ = pc.Close()
			_ = ln.Close()
			return addr
		}
		_ = ln.Close()
	}
	t.Fatal("could not find a port free for both TCP and UDP")
	return ""
}

// upstreamServer is a real DNS server standing in for a configured upstream.
func upstreamServer(t *testing.T, answer string) string {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("upstream listen: %v", err)
	}
	ready := make(chan struct{})
	srv := &D.Server{
		PacketConn:        pc,
		NotifyStartedFunc: func() { close(ready) },
		Handler: D.HandlerFunc(func(w D.ResponseWriter, req *D.Msg) {
			m := new(D.Msg)
			m.SetReply(req)
			if req.Question[0].Qtype == D.TypeA {
				m.Answer = []D.RR{&D.A{
					Hdr: D.RR_Header{Name: req.Question[0].Name, Rrtype: D.TypeA, Class: D.ClassINET, Ttl: 300},
					A:   net.ParseIP(answer),
				}}
			}
			_ = w.WriteMsg(m)
		}),
	}
	go func() { _ = srv.ActivateAndServe() }()
	t.Cleanup(func() { _ = srv.Shutdown() })
	<-ready
	return pc.LocalAddr().String()
}

// ask sends one query to addr over UDP and returns the reply.
func askOverWire(t *testing.T, addr, name string, qtype uint16) *D.Msg {
	t.Helper()
	req := new(D.Msg)
	req.SetQuestion(D.Fqdn(name), qtype)
	client := &D.Client{Net: "udp", Timeout: 5 * time.Second}
	reply, _, err := client.Exchange(req, addr)
	if err != nil {
		t.Fatalf("exchange with %s: %v", addr, err)
	}
	return reply
}

// startService opens a service in a temp directory and binds the two listeners
// that need no certificate. DoT is left unbound on purpose: it is the same
// handler as the debug listener, and binding it would drag a certificate
// lineage into a test about routing rather than about TLS.
func startService(t *testing.T, upstream string) (*Service, string, string) {
	t.Helper()
	dir := t.TempDir()
	debugAddr := freePort(t)
	originAddr := freePort(t)
	seed := DefaultDocument()
	seed.Listen.DoT = ""
	seed.Listen.Debug = debugAddr
	seed.Listen.Origin = originAddr
	seed.Gateway = "198.51.100.1"
	seed.Upstreams.China = []string{upstream}
	seed.Upstreams.Trust = []string{upstream}
	seed.Policy = Policy{
		Fallback: FallbackAuto,
		Rules: []Rule{
			{ID: "steer", Kind: KindDomainSuffix, Value: "corp.example", Intent: IntentProxy, Enabled: true},
			{ID: "deny", Kind: KindDomainSuffix, Value: "ads.example", Intent: IntentBlock, Enabled: true},
		},
	}
	raw, err := json.Marshal(seed)
	if err != nil {
		t.Fatalf("marshal seed: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "dns.json"), raw, 0o600); err != nil {
		t.Fatalf("write seed: %v", err)
	}

	svc, err := Open(dir)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		svc.Shutdown(ctx)
	})

	if err := svc.Listen(); err != nil {
		t.Fatalf("Listen: %v", err)
	}
	return svc, debugAddr, originAddr
}

// The two boundaries answer the same question differently, and that difference
// is the whole design. A test that only checked the client side would pass
// against a service that had accidentally installed the client handler on both.
func TestBothBoundariesServeAndDisagree(t *testing.T) {
	upstream := upstreamServer(t, "192.0.2.50")
	_, clientAddr, originAddr := startService(t, upstream)

	client := askOverWire(t, clientAddr, "www.corp.example", D.TypeA)
	if got := answerIPs(client, 4); !equalStrings(got, []string{"198.51.100.1"}) {
		t.Errorf("client answers %v, want the gateway address", got)
	}

	origin := askOverWire(t, originAddr, "www.corp.example", D.TypeA)
	if got := answerIPs(origin, 4); !equalStrings(got, []string{"192.0.2.50"}) {
		t.Errorf("origin answers %v, want the real address", got)
	}
}

// A blocked name is blocked for a client. It is deliberately NOT blocked at the
// origin boundary: by the time mihomo asks, the connection already exists, and
// refusing to tell it where the origin lives would strand a connection rather
// than prevent one.
func TestBlockAppliesToClientsOnly(t *testing.T) {
	upstream := upstreamServer(t, "192.0.2.60")
	_, clientAddr, originAddr := startService(t, upstream)

	if reply := askOverWire(t, clientAddr, "tracker.ads.example", D.TypeA); reply.Rcode != D.RcodeNameError {
		t.Errorf("client rcode %s, want NXDOMAIN", D.RcodeToString[reply.Rcode])
	}
	if reply := askOverWire(t, originAddr, "tracker.ads.example", D.TypeA); reply.Rcode != D.RcodeSuccess {
		t.Errorf("origin rcode %s, want the origin lookup to succeed", D.RcodeToString[reply.Rcode])
	}
}

// The origin boundary is what keeps egress on IPv4, so it has to withhold AAAA
// over the wire and not merely in the decision function.
func TestBothBoundariesWithholdAAAA(t *testing.T) {
	upstream := upstreamServer(t, "192.0.2.70")
	_, clientAddr, originAddr := startService(t, upstream)

	for _, addr := range []string{clientAddr, originAddr} {
		reply := askOverWire(t, addr, "www.corp.example", D.TypeAAAA)
		if reply.Rcode != D.RcodeSuccess {
			t.Errorf("%s: AAAA rcode %s, want NOERROR", addr, D.RcodeToString[reply.Rcode])
		}
		if len(reply.Answer) != 0 {
			t.Errorf("%s: AAAA returned %d records", addr, len(reply.Answer))
		}
		// The SOA is what lets the asker negatively cache. Without it, mihomo
		// re-asks on every single connection.
		if len(reply.Ns) != 1 {
			t.Errorf("%s: AAAA carried %d authority records, want the synthetic SOA", addr, len(reply.Ns))
		}
	}
}

// An edit has to reach the running resolver, not just the file. This is the
// failure that unit tests cannot see: the document persists, the page shows the
// new rule, and traffic keeps following the old one.
func TestDocumentEditReachesTheRunningResolver(t *testing.T) {
	upstream := upstreamServer(t, "192.0.2.80")
	svc, clientAddr, _ := startService(t, upstream)

	if got := answerIPs(askOverWire(t, clientAddr, "www.corp.example", D.TypeA), 4); !equalStrings(got, []string{"198.51.100.1"}) {
		t.Fatalf("before the edit: %v", got)
	}

	_, revision := svc.Document()
	if _, _, err := svc.Update(revision, func(d Document) (Document, error) {
		d.Policy.Rules[0].Intent = IntentDirect
		return d, nil
	}); err != nil {
		t.Fatalf("Update: %v", err)
	}

	// No sleep and no cache flush by hand: publishing a policy flushes, and if
	// it did not, this assertion is exactly the one that would fail.
	if got := answerIPs(askOverWire(t, clientAddr, "www.corp.example", D.TypeA), 4); !equalStrings(got, []string{"192.0.2.80"}) {
		t.Errorf("after the edit: %v, want the real address -- the change did not reach the resolver", got)
	}
}

// A listener change rebinds; an unrelated change must not. Rebinding on every
// edit would drop :853 whenever an operator touched a policy rule, and each of
// those is a moment where every client on the network has no resolver.
func TestOnlyAListenerChangeRebinds(t *testing.T) {
	upstream := upstreamServer(t, "192.0.2.90")
	svc, clientAddr, _ := startService(t, upstream)

	svc.mu.Lock()
	before := svc.ing
	svc.mu.Unlock()

	_, revision := svc.Document()
	if _, _, err := svc.Update(revision, func(d Document) (Document, error) {
		d.Upstreams.ECS = "203.0.113.0/24"
		return d, nil
	}); err != nil {
		t.Fatalf("Update: %v", err)
	}

	svc.mu.Lock()
	after := svc.ing
	svc.mu.Unlock()
	if before != after {
		t.Error("an upstream edit rebound the listeners")
	}
	// And the socket is still serving, which is the property the pointer
	// comparison is standing in for.
	if reply := askOverWire(t, clientAddr, "www.corp.example", D.TypeA); reply.Rcode != D.RcodeSuccess {
		t.Errorf("listener stopped answering after an unrelated edit: %s", D.RcodeToString[reply.Rcode])
	}
}

func TestListenerChangeDoesNotPublishDocument(t *testing.T) {
	upstream := upstreamServer(t, "192.0.2.95")
	svc, clientAddr, _ := startService(t, upstream)

	beforeDocument, beforeRevision := svc.Document()
	documentPath := filepath.Join(filepath.Dir(svc.rulesDir), "dns.json")
	beforeBytes, err := os.ReadFile(documentPath)
	if err != nil {
		t.Fatalf("read document before update: %v", err)
	}

	_, returnedRevision, err := svc.Update(beforeRevision, func(d Document) (Document, error) {
		d.Listen.Debug = freePort(t)
		d.Listen.Origin = ""
		return d, nil
	})
	if err == nil {
		t.Fatal("listener update changed installation-owned settings")
	}
	if !strings.Contains(err.Error(), "listener settings are installation-owned") {
		t.Fatalf("listener update error = %q", err)
	}
	if returnedRevision != beforeRevision {
		t.Fatalf("returned revision = %q, want %q", returnedRevision, beforeRevision)
	}
	afterDocument, afterRevision := svc.Document()
	if afterRevision != beforeRevision {
		t.Fatalf("live revision moved from %q to %q", beforeRevision, afterRevision)
	}
	if afterDocument.Listen != beforeDocument.Listen {
		t.Fatalf("live listeners changed from %+v to %+v", beforeDocument.Listen, afterDocument.Listen)
	}
	afterBytes, err := os.ReadFile(documentPath)
	if err != nil {
		t.Fatalf("read document after update: %v", err)
	}
	if !bytes.Equal(afterBytes, beforeBytes) {
		t.Fatal("failed listener update changed the persisted document")
	}
	if reply := askOverWire(t, clientAddr, "www.corp.example", D.TypeA); reply.Rcode != D.RcodeSuccess {
		t.Fatalf("old listener stopped after rejected update: %s", D.RcodeToString[reply.Rcode])
	}
}

func TestPolicyPreparationFailureDoesNotPublishDocument(t *testing.T) {
	upstream := upstreamServer(t, "192.0.2.96")
	svc, clientAddr, _ := startService(t, upstream)

	cachePath := subscriptionCachePath(svc.rulesDir, "unreadable-cache")
	if err := os.Mkdir(cachePath, 0o700); err != nil {
		t.Fatalf("create unreadable cache stand-in: %v", err)
	}
	documentPath := filepath.Join(filepath.Dir(svc.rulesDir), "dns.json")
	beforeBytes, err := os.ReadFile(documentPath)
	if err != nil {
		t.Fatalf("read document before update: %v", err)
	}
	_, beforeRevision := svc.Document()

	_, returnedRevision, err := svc.Update(beforeRevision, func(d Document) (Document, error) {
		d.Policy.Rules = append(d.Policy.Rules, Rule{
			ID: "unreadable-cache", Kind: KindSubscription,
			Value: "https://lists.example.test/rules.txt", Intent: IntentBlock, Enabled: true,
			Format: "plain", IntervalSeconds: 3600,
		})
		return d, nil
	})
	if err == nil {
		t.Fatal("policy update accepted an unreadable subscription cache")
	}
	if returnedRevision != beforeRevision {
		t.Fatalf("returned revision = %q, want %q", returnedRevision, beforeRevision)
	}
	_, afterRevision := svc.Document()
	if afterRevision != beforeRevision {
		t.Fatalf("live revision moved from %q to %q", beforeRevision, afterRevision)
	}
	afterBytes, err := os.ReadFile(documentPath)
	if err != nil {
		t.Fatalf("read document after update: %v", err)
	}
	if !bytes.Equal(afterBytes, beforeBytes) {
		t.Fatal("failed policy preparation changed the persisted document")
	}
	if reply := askOverWire(t, clientAddr, "www.corp.example", D.TypeA); reply.Rcode != D.RcodeSuccess {
		t.Fatalf("resolver stopped after rejected policy: %s", D.RcodeToString[reply.Rcode])
	}
}

// A document that cannot be parsed refuses to open. Resetting to defaults would
// discard the operator's policy and extensions without saying so, and the
// gateway would come up resolving names they meant to block.
func TestUnreadableDocumentRefusesToOpen(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "dns.json"), []byte("{ this is not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(dir); err == nil {
		t.Error("Open accepted an unparseable document")
	}
}

// An invalid document is refused before it is written, so a rejected edit
// leaves both the file and the running resolver exactly as they were.
func TestRejectedEditLeavesTheServiceRunning(t *testing.T) {
	upstream := upstreamServer(t, "192.0.2.100")
	svc, clientAddr, _ := startService(t, upstream)

	_, revision := svc.Document()
	if _, _, err := svc.Update(revision, func(d Document) (Document, error) {
		d.Upstreams.Trust = []string{"not-an-upstream"}
		return d, nil
	}); err == nil {
		t.Fatal("an invalid upstream spec was accepted")
	}

	if _, current := svc.Document(); current != revision {
		t.Errorf("the revision moved from %s to %s on a write that failed", revision, current)
	}
	if reply := askOverWire(t, clientAddr, "www.corp.example", D.TypeA); reply.Rcode != D.RcodeSuccess {
		t.Errorf("the resolver stopped answering after a rejected edit: %s", D.RcodeToString[reply.Rcode])
	}
}
