package config

import (
	"errors"
	"strings"
	"testing"

	"github.com/metacubex/mihomo/component/overlay"
	C "github.com/metacubex/mihomo/constant"
	LC "github.com/metacubex/mihomo/listener/config"
	R "github.com/metacubex/mihomo/rules"
	RC "github.com/metacubex/mihomo/rules/common"

	"gopkg.in/yaml.v3"
)

// rulesFrom parses a rule list exactly the way parseRules does for the
// top-level list, including the wrapper, so the layout checks run against the
// same shapes they see in production.
func rulesFrom(t *testing.T, lines ...string) []C.Rule {
	t.Helper()
	proxies := map[string]C.Proxy{}
	out := make([]C.Rule, 0, len(lines))
	for i, line := range lines {
		tp, payload, target, params := RC.ParseRulePayload(line, true)
		r, err := R.ParseRule(tp, payload, target, params, nil)
		if err != nil {
			t.Fatalf("rule %d %q: %v", i, line, err)
		}
		out = append(out, r)
	}
	_ = proxies
	return out
}

const (
	anchorEgress = "RUNTIME-OVERLAY,5gpn,egress"
	anchorClient = "RUNTIME-OVERLAY,5gpn,client"
	terminator   = "IN-NAME,intercept-egress,REJECT"
)

func validLayout() []string {
	return []string{
		"DOMAIN,console.example.test,REJECT",
		anchorEgress,
		terminator,
		"AND,((DOMAIN,quic.example.test),(NETWORK,UDP)),REJECT",
		anchorClient,
		"DOMAIN,console.example.test,DIRECT",
		"MATCH,Proxies",
	}
}

func TestAnchorLayoutAccepted(t *testing.T) {
	layout, err := findAnchorLayout(rulesFrom(t, validLayout()...))
	if err != nil {
		t.Fatalf("valid layout rejected: %v", err)
	}
	if !layout.Present {
		t.Fatal("layout reported absent")
	}
	if layout.Owner != "5gpn" {
		t.Fatalf("owner = %q", layout.Owner)
	}
	if layout.EgressIndex != 1 || layout.ClientIndex != 4 {
		t.Fatalf("indices = %d/%d, want 1/4", layout.EgressIndex, layout.ClientIndex)
	}
	if len(layout.EgressListeners) != 1 || layout.EgressListeners[0] != "intercept-egress" {
		t.Fatalf("egress listeners = %v", layout.EgressListeners)
	}
}

func TestNoAnchorsIsNotAnError(t *testing.T) {
	layout, err := findAnchorLayout(rulesFrom(t, "DOMAIN,a.test,DIRECT", "MATCH,DIRECT"))
	if err != nil {
		t.Fatalf("anchor-free config rejected: %v", err)
	}
	if layout.Present {
		t.Fatal("anchor-free config reported anchors")
	}
}

func TestAnchorLayoutRejections(t *testing.T) {
	replace := func(mutate func([]string) []string) []string {
		return mutate(validLayout())
	}

	cases := map[string][]string{
		"missing client anchor": replace(func(r []string) []string {
			return append(r[:4:4], r[5:]...)
		}),
		"missing egress anchor": replace(func(r []string) []string {
			return append(r[:1:1], r[2:]...)
		}),
		"duplicate egress anchor": replace(func(r []string) []string {
			return append([]string{anchorEgress, terminator}, r...)
		}),
		"terminator not adjacent": replace(func(r []string) []string {
			out := append([]string{}, r[:2]...)
			out = append(out, "DOMAIN,gap.test,REJECT")
			return append(out, r[2:]...)
		}),
		"terminator is not a deny": replace(func(r []string) []string {
			r[2] = "IN-NAME,intercept-egress,DIRECT"
			return r
		}),
		"allow rule precedes the egress anchor": replace(func(r []string) []string {
			r[0] = "DOMAIN,console.example.test,DIRECT"
			return r
		}),
		"allow rule in the system guard slot": replace(func(r []string) []string {
			r[3] = "DOMAIN,console.example.test,DIRECT"
			return r
		}),
		"client anchor before egress anchor": {
			anchorClient, anchorEgress, terminator, "MATCH,DIRECT",
		},
		"anchors disagree on owner": {
			anchorEgress, terminator, "RUNTIME-OVERLAY,other,client", "MATCH,DIRECT",
		},
		"egress anchor is last": {anchorEgress},
	}

	for name, lines := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := findAnchorLayout(rulesFrom(t, lines...))
			if !errors.Is(err, overlay.ErrAnchorInvalid) {
				t.Fatalf("want ErrAnchorInvalid, got %v", err)
			}
		})
	}
}

// The anchors must not be constructible anywhere the structural validator
// cannot see them.
func TestAnchorRejectedInsideLogicRule(t *testing.T) {
	_, err := R.ParseRule("AND", "((RUNTIME-OVERLAY,5gpn,egress),(NETWORK,UDP))", "REJECT", nil, nil)
	if err == nil {
		t.Fatal("an anchor nested inside AND was accepted")
	}
	if !strings.Contains(err.Error(), "RUNTIME-OVERLAY") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestAnchorParsingValidatesStageAndParams(t *testing.T) {
	if _, err := R.ParseRule("RUNTIME-OVERLAY", "5gpn", "sideways", nil, nil); err == nil {
		t.Fatal("an unknown stage was accepted")
	}
	// Trailing params must be rejected rather than silently ignored: the
	// framework's ParseParams drops anything it does not recognise, so a typo
	// would otherwise become a no-op.
	if _, err := R.ParseRule("RUNTIME-OVERLAY", "5gpn", "client", []string{"no-resolve"}, nil); err == nil {
		t.Fatal("trailing params were accepted")
	}
	if _, err := R.ParseRule("RUNTIME-OVERLAY", "bad owner!", "client", nil, nil); err == nil {
		t.Fatal("an illegal owner was accepted")
	}
}

func TestListenerRoutingOverrideRejected(t *testing.T) {
	for _, key := range []string{"proxy", "rule"} {
		t.Run(key, func(t *testing.T) {
			raw := &RawConfig{Listeners: []map[string]any{
				{"name": "gateway", "type": "tunnel", key: "SomeGroup"},
			}}
			if err := validateOverlayListeners(raw); !errors.Is(err, overlay.ErrModeConflict) {
				t.Fatalf("want ErrModeConflict, got %v", err)
			}
		})
	}
	clean := &RawConfig{Listeners: []map[string]any{{"name": "gateway", "type": "tunnel"}}}
	if err := validateOverlayListeners(clean); err != nil {
		t.Fatalf("clean listener rejected: %v", err)
	}
}

// A single extra comma field on a tunnels: entry is a total bypass, so it gets
// its own check rather than riding on the listener one.
func TestTunnelProxyTargetRejected(t *testing.T) {
	cfg := &Config{Tunnels: mustTunnels(t, "tcp,127.0.0.1:9000,example.test:80,SomeGroup")}
	if err := validateOverlayTunnels(cfg); !errors.Is(err, overlay.ErrModeConflict) {
		t.Fatalf("want ErrModeConflict, got %v", err)
	}
	clean := &Config{Tunnels: mustTunnels(t, "tcp,127.0.0.1:9000,example.test:80")}
	if err := validateOverlayTunnels(clean); err != nil {
		t.Fatalf("clean tunnel rejected: %v", err)
	}
}

func TestProcessorIsolation(t *testing.T) {
	processors := map[string]struct{}{"MODULE-INTERCEPT": {}}

	t.Run("group naming the processor", func(t *testing.T) {
		raw := &RawConfig{ProxyGroup: []map[string]any{
			{"name": "Proxies", "type": "select", "proxies": []any{"DIRECT", "MODULE-INTERCEPT"}},
		}}
		if err := validateOverlayProcessorIsolation(raw, processors); !errors.Is(err, overlay.ErrModeConflict) {
			t.Fatalf("want ErrModeConflict, got %v", err)
		}
	})

	t.Run("dialer-proxy chaining through the processor", func(t *testing.T) {
		raw := &RawConfig{Proxy: []map[string]any{
			{"name": "up", "type": "socks5", "dialer-proxy": "MODULE-INTERCEPT"},
		}}
		if err := validateOverlayProcessorIsolation(raw, processors); !errors.Is(err, overlay.ErrModeConflict) {
			t.Fatalf("want ErrModeConflict, got %v", err)
		}
	})

	t.Run("processor setting its own dialer-proxy", func(t *testing.T) {
		raw := &RawConfig{Proxy: []map[string]any{
			{"name": "MODULE-INTERCEPT", "type": "socks5", "dialer-proxy": "Proxies"},
		}}
		if err := validateOverlayProcessorIsolation(raw, processors); !errors.Is(err, overlay.ErrModeConflict) {
			t.Fatalf("want ErrModeConflict, got %v", err)
		}
	})

	t.Run("clean", func(t *testing.T) {
		raw := &RawConfig{
			ProxyGroup: []map[string]any{{"name": "Proxies", "type": "select", "proxies": []any{"DIRECT"}}},
			Proxy:      []map[string]any{{"name": "MODULE-INTERCEPT", "type": "socks5"}},
		}
		if err := validateOverlayProcessorIsolation(raw, processors); err != nil {
			t.Fatalf("clean config rejected: %v", err)
		}
	})
}

func TestOverlayProcessorNamesReadsBothKeySpellings(t *testing.T) {
	raw := &RawConfig{Proxy: []map[string]any{
		{"name": "a", OverlayProcessorKey: true},
		{"name": "b", "runtime_overlay_processor": true},
		{"name": "c"},
		{"name": "d", OverlayProcessorKey: false},
	}}
	got := overlayProcessorNames(raw)
	if len(got) != 2 {
		t.Fatalf("got %d processors, want 2: %v", len(got), got)
	}
	for _, want := range []string{"a", "b"} {
		if _, ok := got[want]; !ok {
			t.Fatalf("%q was not detected as a processor", want)
		}
	}
}

// The closure digest is the core revision's only input, so it must move when
// anything inside the closure moves and stay put otherwise.
func TestClosureDigestSensitivity(t *testing.T) {
	base := func() *RawConfig {
		return &RawConfig{
			Mode:      1, // rule
			Rule:      []string{"MATCH,DIRECT"},
			Hosts:     map[string]any{"a.test": "127.0.0.1"},
			Listeners: []map[string]any{{"name": "gateway", "type": "tunnel"}},
		}
	}
	sum := func(c *RawConfig) string {
		d, err := OverlayClosureDigest(c)
		if err != nil {
			t.Fatalf("digest: %v", err)
		}
		return d.Sum()
	}

	if sum(base()) != sum(base()) {
		t.Fatal("the digest is not deterministic for identical input")
	}

	mutations := map[string]func(*RawConfig){
		"rules":     func(c *RawConfig) { c.Rule = []string{"MATCH,REJECT"} },
		"hosts":     func(c *RawConfig) { c.Hosts["b.test"] = "127.0.0.2" },
		"listeners": func(c *RawConfig) { c.Listeners[0]["port"] = 1080 },
		"tunnels":   func(c *RawConfig) { c.Tunnels = mustTunnels(t, "tcp,127.0.0.1:9000,x.test:80") },
		"sniffer":   func(c *RawConfig) { c.Sniffer.Enable = true },
	}
	original := sum(base())
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			c := base()
			mutate(c)
			if sum(c) == original {
				t.Fatalf("changing %s did not change the closure digest", name)
			}
		})
	}
}

// proxyGroupsDagSort reorders the group slice in place during parsing, so the
// digest must not depend on group order.
func TestClosureDigestIgnoresGroupOrder(t *testing.T) {
	a := &RawConfig{ProxyGroup: []map[string]any{{"name": "A"}, {"name": "B"}}}
	b := &RawConfig{ProxyGroup: []map[string]any{{"name": "B"}, {"name": "A"}}}
	da, err := OverlayClosureDigest(a)
	if err != nil {
		t.Fatalf("digest a: %v", err)
	}
	db, err := OverlayClosureDigest(b)
	if err != nil {
		t.Fatalf("digest b: %v", err)
	}
	if da.Sum() != db.Sum() {
		t.Fatal("group order changed the closure digest")
	}
}

// mustTunnels parses the compact tunnels: string form through the same
// UnmarshalYAML the config uses, so the test exercises the real parser rather
// than a hand-built struct.
func mustTunnels(t *testing.T, lines ...string) []LC.Tunnel {
	t.Helper()
	var out []LC.Tunnel
	raw, err := yaml.Marshal(lines)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if err := yaml.Unmarshal(raw, &out); err != nil {
		t.Fatalf("unmarshal tunnels %v: %v", lines, err)
	}
	return out
}
