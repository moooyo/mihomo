package engine

import (
	"context"
	"encoding/json"
	"net"
	"net/netip"
	"reflect"
	"strings"
	"testing"
	"time"
)

const validManifest = `
apiVersion: 5gpn.io/v1
kind: Extension
metadata:
  id: example.plugin
  name: Example
  version: 1.2.0
  description: A test extension
permissions:
  persistentStorage: true
  network: true
requirements:
  egressGroup:
    required: true
traffic:
  captureHosts:
    - Shared.Example.COM.
    - "*.api.example.com"
  upstreamMappings:
    - host: shared.example.com
      target: Origin.Example.NET.
  routingRules:
    - action: REJECT
      domainSuffix: ads.example.org
settings:
  - key: region
    type: select
    label: Region
    required: true
    options: [cn, hk]
    default: cn
actions:
  - id: rewrite-headers
    phase: request
    match:
      hosts: [shared.example.com]
      pathRegex: "^/v1/"
    enabledWhen:
      key: region
      equals: cn
    script:
      inline: "function transform(context) { return {}; }"
      bodyMode: text
`

func TestGuardedDialFallsBackBeforeABlackholedAddressFamily(t *testing.T) {
	server, peer := net.Pipe()
	t.Cleanup(func() {
		_ = server.Close()
		_ = peer.Close()
	})
	calls := make(chan string, 2)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	started := time.Now()
	conn, err := dialGuardedCandidates(
		ctx,
		"tcp",
		"443",
		[]netip.Addr{netip.MustParseAddr("2001:4860:4860::8888"), netip.MustParseAddr("8.8.8.8")},
		5*time.Millisecond,
		func(ctx context.Context, _, address string) (net.Conn, error) {
			calls <- address
			if strings.HasPrefix(address, "[") {
				<-ctx.Done()
				return nil, ctx.Err()
			}
			return server, nil
		},
	)
	if err != nil {
		t.Fatalf("dialGuardedCandidates() error = %v", err)
	}
	defer conn.Close()
	if elapsed := time.Since(started); elapsed > 200*time.Millisecond {
		t.Fatalf("address-family fallback took %s", elapsed)
	}
	for range 2 {
		select {
		case <-calls:
		case <-time.After(time.Second):
			t.Fatal("both address families were not attempted")
		}
	}
}

func parseFixture(t *testing.T, body string) Module {
	t.Helper()
	imp := &Importer{}
	module, err := imp.Import(context.Background(), ImportRequest{Content: body})
	if err != nil {
		t.Fatalf("Import: %v", err)
	}
	return module
}

func TestManifestParsesAndNormalizes(t *testing.T) {
	m := parseFixture(t, validManifest)

	if m.ID != "example.plugin" || m.Version != "1.2.0" || m.Name != "Example" {
		t.Errorf("identity %q %q %q", m.ID, m.Version, m.Name)
	}
	if m.Enabled {
		t.Error("an import landed enabled")
	}
	if m.CaptureDNS != "trust" {
		t.Errorf("capture DNS %q, want the trust default", m.CaptureDNS)
	}
	if !m.Network || !m.PersistentStorage || !m.EgressGroupRequired {
		t.Errorf("permissions lost: network=%v storage=%v egress=%v", m.Network, m.PersistentStorage, m.EgressGroupRequired)
	}

	// Hosts are lowercased, stripped of the trailing dot, deduplicated and
	// sorted -- the document validator requires sorted, and an unnormalized
	// host silently matches nothing.
	want := []string{"*.api.example.com", "shared.example.com"}
	if len(m.CaptureHosts) != 2 || m.CaptureHosts[0] != want[0] || m.CaptureHosts[1] != want[1] {
		t.Errorf("capture hosts %v, want %v", m.CaptureHosts, want)
	}
	// The mapping target is normalized in the same order, because the stored
	// value is what gets dialed and a trailing dot makes an address literal
	// resolve nowhere.
	if len(m.HostMappings) != 1 || m.HostMappings[0].Target != "origin.example.net" {
		t.Errorf("mapping %+v", m.HostMappings)
	}

	if len(m.Scripts) != 1 {
		t.Fatalf("%d actions, want 1", len(m.Scripts))
	}
	action := m.Scripts[0]
	if action.ScriptDigest == "" || action.ScriptBody == "" {
		t.Error("the inline script was not snapshotted")
	}
	// An unspecified scheme list defaults to https, and an unspecified timeout
	// and body budget take the documented defaults rather than zero -- a zero
	// timeout is an action that can never complete.
	if len(action.Match.Schemes) != 1 || action.Match.Schemes[0] != "https" {
		t.Errorf("schemes %v, want the https default", action.Match.Schemes)
	}
	if action.TimeoutMS == 0 || action.MaxBodyBytes == 0 {
		t.Errorf("timeout %d body %d, want defaults", action.TimeoutMS, action.MaxBodyBytes)
	}
	if action.EnabledWhen == nil || action.EnabledWhen.Key != "region" {
		t.Errorf("the gate was dropped: %+v", action.EnabledWhen)
	}

	if m.Source.Digest != digestText(validManifest) {
		t.Error("the source digest does not cover the manifest bytes")
	}
}

func TestManifestNormalizesMethodsAsCanonicalUppercase(t *testing.T) {
	body := strings.Replace(validManifest,
		`      pathRegex: "^/v1/"`,
		"      methods: [post, GET, ' POST ']\n      pathRegex: \"^/v1/\"", 1)
	module := parseFixture(t, body)

	want := []string{"GET", "POST"}
	if got := module.Scripts[0].Match.Methods; !reflect.DeepEqual(got, want) {
		t.Fatalf("methods = %v, want %v", got, want)
	}
	if err := validateModules([]Module{module}); err != nil {
		t.Fatalf("the normalized module did not validate: %v", err)
	}
	module.Scripts[0].Match.Methods = []string{"get"}
	if err := validateModules([]Module{module}); err == nil || !strings.Contains(err.Error(), "method") {
		t.Fatalf("non-canonical methods returned %v, want a method validation error", err)
	}
}

// Every one of these is a way for a manifest to mean something other than what
// it appears to say, which in a permission block is the difference between what
// the author wrote and what the operator agreed to.
func TestManifestRejectsAmbiguousYAML(t *testing.T) {
	cases := map[string]string{
		"unknown field":   strings.Replace(validManifest, "  network: true", "  network: true\n  filesystem: true", 1),
		"anchor":          strings.Replace(validManifest, "metadata:", "metadata: &meta", 1),
		"merge key":       validManifest + "\n<<: {kind: Extension}\n",
		"second document": validManifest + "\n---\napiVersion: 5gpn.io/v1\n",
		"duplicate key":   validManifest + "\nkind: Extension\n",
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			imp := &Importer{}
			if _, err := imp.Import(context.Background(), ImportRequest{Content: body}); err == nil {
				t.Error("accepted")
			}
		})
	}
}

func TestManifestRejectsWrongIdentity(t *testing.T) {
	cases := map[string]string{
		"apiVersion": strings.Replace(validManifest, "5gpn.io/v1", "5gpn.io/v2", 1),
		"kind":       strings.Replace(validManifest, "kind: Extension", "kind: Module", 1),
		"id":         strings.Replace(validManifest, "id: example.plugin", "id: Example_Plugin", 1),
		"version":    strings.Replace(validManifest, "version: 1.2.0", "version: v1.2", 1),
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			imp := &Importer{}
			if _, err := imp.Import(context.Background(), ImportRequest{Content: body}); err == nil {
				t.Error("accepted")
			}
		})
	}
}

// A gate whose comparison can never hold compiles to an action that never runs,
// which is the failure nobody sees.
func TestActionGateRestrictions(t *testing.T) {
	settings := []ModuleSetting{
		{Key: "flag", Type: "boolean", Required: true},
		{Key: "region", Type: "select", Required: true, Options: []string{"cn", "hk"}},
		{Key: "optional", Type: "select", Required: false, Options: []string{"a"}},
		{Key: "count", Type: "number", Required: true},
	}
	bad := []manifestGate{
		{Key: "flag", Equals: "yes"},   // not a boolean literal
		{Key: "region", Equals: "us"},  // not an option the operator can pick
		{Key: "optional", Equals: "a"}, // optional: the gate has no decidable state
		{Key: "count", Equals: "1"},    // rendered-text comparison an author cannot predict
		{Key: "missing", Equals: "x"},  // not declared
		{Key: "flag", Equals: ""},      // nothing to compare against
	}
	for _, gate := range bad {
		if _, err := parseGate(&gate, settings); err == nil {
			t.Errorf("parseGate(%+v) accepted it", gate)
		}
	}
	for _, gate := range []manifestGate{{Key: "flag", Equals: "true"}, {Key: "region", Equals: "hk"}} {
		if _, err := parseGate(&gate, settings); err != nil {
			t.Errorf("parseGate(%+v): %v", gate, err)
		}
	}
}

func TestActionMustDeclareExactlyOneKind(t *testing.T) {
	none := strings.Replace(validManifest, `      inline: "function transform(context) { return {}; }"`, "      bodyMode: text", 1)
	none = strings.Replace(none, "      bodyMode: text\n      bodyMode: text", "      bodyMode: text", 1)
	imp := &Importer{}
	if _, err := imp.Import(context.Background(), ImportRequest{Content: none}); err == nil {
		t.Error("an action declaring no kind was accepted")
	}

	both := strings.Replace(validManifest,
		`      inline: "function transform(context) { return {}; }"`,
		`      inline: "function transform(context) { return {}; }"`+"\n      reject: true", 1)
	if _, err := imp.Import(context.Background(), ImportRequest{Content: both}); err == nil {
		t.Error("an action declaring two kinds was accepted")
	}
}

// A pasted manifest has no base to resolve against, and guessing one would let
// the same relative path mean different things depending on how the manifest
// reached the box.
func TestRelativeScriptSourceNeedsAURLImport(t *testing.T) {
	body := strings.Replace(validManifest,
		`      inline: "function transform(context) { return {}; }"`,
		"      source: ./transform.js", 1)
	imp := &Importer{}
	if _, err := imp.Import(context.Background(), ImportRequest{Content: body}); err == nil {
		t.Error("a relative source was accepted on a pasted manifest")
	}

	resolved, err := resolveResourceURL("https://example.com/plugins/a/manifest.yaml", "./transform.js")
	if err != nil {
		t.Fatal(err)
	}
	if resolved != "https://example.com/plugins/a/transform.js" {
		t.Errorf("resolved to %q", resolved)
	}
}

func TestResourceURLsMustBeSafeHTTPS(t *testing.T) {
	bad := []string{
		"http://example.com/m.yaml",
		"ftp://example.com/m.yaml",
		"https://user:pass@example.com/m.yaml",
		"https://example.com/m.yaml#frag",
		"https:///m.yaml",
	}
	for _, raw := range bad {
		if err := checkResourceURL(raw); err == nil {
			t.Errorf("checkResourceURL(%q) accepted it", raw)
		}
	}
	if err := checkResourceURL("https://example.com/m.yaml?ref=main"); err != nil {
		t.Errorf("a plain https URL was refused: %v", err)
	}
}

func TestImportRequiresExactlyOneSource(t *testing.T) {
	imp := &Importer{}
	for _, request := range []ImportRequest{
		{},
		{URL: "https://example.com/m.yaml", Content: validManifest},
	} {
		if _, err := imp.Import(context.Background(), request); err == nil {
			t.Errorf("Import(%+v) accepted it", request)
		}
	}
}

// The dial guard is what keeps a manifest URL from reaching the loopback API,
// the metadata service, or anything else on the gateway's own networks.
func TestDialGuardRefusesNonPublicAddresses(t *testing.T) {
	for _, addr := range []string{
		"127.0.0.1", "::1", "10.1.2.3", "172.16.0.1", "192.168.1.1",
		"169.254.169.254", "100.64.0.1", "0.0.0.0", "224.0.0.1", "240.0.0.1",
		"192.0.2.1", "198.18.0.1", "198.51.100.1", "203.0.113.1",
		"fe80::1", "fd00::1", "100::1", "2001:db8::1", "3fff::1", "::ffff:8.8.8.8",
	} {
		if publicUnicast(netip.MustParseAddr(addr)) {
			t.Errorf("publicUnicast(%s) accepted it", addr)
		}
	}
	for _, addr := range []string{"8.8.8.8", "1.1.1.1", "2001:4860:4860::8888"} {
		if !publicUnicast(netip.MustParseAddr(addr)) {
			t.Errorf("publicUnicast(%s) refused a public address", addr)
		}
	}
}

func TestHostTargetsUseTheSharedPublicAddressGuard(t *testing.T) {
	for _, target := range []string{
		"192.0.2.1",
		"198.18.0.1",
		"203.0.113.1",
		"::ffff:8.8.8.8",
		"server:192.0.2.1",
	} {
		if validHostTarget(target) {
			t.Errorf("validHostTarget(%q) accepted a special-purpose address", target)
		}
	}
	for _, target := range []string{"8.8.8.8", "server:8.8.8.8"} {
		if !validHostTarget(target) {
			t.Errorf("validHostTarget(%q) refused a public IPv4 target", target)
		}
	}
}

// The digest is the operator's proof that what lands is what they reviewed, so
// it must cover what the publisher offered and nothing the operator chose --
// otherwise editing a setting would invalidate every review.
func TestSnapshotDigestCoversThePublisherAndNotTheOperator(t *testing.T) {
	base := parseFixture(t, validManifest)
	want := SnapshotDigest(base)

	operatorEdits := base
	operatorEdits.Enabled = true
	operatorEdits.EgressGroup = "Proxies"
	operatorEdits.CaptureDNS = "china"
	operatorEdits.Settings = append([]ModuleSetting(nil), base.Settings...)
	operatorEdits.Settings[0].Value = json.RawMessage(`"hk"`)
	if got := SnapshotDigest(operatorEdits); got != want {
		t.Error("the digest changed when the operator edited their own state")
	}

	publisherEdits := base
	publisherEdits.Network = false
	if SnapshotDigest(publisherEdits) == want {
		t.Error("the digest survived a change to the network permission")
	}

	scriptEdits := base
	scriptEdits.Scripts = append([]ScriptRule(nil), base.Scripts...)
	scriptEdits.Scripts[0].ScriptDigest = "different"
	if SnapshotDigest(scriptEdits) == want {
		t.Error("the digest survived a change to the code that runs")
	}

	hostEdits := base
	hostEdits.CaptureHosts = []string{"*.api.example.com", "shared.example.com", "extra.example.com"}
	if SnapshotDigest(hostEdits) == want {
		t.Error("the digest survived a new capture host")
	}
}

func TestSnapshotDigestSurvivesPersistenceOfEmptyOptionalLists(t *testing.T) {
	module := parseFixture(t, `
apiVersion: 5gpn.io/v1
kind: Extension
metadata:
  id: stable.digest
  name: Stable digest
  version: 1.0.0
  description: Digest persistence fixture
permissions:
  persistentStorage: false
  network: false
traffic:
  captureHosts: [stable.example.com]
actions:
  - id: pass
    phase: request
    match:
      hosts: [stable.example.com]
    script:
      inline: "function transform() { return {}; }"
      bodyMode: none
      timeoutMs: 1000
      maxBodyBytes: 1024
`)
	want := SnapshotDigest(module)
	raw, err := json.Marshal(module)
	if err != nil {
		t.Fatal(err)
	}
	var restored Module
	if err := json.Unmarshal(raw, &restored); err != nil {
		t.Fatal(err)
	}
	if got := SnapshotDigest(restored); got != want {
		t.Fatalf("digest changed across persistence: %s -> %s", want, got)
	}
}

// An import produces a candidate; deciding what to do with it is the caller's,
// and a digest that was not reviewed is not a decision.
func TestInstallAndUpdateRequireADigest(t *testing.T) {
	e := newTestEngine(t, twoExtensionDocument)
	if _, _, err := e.Install(context.Background(), e.Revision(), InstallRequest{
		ImportRequest: ImportRequest{Content: validManifest},
	}); err == nil {
		t.Error("an install without a reviewed digest was accepted")
	}
	if _, _, err := e.ApplyUpdate(context.Background(), e.Revision(), "first", ""); err == nil {
		t.Error("an update without a reviewed digest was accepted")
	}
}

// Enabled state is operator authorization, not a lock on the immutable runtime
// pointer. A reviewed update may therefore replace an enabled extension.
func TestEnabledExtensionIsUpdatable(t *testing.T) {
	cfg, err := decodeConfig([]byte(twoExtensionDocument))
	if err != nil {
		t.Fatal(err)
	}
	module, err := updatableModule(cfg, "first")
	if err != nil {
		t.Fatalf("enabled extension is not updatable: %v", err)
	}
	if !module.Enabled {
		t.Fatal("fixture extension unexpectedly disabled")
	}
}

// A pasted manifest has no authority to re-read, and inventing one would
// silently change where an operator's code comes from.
func TestUpdateCheckNeedsASourceURL(t *testing.T) {
	e := newTestEngine(t, twoExtensionDocument)
	_, err := e.CheckUpdate(context.Background(), "second")
	if err == nil || !strings.Contains(err.Error(), "pasted manifest") {
		t.Errorf("checking a pasted extension returned %v", err)
	}
}
