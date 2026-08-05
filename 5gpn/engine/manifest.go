package engine

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"gopkg.in/yaml.v3"
)

// 5gpn accepts one manifest format and nothing else.
//
// There is no third-party client-format parser, no compatibility mode, no
// deep-link alias, and no partial-execution acknowledgement. A format this
// program cannot fully represent would be accepted with the parts it did not
// understand silently dropped -- and what gets dropped in a plugin manifest is
// a permission, a capture host, or a match constraint, so "mostly imported" is
// the one outcome worth refusing outright.
const (
	manifestAPIVersion = "5gpn.io/v1"
	manifestKind       = "Extension"
	manifestUserAgent  = "5gpn-extension-fetch/1"
)

const (
	maxManifestBytes    = 2 << 20
	maxScriptBytes      = 2 << 20
	maxScriptTotalBytes = 8 << 20
	maxResourceURLBytes = 4096
	maxManifestSettings = 64
	maxManifestActions  = 256
)

var manifestVersionPattern = regexp.MustCompile(`^[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$`)

// Resolver is how the importer turns a hostname into addresses it may dial.
//
// Injected rather than using the system resolver, because on this box the
// system resolver is this process: a fetch that went through the ordinary path
// would be steered by the very policy it is being used to configure.
type Resolver func(ctx context.Context, host string) ([]string, error)

// Importer fetches and parses manifests.
type Importer struct {
	client *http.Client
	now    func() time.Time
}

// NewImporter builds an importer with one reusable, guarded client.
//
// One client, built once, because the previous implementation constructed a
// transport per resource and let it go out of scope. A transport's read and
// write loops keep it alive after the last reference is gone, and a zero-value
// IdleConnTimeout means its idle connections never expire, so importing one
// extension with five script resources stranded six open TLS connections --
// permanently, on the process that also serves DoT.
func NewImporter(resolve Resolver) *Importer {
	return &Importer{
		client: &http.Client{
			Transport: &http.Transport{
				DialContext:            guardedDialer(resolve),
				ForceAttemptHTTP2:      true,
				MaxResponseHeaderBytes: 64 << 10,
				ResponseHeaderTimeout:  15 * time.Second,
				TLSHandshakeTimeout:    10 * time.Second,
				// Reuse is the point, but not forever: a source an operator adds
				// once should not cost a permanently open socket.
				IdleConnTimeout: 90 * time.Second,
			},
			Timeout:       30 * time.Second,
			CheckRedirect: redirectPolicy,
		},
		now: time.Now,
	}
}

// ImportRequest is one import: exactly one of URL or Content.
type ImportRequest struct {
	URL     string `json:"url,omitempty"`
	Content string `json:"content,omitempty"`
}

// Import fetches, parses and snapshots one extension.
//
// The result is always disabled and carries the immutable manifest body and its
// digest. Nothing here consults the installed document: an import produces a
// candidate, and deciding what to do with it is the caller's.
func (imp *Importer) Import(ctx context.Context, request ImportRequest) (Module, error) {
	sourceURL := strings.TrimSpace(request.URL)
	body := []byte(request.Content)

	switch {
	case sourceURL == "" && len(body) == 0:
		return Module{}, fmt.Errorf("%w: one of url or content is required", ErrInvalidRequest)
	case sourceURL != "" && len(body) != 0:
		return Module{}, fmt.Errorf("%w: url and content are mutually exclusive", ErrInvalidRequest)
	case len(sourceURL) > maxResourceURLBytes:
		return Module{}, fmt.Errorf("%w: url exceeds %d bytes", ErrInvalidRequest, maxResourceURLBytes)
	}

	if sourceURL != "" {
		if err := checkResourceURL(sourceURL); err != nil {
			return Module{}, err
		}
		var err error
		// The final URL after redirects becomes the base for relative script
		// resources. Resolving them against the URL the operator typed would
		// point at a host the redirect moved away from.
		body, sourceURL, err = imp.fetch(ctx, sourceURL, maxManifestBytes)
		if err != nil {
			return Module{}, fmt.Errorf("fetch extension manifest: %w", err)
		}
	}

	if len(body) == 0 || len(body) > maxManifestBytes {
		return Module{}, fmt.Errorf("%w: the manifest must contain 1 to %d bytes", ErrInvalidRequest, maxManifestBytes)
	}
	if bytes.IndexByte(body, 0) >= 0 {
		return Module{}, fmt.Errorf("%w: the manifest contains a NUL byte", ErrInvalidRequest)
	}
	if !utf8.Valid(body) {
		return Module{}, fmt.Errorf("%w: the manifest must be valid UTF-8", ErrInvalidRequest)
	}

	module, err := imp.parse(ctx, sourceURL, body)
	if err != nil {
		return Module{}, err
	}
	module.Enabled = false
	module.ImportedAt = imp.clock().UTC().Format(time.RFC3339)
	module.Source = ModuleSource{URL: sourceURL, Digest: digestText(string(body)), Body: string(body)}
	return module, nil
}

func (imp *Importer) clock() time.Time {
	if imp.now != nil {
		return imp.now()
	}
	return time.Now()
}

// --- the manifest shape --------------------------------------------------

type manifest struct {
	APIVersion   string              `yaml:"apiVersion"`
	Kind         string              `yaml:"kind"`
	Metadata     manifestMetadata    `yaml:"metadata"`
	Permissions  manifestPermissions `yaml:"permissions"`
	Requirements manifestRequires    `yaml:"requirements"`
	Traffic      manifestTraffic     `yaml:"traffic"`
	Settings     []manifestSetting   `yaml:"settings"`
	Actions      []manifestAction    `yaml:"actions"`
}

type manifestMetadata struct {
	ID          string `yaml:"id"`
	Name        string `yaml:"name"`
	Version     string `yaml:"version"`
	Description string `yaml:"description"`
}

type manifestPermissions struct {
	PersistentStorage bool `yaml:"persistentStorage"`
	// Network is one boolean: the extension may reach the network or it may
	// not. It replaced an origins/any pair that described the same capability
	// at two breadths, which forced an extension needing both -- a script
	// reaching operator-chosen hosts, an action rewriting to a fixed one -- to
	// pick a breadth that broke the other half. Every review therefore says
	// "any host it can reach" rather than naming one.
	Network bool `yaml:"network"`
}

type manifestRequires struct {
	EgressGroup struct {
		Required bool `yaml:"required"`
	} `yaml:"egressGroup"`
}

type manifestTraffic struct {
	CaptureHosts     []string          `yaml:"captureHosts"`
	UpstreamMappings []manifestMapping `yaml:"upstreamMappings"`
	RoutingRules     []manifestRoute   `yaml:"routingRules"`
}

type manifestMapping struct {
	Host   string `yaml:"host"`
	Target string `yaml:"target"`
}

type manifestRoute struct {
	Action            string    `yaml:"action"`
	Domain            *string   `yaml:"domain"`
	DomainSuffix      *string   `yaml:"domainSuffix"`
	DomainKeywords    *[]string `yaml:"domainKeywords"`
	AllDomainKeywords *[]string `yaml:"allDomainKeywords"`
	IPCIDR            *string   `yaml:"ipCIDR"`
	Network           *string   `yaml:"network"`
	DestinationPort   *int      `yaml:"destinationPort"`
}

type manifestSetting struct {
	Key         string    `yaml:"key"`
	Type        string    `yaml:"type"`
	Label       string    `yaml:"label"`
	Description string    `yaml:"description"`
	Required    bool      `yaml:"required"`
	Options     []string  `yaml:"options"`
	Min         *float64  `yaml:"min"`
	Max         *float64  `yaml:"max"`
	Default     yaml.Node `yaml:"default"`
}

type manifestAction struct {
	ID     string             `yaml:"id"`
	Phase  string             `yaml:"phase"`
	Match  manifestMatch      `yaml:"match"`
	Gate   *manifestGate      `yaml:"enabledWhen"`
	Script manifestScriptSpec `yaml:"script"`
}

type manifestGate struct {
	Key    string `yaml:"key"`
	Equals string `yaml:"equals"`
}

type manifestMatch struct {
	Hosts       []string `yaml:"hosts"`
	Schemes     []string `yaml:"schemes"`
	Methods     []string `yaml:"methods"`
	PathRegex   string   `yaml:"pathRegex"`
	StatusCodes []int    `yaml:"statusCodes"`
}

type manifestScriptSpec struct {
	Source       string        `yaml:"source"`
	Inline       string        `yaml:"inline"`
	BodyMode     string        `yaml:"bodyMode"`
	Entry        string        `yaml:"entry"`
	JQ           string        `yaml:"jq"`
	Reject       bool          `yaml:"reject"`
	Mock         *MockResponse `yaml:"mock"`
	Headers      *HeaderEdits  `yaml:"headers"`
	Rewrite      *URLRewrite   `yaml:"rewrite"`
	ReplaceBody  *BodyReplace  `yaml:"replaceBody"`
	TimeoutMS    int           `yaml:"timeoutMs"`
	MaxBodyBytes int64         `yaml:"maxBodyBytes"`
}

// --- parsing -------------------------------------------------------------

func (imp *Importer) parse(ctx context.Context, sourceURL string, body []byte) (Module, error) {
	doc, err := decodeManifest(body)
	if err != nil {
		return Module{}, err
	}
	if doc.APIVersion != manifestAPIVersion {
		return Module{}, fmt.Errorf("%w: apiVersion must be %q", ErrInvalidRequest, manifestAPIVersion)
	}
	if doc.Kind != manifestKind {
		return Module{}, fmt.Errorf("%w: kind must be %q", ErrInvalidRequest, manifestKind)
	}
	if !nativeExtensionIDPattern.MatchString(doc.Metadata.ID) {
		return Module{}, fmt.Errorf("%w: metadata.id must be a lowercase dotted identifier", ErrInvalidRequest)
	}
	if !manifestVersionPattern.MatchString(doc.Metadata.Version) {
		return Module{}, fmt.Errorf("%w: metadata.version must be a semantic version", ErrInvalidRequest)
	}

	// Every count is checked before any network request.
	//
	// The action loop below fetches one resource per action carrying a
	// script.source, and the structural limits used to be applied only after
	// all of them had been fetched. The single in-loop bound was the cumulative
	// script size, which a server answering with one-byte bodies never reaches
	// -- so a manifest declaring sixteen thousand remote actions drove sixteen
	// thousand sequential outbound requests, to hosts it chose itself, each
	// with its own handshake and a thirty-second timeout, before being rejected
	// for a bound that was knowable from the first line. A server that stalls
	// near that timeout stretches one import across days.
	if n := len(doc.Actions) + len(doc.Traffic.UpstreamMappings); n > maxManifestActions {
		return Module{}, fmt.Errorf("%w: %d actions and mappings exceed the limit of %d", ErrInvalidRequest, n, maxManifestActions)
	}
	if n := len(doc.Traffic.CaptureHosts); n > maxModuleCaptureHosts {
		return Module{}, fmt.Errorf("%w: %d capture hosts exceed the limit of %d", ErrInvalidRequest, n, maxModuleCaptureHosts)
	}
	if n := len(doc.Traffic.RoutingRules); n > maxModuleRoutingRules {
		return Module{}, fmt.Errorf("%w: %d routing rules exceed the limit of %d", ErrInvalidRequest, n, maxModuleRoutingRules)
	}
	if n := len(doc.Settings); n > maxManifestSettings {
		return Module{}, fmt.Errorf("%w: %d settings exceed the limit of %d", ErrInvalidRequest, n, maxManifestSettings)
	}

	captureHosts, err := normalizeHosts(doc.Traffic.CaptureHosts)
	if err != nil {
		return Module{}, fmt.Errorf("%w: traffic.captureHosts: %v", ErrInvalidRequest, err)
	}

	mappings := make([]HostMapping, 0, len(doc.Traffic.UpstreamMappings))
	for i, raw := range doc.Traffic.UpstreamMappings {
		host, err := normalizeHostPattern(raw.Host)
		if err != nil {
			return Module{}, fmt.Errorf("%w: traffic.upstreamMappings[%d].host: %v", ErrInvalidRequest, i, err)
		}
		// Normalized in the same order as the pattern: lower, trim, then strip
		// the trailing dot. Stripping first leaves the dot in place for a target
		// with trailing whitespace, and the stored value is what gets dialed --
		// "8.8.8.8." is not an address literal, so such a mapping resolves
		// nowhere while every validator it passes through re-normalizes
		// internally and reports it fine.
		mappings = append(mappings, HostMapping{
			Pattern: host,
			Target:  strings.TrimSuffix(strings.ToLower(strings.TrimSpace(raw.Target)), "."),
		})
	}

	routes := make(RoutingRules, 0, len(doc.Traffic.RoutingRules))
	for i, raw := range doc.Traffic.RoutingRules {
		rule, err := normalizeRoute(raw)
		if err != nil {
			return Module{}, fmt.Errorf("%w: traffic.routingRules[%d]: %v", ErrInvalidRequest, i, err)
		}
		routes = append(routes, rule)
	}

	settings := make([]ModuleSetting, 0, len(doc.Settings))
	for i, raw := range doc.Settings {
		value, err := yamlToJSON(raw.Default)
		if err != nil {
			return Module{}, fmt.Errorf("%w: settings[%d].default: %v", ErrInvalidRequest, i, err)
		}
		settings = append(settings, ModuleSetting{
			Key:         raw.Key,
			Type:        strings.ToLower(strings.TrimSpace(raw.Type)),
			Label:       strings.TrimSpace(raw.Label),
			Description: strings.TrimSpace(raw.Description),
			Required:    raw.Required,
			Options:     append([]string(nil), raw.Options...),
			Min:         raw.Min,
			Max:         raw.Max,
			Default:     append(json.RawMessage(nil), value...),
			// A fresh import starts at the declared default, so an extension
			// whose settings are all optional is immediately enableable.
			Value: append(json.RawMessage(nil), value...),
		})
	}

	scripts, err := imp.parseActions(ctx, sourceURL, doc.Actions, settings)
	if err != nil {
		return Module{}, err
	}

	return Module{
		ID:                  doc.Metadata.ID,
		Version:             doc.Metadata.Version,
		Name:                strings.TrimSpace(doc.Metadata.Name),
		Description:         strings.TrimSpace(doc.Metadata.Description),
		CaptureHosts:        captureHosts,
		CaptureDNS:          "trust",
		HostMappings:        mappings,
		RoutingRules:        routes,
		Settings:            settings,
		Scripts:             scripts,
		PersistentStorage:   doc.Permissions.PersistentStorage,
		Network:             doc.Permissions.Network,
		EgressGroupRequired: doc.Requirements.EgressGroup.Required,
	}, nil
}

func (imp *Importer) parseActions(ctx context.Context, sourceURL string, actions []manifestAction, settings []ModuleSetting) ([]ScriptRule, error) {
	out := make([]ScriptRule, 0, len(actions))
	total := 0

	for i, raw := range actions {
		hosts, err := normalizeHosts(raw.Match.Hosts)
		if err != nil {
			return nil, fmt.Errorf("%w: actions[%d].match.hosts: %v", ErrInvalidRequest, i, err)
		}
		schemes := normalizeLower(raw.Match.Schemes)
		if len(schemes) == 0 {
			schemes = []string{"https"}
		}
		path := strings.TrimSpace(raw.Match.PathRegex)
		if path == "" {
			path = "^/"
		}
		bodyMode := strings.ToLower(strings.TrimSpace(raw.Script.BodyMode))
		if bodyMode == "" {
			bodyMode = "none"
		}
		gate, err := parseGate(raw.Gate, settings)
		if err != nil {
			return nil, fmt.Errorf("%w: action %q enabledWhen: %v", ErrInvalidRequest, raw.ID, err)
		}

		entry := strings.ToLower(strings.TrimSpace(raw.Script.Entry))
		if entry == "native" {
			entry = ""
		}
		if entry != "" && entry != scriptEntryProxyCompat {
			return nil, fmt.Errorf("%w: action %q script entry must be native or %s", ErrInvalidRequest, raw.ID, scriptEntryProxyCompat)
		}

		jq := strings.TrimSpace(raw.Script.JQ)
		source := strings.TrimSpace(raw.Script.Source)
		inline := raw.Script.Inline

		// Exactly one action kind applies. Two would be ambiguous about which
		// runs, and the ambiguity would resolve differently depending on the
		// order this function happens to check them in.
		kinds := 0
		for _, present := range []bool{
			jq != "", raw.Script.Reject, raw.Script.Mock != nil,
			raw.Script.Headers != nil, raw.Script.Rewrite != nil, raw.Script.ReplaceBody != nil,
			source != "" || inline != "",
		} {
			if present {
				kinds++
			}
		}
		if kinds == 0 {
			return nil, fmt.Errorf("%w: action %q declares no action kind", ErrInvalidRequest, raw.ID)
		}
		if kinds > 1 {
			return nil, fmt.Errorf("%w: action %q declares more than one action kind", ErrInvalidRequest, raw.ID)
		}

		declarative := jq != "" || raw.Script.Reject || raw.Script.Mock != nil ||
			raw.Script.Headers != nil || raw.Script.Rewrite != nil || raw.Script.ReplaceBody != nil
		if entry != "" && declarative {
			return nil, fmt.Errorf("%w: action %q declares script.entry without a script", ErrInvalidRequest, raw.ID)
		}

		rule := ScriptRule{
			ID:    strings.TrimSpace(raw.ID),
			Phase: strings.ToLower(strings.TrimSpace(raw.Phase)),
			Match: ActionMatch{
				Hosts:       hosts,
				Schemes:     schemes,
				Methods:     normalizeUpper(raw.Match.Methods),
				PathRegex:   path,
				StatusCodes: uniqueSortedInts(raw.Match.StatusCodes),
			},
			BodyMode:     bodyMode,
			EnabledWhen:  gate,
			TimeoutMS:    orDefaultInt(raw.Script.TimeoutMS, 1000),
			MaxBodyBytes: orDefaultInt64(raw.Script.MaxBodyBytes, 8<<20),
		}

		switch {
		case declarative && jq == "":
			// reject, mock, headers, rewrite and replaceBody are what published
			// modules actually declare, and none of them runs any code.
			for _, validate := range []func() error{
				raw.Script.Mock.validate, raw.Script.Headers.validate,
				raw.Script.Rewrite.validate, raw.Script.ReplaceBody.validate,
			} {
				if err := validate(); err != nil {
					return nil, fmt.Errorf("%w: action %q %v", ErrInvalidRequest, raw.ID, err)
				}
			}
			rule.Reject = raw.Script.Reject
			rule.Mock = raw.Script.Mock
			rule.Headers = raw.Script.Headers
			rule.Rewrite = raw.Script.Rewrite
			rule.ReplaceBody = raw.Script.ReplaceBody

		case jq != "":
			if bodyMode != "text" {
				return nil, fmt.Errorf("%w: action %q script.jq requires bodyMode text", ErrInvalidRequest, raw.ID)
			}
			if len(jq) > maxJQProgramBytes {
				return nil, fmt.Errorf("%w: action %q script.jq exceeds %d bytes", ErrInvalidRequest, raw.ID, maxJQProgramBytes)
			}
			rule.JQProgram = jq

		default:
			if (source == "") == (inline == "") {
				return nil, fmt.Errorf("%w: action %q must declare exactly one of script.source or script.inline", ErrInvalidRequest, raw.ID)
			}
			scriptBody := []byte(inline)
			if source != "" {
				resolved, err := resolveResourceURL(sourceURL, source)
				if err != nil {
					return nil, fmt.Errorf("%w: action %q script source: %v", ErrInvalidRequest, raw.ID, err)
				}
				scriptBody, _, err = imp.fetch(ctx, resolved, maxScriptBytes)
				if err != nil {
					return nil, fmt.Errorf("fetch action %q script: %w", raw.ID, err)
				}
				rule.ScriptURL = resolved
			}
			if !utf8.Valid(scriptBody) {
				return nil, fmt.Errorf("%w: action %q script must be valid UTF-8", ErrInvalidRequest, raw.ID)
			}
			total += len(scriptBody)
			if total > maxScriptTotalBytes {
				return nil, fmt.Errorf("%w: the extension's scripts exceed %d bytes", ErrInvalidRequest, maxScriptTotalBytes)
			}
			rule.Entry = entry
			rule.ScriptDigest = digestText(string(scriptBody))
			rule.ScriptBody = string(scriptBody)
		}

		out = append(out, rule)
	}
	return out, nil
}

// parseGate checks an action's enabledWhen against the settings the same
// manifest declares.
//
// Only a required boolean or select may gate. Required is the load-bearing
// half: an enabled extension's required settings always carry a value, so a
// gate always has a decidable state. An optional setting adds a third case --
// declared, gating an action, unset -- whose only resolutions are running
// something the operator may have switched off, or dropping an action in
// silence.
//
// The type restriction is a whitelist rather than a fallthrough because the
// runtime compares the setting's rendered text. A gate on a number written
// `equals: "1.0"` never matches the value 1, whose canonical form is "1", and a
// location renders as a map nobody can write in advance because it depends on
// coordinates the operator picks. Both compile to an action that is silently
// skipped, with no error and no log line.
func parseGate(raw *manifestGate, settings []ModuleSetting) (*ActionGate, error) {
	if raw == nil {
		return nil, nil
	}
	key := strings.TrimSpace(raw.Key)
	equals := strings.TrimSpace(raw.Equals)
	if !validSettingKey(key) {
		return nil, fmt.Errorf("%q is not a valid setting key", key)
	}
	if equals == "" {
		return nil, fmt.Errorf("%q declares no value to compare against", key)
	}
	for _, setting := range settings {
		if setting.Key != key {
			continue
		}
		if !setting.Required {
			return nil, fmt.Errorf("%q is optional; a gate must name a required setting", key)
		}
		switch setting.Type {
		case "boolean":
			if equals != "true" && equals != "false" {
				return nil, fmt.Errorf("%q is a boolean setting and cannot equal %q", key, equals)
			}
		case "select":
			// Comparing against a value the operator can never choose compiles
			// to an action that never runs, which is the failure nobody sees.
			if !slices.Contains(setting.Options, equals) {
				return nil, fmt.Errorf("%q has no option %q", key, equals)
			}
		default:
			return nil, fmt.Errorf("%q is a %s setting; only boolean and select settings can gate an action", key, setting.Type)
		}
		return &ActionGate{Key: key, Equals: equals}, nil
	}
	return nil, fmt.Errorf("%q is not a setting this extension declares", key)
}

func normalizeRoute(raw manifestRoute) (RoutingRule, error) {
	rule := RoutingRule{Action: strings.ToLower(strings.TrimSpace(raw.Action))}

	if raw.Domain != nil {
		value, err := normalizeHostPattern(*raw.Domain)
		if err != nil || strings.HasPrefix(value, "*.") {
			return RoutingRule{}, errors.New("domain must be one canonical exact hostname")
		}
		rule.Domain = &value
	}
	if raw.DomainSuffix != nil {
		value, err := normalizeHostPattern(*raw.DomainSuffix)
		if err != nil || strings.HasPrefix(value, "*.") {
			return RoutingRule{}, errors.New("domainSuffix must be one canonical suffix without '*.'")
		}
		rule.DomainSuffix = &value
	}
	if raw.IPCIDR != nil {
		_, network, err := net.ParseCIDR(strings.TrimSpace(*raw.IPCIDR))
		if err != nil {
			return RoutingRule{}, errors.New("ipCIDR must be one IPv4 or IPv6 CIDR")
		}
		value := network.String()
		rule.IPCIDR = &value
	}
	if raw.Network != nil {
		value := strings.ToLower(strings.TrimSpace(*raw.Network))
		if value == "" {
			return RoutingRule{}, errors.New("network must not be empty when declared")
		}
		rule.Network = &value
	}
	if raw.DestinationPort != nil {
		if *raw.DestinationPort < 1 || *raw.DestinationPort > 65535 {
			return RoutingRule{}, errors.New("destinationPort must be between 1 and 65535 when declared")
		}
		port := *raw.DestinationPort
		rule.DestinationPort = &port
	}

	keywords, err := normalizeKeywords(raw.DomainKeywords, "domainKeywords")
	if err != nil {
		return RoutingRule{}, err
	}
	all, err := normalizeKeywords(raw.AllDomainKeywords, "allDomainKeywords")
	if err != nil {
		return RoutingRule{}, err
	}
	// A one-element "any of these" is an "all of these" with one element, and
	// keeping both spellings would make two rules that behave identically
	// compare unequal everywhere they are deduplicated.
	if keywords != nil && len(*keywords) == 1 {
		merged := append(append([]string(nil), derefOrNil(all)...), (*keywords)[0])
		sort.Strings(merged)
		all, keywords = &merged, nil
	}
	rule.DomainKeywords = keywords
	rule.AllDomainKeywords = all
	return rule, nil
}

func normalizeKeywords(raw *[]string, field string) (*[]string, error) {
	if raw == nil {
		return nil, nil
	}
	if len(*raw) == 0 {
		return nil, fmt.Errorf("%s must not be empty when declared", field)
	}
	seen := make(map[string]struct{}, len(*raw))
	out := make([]string, 0, len(*raw))
	for _, value := range *raw {
		keyword := strings.ToLower(strings.TrimSpace(value))
		if keyword == "" || len(keyword) > 64 || !nativeExtensionRouteKeywordPattern.MatchString(keyword) {
			return nil, fmt.Errorf("%s entries must contain 1 to 64 safe bytes", field)
		}
		if _, duplicate := seen[keyword]; duplicate {
			return nil, fmt.Errorf("duplicate keyword %q in %s", keyword, field)
		}
		seen[keyword] = struct{}{}
		out = append(out, keyword)
	}
	sort.Strings(out)
	return &out, nil
}

func derefOrNil(p *[]string) []string {
	if p == nil {
		return nil
	}
	return *p
}

// decodeManifest is strict on purpose: unknown fields, duplicate keys, multiple
// documents, aliases, anchors and merge keys are all refused.
//
// Each of those is a way for a manifest to mean something other than what it
// appears to say. An unknown field is a declaration this program will ignore --
// which, in a permission block, is the difference between what the author wrote
// and what the operator is agreeing to.
func decodeManifest(body []byte) (manifest, error) {
	body = bytes.TrimPrefix(body, []byte{0xef, 0xbb, 0xbf})

	var doc manifest
	decoder := yaml.NewDecoder(bytes.NewReader(body))
	decoder.KnownFields(true)
	if err := decoder.Decode(&doc); err != nil {
		return manifest{}, fmt.Errorf("%w: decode manifest: %v", ErrInvalidRequest, err)
	}
	var extra yaml.Node
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		if err == nil {
			return manifest{}, fmt.Errorf("%w: the manifest must contain exactly one YAML document", ErrInvalidRequest)
		}
		return manifest{}, fmt.Errorf("%w: decode trailing document: %v", ErrInvalidRequest, err)
	}

	var root yaml.Node
	if err := yaml.Unmarshal(body, &root); err != nil {
		return manifest{}, fmt.Errorf("%w: inspect manifest: %v", ErrInvalidRequest, err)
	}
	if err := rejectUnsafeYAML(&root); err != nil {
		return manifest{}, fmt.Errorf("%w: %v", ErrInvalidRequest, err)
	}
	return doc, nil
}

func rejectUnsafeYAML(node *yaml.Node) error {
	if node == nil {
		return nil
	}
	if node.Kind == yaml.AliasNode || node.Anchor != "" {
		return errors.New("the manifest cannot use YAML aliases or anchors")
	}
	if node.Kind == yaml.MappingNode {
		seen := make(map[string]struct{}, len(node.Content)/2)
		for i := 0; i+1 < len(node.Content); i += 2 {
			key := node.Content[i].Value
			if key == "<<" {
				return errors.New("the manifest cannot use YAML merge keys")
			}
			if _, duplicate := seen[key]; duplicate {
				return fmt.Errorf("duplicate key %q", key)
			}
			seen[key] = struct{}{}
		}
	}
	for _, child := range node.Content {
		if err := rejectUnsafeYAML(child); err != nil {
			return err
		}
	}
	return nil
}

func yamlToJSON(node yaml.Node) (json.RawMessage, error) {
	if node.Kind == 0 || (node.Kind == yaml.ScalarNode && node.Tag == "!!null") {
		return nil, nil
	}
	var value any
	if err := node.Decode(&value); err != nil {
		return nil, err
	}
	return json.Marshal(value)
}

// --- normalization -------------------------------------------------------

// normalizeHostPattern lowercases, trims, strips a trailing dot, and refuses
// anything the matcher cannot represent.
func normalizeHostPattern(raw string) (string, error) {
	host := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(raw)), ".")
	if host == "" {
		return "", errors.New("host must not be empty")
	}
	if !validHostPattern(host) {
		return "", fmt.Errorf("%q is not a canonical hostname or *.suffix wildcard", raw)
	}
	return host, nil
}

func normalizeHosts(raw []string) ([]string, error) {
	hosts := make([]string, 0, len(raw))
	for _, value := range raw {
		host, err := normalizeHostPattern(value)
		if err != nil {
			return nil, err
		}
		hosts = append(hosts, host)
	}
	hosts = uniqueSorted(hosts)
	if len(hosts) == 0 {
		return nil, errors.New("at least one host is required")
	}
	return hosts, nil
}

func normalizeLower(raw []string) []string {
	out := make([]string, 0, len(raw))
	for _, value := range raw {
		if value = strings.ToLower(strings.TrimSpace(value)); value != "" {
			out = append(out, value)
		}
	}
	return uniqueSorted(out)
}

func normalizeUpper(raw []string) []string {
	seen := make(map[string]struct{}, len(raw))
	out := make([]string, 0, len(raw))
	for _, value := range raw {
		if value = strings.ToUpper(strings.TrimSpace(value)); value != "" {
			if _, exists := seen[value]; !exists {
				seen[value] = struct{}{}
				out = append(out, value)
			}
		}
	}
	sort.Strings(out)
	return out
}

func uniqueSortedInts(raw []int) []int {
	seen := make(map[int]struct{}, len(raw))
	out := make([]int, 0, len(raw))
	for _, value := range raw {
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	sort.Ints(out)
	return out
}

func orDefaultInt(value, fallback int) int {
	if value == 0 {
		return fallback
	}
	return value
}

func orDefaultInt64(value, fallback int64) int64 {
	if value == 0 {
		return fallback
	}
	return value
}

// --- fetching ------------------------------------------------------------

func (imp *Importer) fetch(ctx context.Context, rawURL string, limit int64) ([]byte, string, error) {
	if err := checkResourceURL(rawURL); err != nil {
		return nil, "", err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, "", err
	}
	setFetchHeaders(req)

	resp, err := imp.client.Do(req)
	if err != nil {
		return nil, "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
		return nil, "", fmt.Errorf("HTTP %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return nil, "", err
	}
	if int64(len(body)) > limit {
		return nil, "", fmt.Errorf("response exceeds %d bytes", limit)
	}
	if len(body) == 0 {
		return nil, "", errors.New("empty response")
	}

	// An HTML body is a captive portal, a login page, or a repository's
	// rendered file view -- never an extension resource. Accepting it produces
	// a parse error pointing at YAML syntax, which sends the operator looking
	// for a mistake in a manifest they never actually fetched.
	prefix := strings.ToLower(strings.TrimSpace(string(body[:min(len(body), 512)])))
	if strings.Contains(strings.ToLower(resp.Header.Get("Content-Type")), "text/html") ||
		strings.HasPrefix(prefix, "<!doctype html") || strings.HasPrefix(prefix, "<html") {
		return nil, "", errors.New("refusing an HTML response instead of an extension resource")
	}
	return body, resp.Request.URL.String(), nil
}

func setFetchHeaders(req *http.Request) {
	// net/http synthesizes Referer while following a redirect. Extension URLs
	// can carry opaque query data, so the previous URL is never disclosed to
	// another origin.
	req.Header.Del("Referer")
	req.Header.Set("Accept", "application/json, application/yaml, text/yaml, application/javascript, text/plain, */*;q=0.1")
	req.Header.Set("User-Agent", manifestUserAgent)
}

func redirectPolicy(req *http.Request, via []*http.Request) error {
	if len(via) >= 5 {
		return errors.New("too many redirects")
	}
	if err := checkResourceURL(req.URL.String()); err != nil {
		return fmt.Errorf("unsafe redirect: %w", err)
	}
	setFetchHeaders(req)
	return nil
}

func checkResourceURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("%w: invalid URL: %v", ErrInvalidRequest, err)
	}
	if u.Scheme != "https" {
		return fmt.Errorf("%w: extension resources must use https", ErrInvalidRequest)
	}
	if u.Hostname() == "" || u.User != nil {
		return fmt.Errorf("%w: the URL must have a host and no userinfo", ErrInvalidRequest)
	}
	if u.Fragment != "" {
		return fmt.Errorf("%w: the URL must not contain a fragment", ErrInvalidRequest)
	}
	return nil
}

func resolveResourceURL(manifestURL, resource string) (string, error) {
	resource = strings.TrimSpace(resource)
	if resource == "" {
		return "", errors.New("script source is empty")
	}
	u, err := url.Parse(resource)
	if err != nil {
		return "", err
	}
	if !u.IsAbs() {
		// A pasted manifest has no base to resolve against, so it must use
		// absolute URLs or inline source. Guessing a base would let one
		// manifest's relative path mean something different depending on how it
		// reached the box.
		if manifestURL == "" {
			return "", errors.New("a relative script source requires a URL-based import")
		}
		base, err := url.Parse(manifestURL)
		if err != nil {
			return "", err
		}
		u = base.ResolveReference(u)
	}
	if err := checkResourceURL(u.String()); err != nil {
		return "", err
	}
	return u.String(), nil
}

// guardedDialer resolves through the injected resolver and refuses any address
// that is not public unicast.
//
// Resolving here rather than letting the transport do it is what makes the
// check mean anything: a guard applied to a name the dialer then resolves again
// checks one answer and dials another.
func guardedDialer(resolve Resolver) func(context.Context, string, string) (net.Conn, error) {
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(addr)
		if err != nil {
			return nil, err
		}
		candidates := []string{host}
		if net.ParseIP(host) == nil {
			if resolve == nil {
				return nil, errors.New("5gpn/engine: no resolver for extension fetches")
			}
			if candidates, err = resolve(ctx, host); err != nil {
				return nil, fmt.Errorf("resolve %s: %w", host, err)
			}
		}
		var lastErr error
		for _, candidate := range candidates {
			ip := net.ParseIP(candidate)
			if ip == nil {
				continue
			}
			if !publicUnicast(ip) {
				lastErr = fmt.Errorf("refusing to dial %s for %s", ip, host)
				continue
			}
			conn, err := (&net.Dialer{Timeout: 10 * time.Second}).DialContext(ctx, network, net.JoinHostPort(ip.String(), port))
			if err == nil {
				return conn, nil
			}
			lastErr = err
		}
		if lastErr == nil {
			lastErr = fmt.Errorf("no usable address for %s", host)
		}
		return nil, lastErr
	}
}

func publicUnicast(ip net.IP) bool {
	if ip == nil || ip.IsLoopback() || ip.IsUnspecified() || ip.IsMulticast() ||
		ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsInterfaceLocalMulticast() ||
		ip.IsPrivate() {
		return false
	}
	if v4 := ip.To4(); v4 != nil {
		// 100.64.0.0/10 behaves like private space on a hosted gateway, and the
		// reserved top of the range is not routable.
		if v4[0] == 100 && v4[1] >= 64 && v4[1] <= 127 {
			return false
		}
		if v4[0] == 0 || v4[0] == 127 || v4[0] >= 240 {
			return false
		}
	}
	return true
}
