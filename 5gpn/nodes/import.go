package nodes

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/metacubex/mihomo/adapter"
	"github.com/metacubex/mihomo/common/convert"

	"gopkg.in/yaml.v3"
)

var supportedURISchemes = map[string]struct{}{
	"anytls":          {},
	"http":            {},
	"https":           {},
	"hy2":             {},
	"hy2+realm":       {},
	"hysteria":        {},
	"hysteria2":       {},
	"hysteria2+realm": {},
	"mierus":          {},
	"socks":           {},
	"socks5":          {},
	"socks5h":         {},
	"ss":              {},
	"ssr":             {},
	"trojan":          {},
	"tuic":            {},
	"vless":           {},
	"vmess":           {},
}

var prohibitedProxyTypes = map[string]struct{}{
	"openvpn":   {},
	"tailscale": {},
	"wireguard": {},
}

func parseImportedProxies(content []byte) ([]*yaml.Node, error) {
	if len(content) > MaxImportBytes {
		return nil, fmt.Errorf("%w: imported content exceeds %d bytes", ErrInvalidInput, MaxImportBytes)
	}
	content = bytes.TrimPrefix(content, []byte{0xef, 0xbb, 0xbf})
	if len(bytes.TrimSpace(content)) == 0 {
		return nil, fmt.Errorf("%w: imported content is empty", ErrInvalidInput)
	}
	if !utf8.Valid(content) {
		return nil, fmt.Errorf("%w: imported content is not valid UTF-8", ErrInvalidInput)
	}

	items, structured, structuredErr := parseStructuredProxyYAML(content)
	if structured {
		if structuredErr != nil {
			return nil, fmt.Errorf("%w: %v", ErrInvalidInput, structuredErr)
		}
		return validateImportedNodes(items)
	}
	if structuredErr != nil && looksStructuredYAML(content) {
		return nil, fmt.Errorf("%w: invalid proxy YAML", ErrInvalidInput)
	}

	items, err := parseURIList(content)
	if err != nil {
		if structuredErr != nil {
			return nil, fmt.Errorf("%w: content is neither supported proxy YAML nor a valid URI list: %v", ErrInvalidInput, err)
		}
		return nil, fmt.Errorf("%w: %v", ErrInvalidInput, err)
	}
	return validateImportedNodes(items)
}

func parseStructuredProxyYAML(content []byte) ([]*yaml.Node, bool, error) {
	document, err := decodeSingleYAML(content)
	if err != nil {
		return nil, false, err
	}
	if len(document.Content) != 1 {
		return nil, false, fmt.Errorf("YAML document has no root value")
	}
	root := document.Content[0]
	if root.Kind == yaml.AliasNode {
		return nil, true, fmt.Errorf("top-level YAML aliases are not supported")
	}
	switch root.Kind {
	case yaml.MappingNode:
		nameNode, _, err := mappingValue(root, "name")
		if err != nil {
			return nil, true, err
		}
		typeNode, _, err := mappingValue(root, "type")
		if err != nil {
			return nil, true, err
		}
		if nameNode != nil || typeNode != nil {
			if nameNode == nil || typeNode == nil {
				return nil, true, fmt.Errorf("a single proxy mapping requires both name and type")
			}
			return []*yaml.Node{root}, true, nil
		}
		proxies, _, err := mappingValue(root, "proxies")
		if err != nil {
			return nil, true, err
		}
		if proxies == nil {
			return nil, true, fmt.Errorf("mapping must be a proxy or contain top-level proxies")
		}
		if proxies.Kind == yaml.AliasNode || proxies.Kind != yaml.SequenceNode {
			return nil, true, fmt.Errorf("top-level proxies must be a concrete sequence")
		}
		return append([]*yaml.Node(nil), proxies.Content...), true, nil
	case yaml.SequenceNode:
		return append([]*yaml.Node(nil), root.Content...), true, nil
	case yaml.ScalarNode:
		return nil, false, nil
	default:
		return nil, true, fmt.Errorf("unsupported YAML root kind")
	}
}

func looksStructuredYAML(content []byte) bool {
	trimmed := strings.TrimSpace(string(content))
	return strings.HasPrefix(trimmed, "{") ||
		strings.HasPrefix(trimmed, "[") ||
		strings.HasPrefix(trimmed, "-") ||
		strings.HasPrefix(trimmed, "name:") ||
		strings.HasPrefix(trimmed, "type:") ||
		strings.HasPrefix(trimmed, "proxies:")
}

func parseURIList(content []byte) ([]*yaml.Node, error) {
	text := strings.TrimSpace(string(content))
	if !strings.Contains(text, "://") {
		decoded, err := decodeSubscriptionBase64(text)
		if err != nil {
			return nil, fmt.Errorf("subscription is not valid Base64")
		}
		if len(decoded) > MaxImportBytes {
			return nil, fmt.Errorf("decoded subscription exceeds %d bytes", MaxImportBytes)
		}
		if !utf8.Valid(decoded) {
			return nil, fmt.Errorf("decoded subscription is not valid UTF-8")
		}
		text = strings.TrimSpace(string(decoded))
	}

	var items []*yaml.Node
	for index, rawLine := range strings.Split(text, "\n") {
		line := strings.TrimSpace(strings.TrimSuffix(rawLine, "\r"))
		if line == "" {
			continue
		}
		mappings, err := convertStrictLine(line)
		if err != nil {
			return nil, fmt.Errorf("URI line %d: %w", index+1, err)
		}
		for _, mapping := range mappings {
			var node yaml.Node
			if err := node.Encode(mapping); err != nil {
				return nil, fmt.Errorf("URI line %d: encode converted proxy: %w", index+1, err)
			}
			items = append(items, &node)
		}
	}
	if len(items) == 0 {
		return nil, fmt.Errorf("URI list contains no nodes")
	}
	return items, nil
}

func convertStrictLine(line string) ([]map[string]any, error) {
	scheme, _, found := strings.Cut(line, "://")
	if !found {
		return nil, fmt.Errorf("missing URI scheme")
	}
	scheme = strings.ToLower(strings.TrimSpace(scheme))
	if _, supported := supportedURISchemes[scheme]; !supported {
		return nil, fmt.Errorf("unsupported URI scheme")
	}
	if scheme == "mierus" {
		if err := validateMieruLine(line); err != nil {
			return nil, err
		}
	}
	if scheme == "vmess" {
		if err := validateLegacyVMessJSON(line); err != nil {
			return nil, err
		}
	}

	mappings, err := convert.ConvertsV2Ray([]byte(line))
	if err != nil || len(mappings) == 0 {
		return nil, fmt.Errorf("URI could not be converted")
	}
	if scheme == "mierus" {
		parsed, _ := url.Parse(line)
		if len(mappings) != len(parsed.Query()["port"]) {
			return nil, fmt.Errorf("mierus URI was only partially converted")
		}
	}
	for _, mapping := range mappings {
		stabilizeConvertedProxy(mapping)
		server, ok := mapping["server"].(string)
		if !ok || strings.TrimSpace(server) == "" {
			return nil, fmt.Errorf("converted proxy has no server")
		}
		if _, err := adapter.ParseProxy(mapping); err != nil {
			return nil, fmt.Errorf("converted proxy is invalid")
		}
	}
	return mappings, nil
}

func decodeSubscriptionBase64(text string) ([]byte, error) {
	text = strings.Map(func(r rune) rune {
		if unicode.IsSpace(r) {
			return -1
		}
		return r
	}, text)
	if text == "" {
		return nil, fmt.Errorf("empty Base64 subscription")
	}
	encodings := []*base64.Encoding{
		base64.StdEncoding,
		base64.RawStdEncoding,
	}
	for _, encoding := range encodings {
		decoded, err := encoding.DecodeString(text)
		if err == nil {
			return decoded, nil
		}
	}
	return nil, fmt.Errorf("invalid Base64 subscription")
}

func validateMieruLine(line string) error {
	parsed, err := url.Parse(line)
	if err != nil {
		return fmt.Errorf("invalid mierus URI")
	}
	ports := parsed.Query()["port"]
	protocols := parsed.Query()["protocol"]
	if len(ports) == 0 || len(ports) != len(protocols) {
		return fmt.Errorf("mierus URI requires matching port and protocol values")
	}
	baseName := parsed.Fragment
	if baseName == "" {
		baseName = parsed.Query().Get("profile")
	}
	if baseName == "" {
		baseName = parsed.Hostname()
	}
	names := make(map[string]struct{}, len(ports))
	for index, port := range ports {
		name := fmt.Sprintf("%s:%s/%s", baseName, port, protocols[index])
		if _, exists := names[name]; exists {
			return fmt.Errorf("mierus URI contains duplicate node names")
		}
		names[name] = struct{}{}
	}
	for _, port := range ports {
		if strings.Contains(port, "-") {
			parts := strings.Split(port, "-")
			if len(parts) != 2 {
				return fmt.Errorf("invalid mierus port range")
			}
			for _, part := range parts {
				value, err := strconv.Atoi(part)
				if err != nil || value < 1 || value > 65535 {
					return fmt.Errorf("invalid mierus port range")
				}
			}
			continue
		}
		value, err := strconv.Atoi(port)
		if err != nil || value < 1 || value > 65535 {
			return fmt.Errorf("invalid mierus port")
		}
	}
	return nil
}

func validateLegacyVMessJSON(line string) error {
	_, body, _ := strings.Cut(line, "://")
	decoded, err := convert.TryDecodeBase64(body)
	if err != nil || !bytes.HasPrefix(bytes.TrimSpace(decoded), []byte("{")) {
		return nil
	}
	decoder := json.NewDecoder(bytes.NewReader(decoded))
	var value map[string]any
	if err := decoder.Decode(&value); err != nil {
		return fmt.Errorf("invalid legacy vmess JSON")
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return fmt.Errorf("legacy vmess JSON has trailing content")
	}
	return nil
}

func stabilizeConvertedProxy(mapping map[string]any) {
	for _, optionKey := range []string{"ws-opts"} {
		options, ok := mapping[optionKey].(map[string]any)
		if !ok {
			continue
		}
		headers, ok := options["headers"].(map[string]any)
		if !ok {
			continue
		}
		if _, generated := headers["User-Agent"]; generated {
			headers["User-Agent"] = "Mozilla/5.0"
		}
	}
}

func validateImportedNodes(items []*yaml.Node) ([]*yaml.Node, error) {
	if len(items) == 0 {
		return nil, fmt.Errorf("%w: proxy list is empty", ErrInvalidInput)
	}
	if len(items) > MaxStaticNodes {
		return nil, fmt.Errorf("%w: proxy list exceeds %d nodes", ErrInvalidInput, MaxStaticNodes)
	}
	for index, item := range items {
		if item == nil || item.Kind == yaml.AliasNode || item.Kind != yaml.MappingNode {
			return nil, fmt.Errorf("%w: proxy %d must be a concrete mapping", ErrInvalidInput, index)
		}
		if containsYAMLReference(item) {
			return nil, fmt.Errorf("%w: proxy %d contains a YAML anchor or alias", ErrInvalidInput, index)
		}
		if _, err := proxyName(item, true); err != nil {
			return nil, fmt.Errorf("%w: proxy %d: %v", ErrInvalidInput, index, err)
		}
		typeNode, _, err := mappingValue(item, "type")
		if err != nil {
			return nil, fmt.Errorf("%w: proxy %d: %v", ErrInvalidInput, index, err)
		}
		proxyType, err := scalarString(typeNode, "proxy type")
		if err != nil {
			return nil, fmt.Errorf("%w: proxy %d: %v", ErrInvalidInput, index, err)
		}
		if _, prohibited := prohibitedProxyTypes[strings.ToLower(strings.TrimSpace(proxyType))]; prohibited {
			return nil, fmt.Errorf("%w: proxy %d uses prohibited type %q", ErrInvalidInput, index, proxyType)
		}
		var mapping map[string]any
		if err := item.Decode(&mapping); err != nil {
			return nil, fmt.Errorf("%w: proxy %d cannot be decoded", ErrInvalidInput, index)
		}
		if _, err := adapter.ParseProxy(mapping); err != nil {
			return nil, fmt.Errorf("%w: proxy %d is invalid", ErrInvalidInput, index)
		}
	}
	return items, nil
}

func containsYAMLReference(node *yaml.Node) bool {
	if node == nil {
		return false
	}
	if node.Kind == yaml.AliasNode || node.Anchor != "" {
		return true
	}
	for _, child := range node.Content {
		if containsYAMLReference(child) {
			return true
		}
	}
	return false
}
